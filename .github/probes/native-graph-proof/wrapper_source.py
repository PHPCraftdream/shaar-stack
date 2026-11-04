# SPDX-License-Identifier: MIT OR Apache-2.0

def native_wrapper_source():
    """Return the pinned, dependency-free Rust compiler capture wrapper."""
    return r'''// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

type BoxError = Box<dyn std::error::Error>;
fn q(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            c if c as u32 == 34 => {
                out.push(char::from(92));
                out.push(char::from(34));
            }
            c if c as u32 == 92 => {
                out.push(char::from(92));
                out.push(char::from(92));
            }
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push(char::from(34));
    out
}
fn text(v: &OsString, name: &str) -> Result<String, BoxError> {
    v.clone().into_string().map_err(|_| format!("{name} is not valid UTF-8").into())
}
fn output_paths(args: &[String], cwd: &Path) -> Result<Vec<PathBuf>, BoxError> {
    let mut crate_name = None;
    let mut out_dir = None;
    let mut extra = String::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--crate-name" {
            i += 1;
            crate_name = args.get(i).cloned();
        } else if let Some(v) = a.strip_prefix("--crate-name=") {
            crate_name = Some(v.to_owned());
        } else if a == "--out-dir" {
            i += 1;
            out_dir = args.get(i).cloned();
        } else if let Some(v) = a.strip_prefix("--out-dir=") {
            out_dir = Some(v.to_owned());
        } else if a == "-C" {
            i += 1;
            if let Some(v) = args.get(i).and_then(|s| s.strip_prefix("extra-filename=")) {
                extra = v.to_owned();
            }
        } else if let Some(v) = a.strip_prefix("-Cextra-filename=") {
            extra = v.to_owned();
        } else if let Some(v) = a.strip_prefix("-C").and_then(|s| s.strip_prefix("extra-filename=")) {
            extra = v.to_owned();
        }
        i += 1;
    }
    let Some(crate_name) = crate_name else {
        return Ok(Vec::new());
    };
    let out_dir = out_dir.ok_or("--out-dir required for crate compilation")?;
    let path = PathBuf::from(out_dir);
    let dir = if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    };
    let expected = [crate_name.clone(), format!("lib{crate_name}")];
    let mut result = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if !kind.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name_text = text(&name, "output filename")?;
        let stem = Path::new(&name_text).file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if expected.iter().any(|base| {
            let prefix = format!("{base}{extra}");
            stem == prefix || stem.strip_prefix(&prefix).is_some_and(|tail| tail.starts_with('.'))
        }) {
            result.push(entry.path());
        }
    }
    result.sort();
    Ok(result)
}
fn forward<F>(compiler: &OsString, args_os: &[OsString], launch: F) -> io::Result<std::process::ExitStatus>
where
    F: FnOnce(&mut Command) -> io::Result<std::process::ExitStatus>,
{
    let mut cmd = Command::new(compiler);
    cmd.args(args_os)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    launch(&mut cmd)
}

fn read_stdin<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(4097);
    reader.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stdin capture exceeds 4096 bytes",
        ));
    }
    Ok(bytes)
}

fn forward_input(compiler: &OsString, args: &[OsString], input: &[u8]) -> io::Result<std::process::ExitStatus> {
    forward_input_with(compiler, args, input, |stdin, bytes| stdin.write_all(bytes))
}

fn forward_input_with<W>(
    compiler: &OsString,
    args: &[OsString],
    input: &[u8],
    write: W,
) -> io::Result<std::process::ExitStatus>
where
    W: FnOnce(&mut std::process::ChildStdin, &[u8]) -> io::Result<()>,
{
    let mut child = Command::new(compiler)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    let result = match child.stdin.take() {
        Some(mut stdin) => write(&mut stdin, input),
        None => Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "child stdin missing",
        )),
    };
    if let Err(error) = result {
        let kill_error = child.kill().err();
        return match child.wait() {
            Ok(_) => Err(error),
            Err(wait_error) => Err(io::Error::other(format!(
                "failed to reap child after stdin write error ({error}); kill error: {}; wait error: {wait_error}",
                kill_error.map(|e| e.to_string()).unwrap_or_else(|| "none".to_owned()),
            ))),
        };
    }
    match child.wait() {
        Ok(status) => Ok(status),
        Err(wait_error) => {
            let kill_error = child.kill().err();
            match child.wait() {
                Ok(_) => Err(wait_error),
                Err(cleanup_error) => Err(io::Error::other(format!(
                    "failed to wait for child ({wait_error}); cleanup wait error: {cleanup_error}; kill error: {}",
                    kill_error.map(|e| e.to_string()).unwrap_or_else(|| "none".to_owned()),
                ))),
            }
        }
    }
}

fn captures_stdin(args: &[String]) -> bool {
    if args.len() != 9 {
        return false;
    }
    let Some(rest) = args[1].strip_prefix("autocfg_") else {
        return false;
    };
    let Some((nonce, counter)) = rest.rsplit_once('_') else {
        return false;
    };
    args[0] == "--crate-name"
        && nonce.len() == 16
        && nonce.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && matches!(counter, "0" | "1")
        && args[2] == "--crate-type=lib"
        && args[3] == "--out-dir"
        && !args[4].is_empty()
        && args[5] == "--emit=llvm-ir"
        && args[6] == "--target"
        && !args[7].is_empty()
        && args[8] == "-"
}

fn run() -> Result<i32, BoxError> {
    let mut iter = env::args_os();
    iter.next();
    let compiler = iter.next().ok_or("compiler argument required")?;
    let compiler_text = text(&compiler, "compiler")?;
    let args_os: Vec<OsString> = iter.collect();
    let args: Vec<String> = args_os.iter().map(|a| text(a, "compiler argument")).collect::<Result<_, _>>()?;
    let cwd = env::current_dir()?;
    let probe = args.iter().any(|a| a == "-vV" || a == "--print" || a.starts_with("--print=") || a == "--version" || a == "-V");
    let capture = Some(PathBuf::from(env::var_os("SHAAR_CAPTURE_DIR").ok_or("SHAAR_CAPTURE_DIR required")?));
    let config = [
        "SHAAR_CAPTURE_ROLE",
        "SHAAR_CAPTURE_REVISION",
        "SHAAR_CAPTURE_NONCE",
        "SHAAR_CAPTURE_RECIPE_SHA256",
    ];
    let mut metadata = Vec::new();
    if capture.is_some() {
        for key in config {
            metadata.push((key, env::var(key).map_err(|_| format!("{key} required"))?));
        }
        fs::create_dir_all(capture.as_ref().unwrap())?;
    }
    let should_capture = !probe && captures_stdin(&args)
        && env::var("CARGO_PKG_NAME").ok().as_deref() == Some("num-traits")
        && env::var("CARGO_PKG_VERSION").ok().as_deref() == Some("0.2.19");
    let mut stdin_record = String::from("null");
    let mut captured = None;
    let mut read_error = None;
    if should_capture {
        match read_stdin(&mut io::stdin().lock()) {
            Ok(bytes) => {
                let dir = capture.as_ref().unwrap();
                let snapshot_dir = dir.join(format!("inputs-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()));
                fs::create_dir(&snapshot_dir)?;
                let snapshot = snapshot_dir.join("0.bin");
                fs::write(&snapshot, &bytes)?;
                stdin_record = format!("{{\"snapshot\":{},\"size\":{}}}", q(&text(&snapshot.as_os_str().to_os_string(), "stdin snapshot")?), bytes.len());
                captured = Some(bytes);
            }
            Err(error) => read_error = Some(error),
        }
    }
    let (code, launch_error) = match if let Some(error) = read_error {
        Err(error)
    } else if let Some(bytes) = captured.as_ref() {
        forward_input(&compiler, &args_os, bytes)
    } else {
        forward(&compiler, &args_os, |cmd| cmd.current_dir(&cwd).status())
    } {
        Ok(status) => (status.code().unwrap_or(1), None),
        Err(error) => (1, Some(error.to_string())),
    };
    let outputs = if probe || code != 0 || launch_error.is_some() {
        Vec::new()
    } else {
        output_paths(&args, &cwd)?
    };
    if let Some(dir) = capture {
        let snapshot_dir = dir.join(format!(
            "outputs-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        if !outputs.is_empty() {
            fs::create_dir(&snapshot_dir)?;
        }
        let mut snapshots = Vec::new();
        for (i, path) in outputs.iter().enumerate() {
            let bytes = fs::read(path)?;
            let name = format!("snapshot-{}-{i}", SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos());
            let snapshot = snapshot_dir.join(&name);
            fs::write(&snapshot, bytes)?;
            let size = fs::metadata(&snapshot)?.len();
            snapshots.push((path, snapshot, size));
        }
        let get = |key: &str| env::var(key).unwrap_or_default();
        let kind = if probe { "probe" } else { "compile" };
        let mut row = format!("{{\"schema\":1,\"role\":{},\"revision\":{},\"nonce\":{},\"recipe_sha256\":{},\"compiler\":{},\"env\":{{\"RUSTC_WRAPPER\":{},\"RUSTC_WORKSPACE_WRAPPER\":{},\"CARGO_TARGET_DIR\":{}}},\"kind\":{},\"args\":[",
            q(&metadata[0].1), q(&metadata[1].1), q(&metadata[2].1), q(&metadata[3].1), q(&compiler_text), q(&get("RUSTC_WRAPPER")), q(&get("RUSTC_WORKSPACE_WRAPPER")), q(&get("CARGO_TARGET_DIR")), q(kind));
        for (i, a) in args.iter().enumerate() {
            if i > 0 {
                row.push(',');
            }
            row.push_str(&q(a));
        }
        row.push_str(&format!("],\"cwd\":{},\"stdin\":{},\"package_name\":{},\"package_version\":{},\"manifest_dir\":{},\"exit_code\":{},\"launch_error\":{},\"outputs\":[",
            q(&text(&cwd.as_os_str().to_os_string(), "cwd")?), stdin_record, q(&get("CARGO_PKG_NAME")), q(&get("CARGO_PKG_VERSION")), q(&get("CARGO_MANIFEST_DIR")), code,
            launch_error.as_deref().map(q).unwrap_or_else(|| "null".to_owned())));
        for (i, (path, _, _)) in snapshots.iter().enumerate() {
            if i > 0 {
                row.push(',');
            }
            row.push_str(&q(&text(
                &path.as_os_str().to_os_string(),
                "output",
            )?));
        }
        row.push_str("],\"snapshots\":[");
        for (i, (path, name, size)) in snapshots.iter().enumerate() {
            if i > 0 {
                row.push(',');
            }
            row.push_str(&format!(
                "{{\"output\":{},\"snapshot\":{},\"size\":{}}}",
                q(&text(&path.as_os_str().to_os_string(), "output")?),
                q(&text(&name.as_os_str().to_os_string(), "snapshot path")?),
                size
            ));
        }
        row.push_str("]}");
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let final_path = dir.join(format!("compile-{}-{nonce}.json", std::process::id()));
        let temp = dir.join(format!(".compile-{}-{nonce}.tmp", std::process::id()));
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&temp)?;
        file.write_all(row.as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, &final_path)?;
    }
    Ok(code)
}
fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("native wrapper: {e}");
            std::process::exit(2);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    struct ChunkReader {
        chunks: Vec<Vec<u8>>,
        interrupted: bool,
    }
    impl Read for ChunkReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            if self.chunks.is_empty() {
                return Ok(0);
            }
            let mut chunk = self.chunks.remove(0);
            let count = chunk.len().min(buf.len());
            buf[..count].copy_from_slice(&chunk[..count]);
            if count < chunk.len() {
                chunk.drain(..count);
                self.chunks.insert(0, chunk);
            }
            Ok(count)
        }
    }
    struct ErrorReader;
    impl Read for ErrorReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }
    }
    #[test]
    fn read_stdin_accepts_empty_and_exact_bound() {
        assert_eq!(read_stdin(&mut io::Cursor::new(Vec::<u8>::new())).unwrap(), b"");
        let bytes = vec![0xA5; 4096];
        assert_eq!(read_stdin(&mut io::Cursor::new(bytes.clone())).unwrap(), bytes);
    }
    #[test]
    fn read_stdin_rejects_over_bound() {
        assert!(read_stdin(&mut io::Cursor::new(vec![0x5A; 4097])).is_err());
    }
    #[test]
    fn read_stdin_preserves_short_chunks_and_retries_interrupted() {
        let reader = ChunkReader { chunks: vec![b"ab".to_vec(), vec![0, 255], b"xyz".to_vec()], interrupted: false };
        assert_eq!(read_stdin(&mut { reader }).unwrap(), b"ab\0\xffxyz");
    }
    #[test]
    fn read_stdin_propagates_reader_error() {
        assert_eq!(read_stdin(&mut ErrorReader).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }
    #[test]
    fn forward_input_sends_exact_binary_input_and_preserves_status() {
        let python = env::var_os("SHAAR_TRANSPORT_PYTHON").expect("SHAAR_TRANSPORT_PYTHON required");
        let input = [0, 255, 128, b'a', b'\n', 0xFE];
        let script = "import sys; data=sys.stdin.buffer.read(); assert data==bytes([0,255,128,97,10,254]); sys.stdout.write('transport stdout marker\\n'); sys.stderr.write('transport stderr marker\\n'); sys.exit(37)";
        let args = [OsString::from("-c"), OsString::from(script)];
        if env::var_os("SHAAR_STDIN_FORWARD_CHILD").is_some() {
            let status = forward_input(&python, &args, &input).unwrap();
            std::process::exit(status.code().unwrap_or(1));
        }
        let output = Command::new(env::current_exe().unwrap())
            .args(["--exact", "tests::forward_input_sends_exact_binary_input_and_preserves_status", "--nocapture"])
            .env("SHAAR_STDIN_FORWARD_CHILD", "1")
            .output().unwrap();
        assert_eq!(output.status.code(), Some(37));
        assert!(String::from_utf8_lossy(&output.stdout).contains("transport stdout marker"));
        assert!(String::from_utf8_lossy(&output.stderr).contains("transport stderr marker"));
    }
    #[test]
    fn forward_input_accepts_empty_and_exact_bound() {
        let python = env::var_os("SHAAR_TRANSPORT_PYTHON").expect("SHAAR_TRANSPORT_PYTHON required");
        for input in [Vec::new(), vec![0xA5; 4096]] {
            let script = "import sys; data=sys.stdin.buffer.read(); assert data==bytes([165])*int(sys.argv[1])";
            let args = [OsString::from("-c"), OsString::from(script), OsString::from(input.len().to_string())];
            let status = forward_input(&python, &args, &input).unwrap();
            assert_eq!(status.code(), Some(0));
        }
    }
    #[test]
    fn forward_input_write_failure_is_reported() {
        let python = env::var_os("SHAAR_TRANSPORT_PYTHON").expect("SHAAR_TRANSPORT_PYTHON required");
        let args = [OsString::from("-c"), OsString::from("import sys; sys.stdin.buffer.read()")];
        let result = forward_input_with(&python, &args, b"input", |_, _| {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "injected stdin write failure"))
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }
    #[test]
    fn forward_input_launch_failure_is_error() {
        let missing = OsString::from("/invalid/native-wrapper-probe");
        assert!(forward_input(&missing, &[], b"input").is_err());
    }
    #[test]
    fn captures_only_exact_stdin_compile() {
        let mut args = vec![
            "--crate-name".to_owned(),
            "autocfg_722b072ff7e63095_0".to_owned(),
            "--crate-type=lib".to_owned(),
            "--out-dir".to_owned(),
            "/tmp/out".to_owned(),
            "--emit=llvm-ir".to_owned(),
            "--target".to_owned(),
            "fixture-host".to_owned(),
            "-".to_owned(),
        ];
        assert!(captures_stdin(&args));
        args.push("--cfg=feature=\"forged\"".to_owned());
        assert!(!captures_stdin(&args));
        assert!(!captures_stdin(&vec!["-vV".to_owned()]));
    }

    #[test]
    fn quote_is_valid_json_string() {
        assert_eq!(q("a\"b\\c\n"), "\"a\\\"b\\\\c\\n\"");
    }
    #[test]
    fn parses_all_outputs_absolute() {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = env::temp_dir().join(format!("shaar-output-paths-{}-{nonce}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        for name in [
            "libdemo-unit.rlib",
            "libdemo-unit.rmeta",
            "demo-unit.d",
            "unrelated.rlib",
        ] {
            File::create(dir.join(name)).unwrap();
        }
        let args = vec![
            "--out-dir".into(),
            dir.to_string_lossy().into_owned(),
            "--crate-name".into(),
            "demo".into(),
            "-C".into(),
            "extra-filename=-unit".into(),
        ];
        let paths = output_paths(&args, Path::new("/work")).unwrap();
        let mut expected = vec![
            dir.join("demo-unit.d"),
            dir.join("libdemo-unit.rlib"),
            dir.join("libdemo-unit.rmeta"),
        ];
        expected.sort();
        assert_eq!(paths, expected);
        assert!(paths.iter().all(|path| path.is_absolute()));
        fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    fn missing_out_dir_is_error() {
        let args = vec!["--crate-name".into(), "demo".into()];
        assert!(output_paths(&args, Path::new("/work")).is_err());
    }
    #[test]
    fn forwards_stdio_and_preserves_status() {
        use std::io::Write;
        let python = env::var_os("SHAAR_TRANSPORT_PYTHON").expect("SHAAR_TRANSPORT_PYTHON required");
        let script = concat!(
            "import sys\n",
            "data = sys.stdin.buffer.read()\n",
            "sys.stdout.buffer.write(data + \"|\".join(sys.argv[1:]).encode(\"utf-8\"))\n",
            "sys.stderr.buffer.write(b\"stderr marker\")\n",
            "sys.exit(37)\n",
        );
        let args = vec![OsString::from("-c"), OsString::from(script), OsString::from("space arg"), OsString::from("雪☃"), OsString::from("quote'\"arg")];
        let status = forward(&python, &args, |cmd| {
            let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
            child.stdin.take().unwrap().write_all(b"input marker")?;
            let out = child.wait_with_output()?;
            assert_eq!(out.stdout, "input markerspace arg|雪☃|quote'\"arg".as_bytes());
            assert_eq!(out.stderr, b"stderr marker");
            Ok(out.status)
        }).unwrap();
        assert_eq!(status.code(), Some(37));
    }
    #[test]
    fn actual_wrapper_stdin_capture() {
        let python = env::var_os("SHAAR_TRANSPORT_PYTHON").expect("SHAAR_TRANSPORT_PYTHON required");
        let compiler = env::var_os("SHAAR_TRANSPORT_RUSTC").expect("SHAAR_TRANSPORT_RUSTC required");
        let host = env::var_os("SHAAR_TRANSPORT_HOST").expect("SHAAR_TRANSPORT_HOST required");
        let wrapper = env::current_exe().unwrap().parent().unwrap().join(if cfg!(windows) { "capture-wrapper.exe" } else { "capture-wrapper" });
        let script = r#"import json, os, pathlib, subprocess, sys, tempfile
wrapper, compiler, host = sys.argv[1:]
with tempfile.TemporaryDirectory() as temporary:
    root = pathlib.Path(temporary).resolve()
    cap = root / 'capture'
    out = root / 'target' / host / 'debug/build/num-traits-abcd/out'
    out.mkdir(parents=True)
    environment = os.environ.copy()
    environment.update(SHAAR_CAPTURE_DIR=str(cap), SHAAR_CAPTURE_ROLE='candidate', SHAAR_CAPTURE_REVISION='fixture', SHAAR_CAPTURE_NONCE='fixture', SHAAR_CAPTURE_RECIPE_SHA256='a'*64, CARGO_PKG_NAME='num-traits', CARGO_PKG_VERSION='0.2.19', CARGO_MANIFEST_DIR=str(root), RUSTC_WRAPPER=str(wrapper), RUSTC_WORKSPACE_WRAPPER='', CARGO_TARGET_DIR=str(root/'target'))
    for index, data in enumerate((b'', b'pub fn probe() { let _ = 1f64.total_cmp(&2f64); }')):
        crate = 'autocfg_0123456789abcdef_' + str(index)
        args = ['--crate-name', crate, '--crate-type=lib', '--out-dir', str(out), '--emit=llvm-ir', '--target', host, '-']
        result = subprocess.run([wrapper, compiler, *args], input=data, capture_output=True, env=environment)
        assert result.returncode == 0, result.stderr
        rows = [json.loads(p.read_text()) for p in cap.glob('compile-*.json')]
        row = next(r for r in rows if r['args'][1] == crate)
        assert row['stdin']['size'] == len(data)
        assert pathlib.Path(row['stdin']['snapshot']).read_bytes() == data
        output = pathlib.Path(row['outputs'][0])
        snapshot = pathlib.Path(row['snapshots'][0]['snapshot'])
        saved = snapshot.read_bytes()
        assert output.read_bytes() == saved
        output.unlink()
        assert snapshot.read_bytes() == saved
    version = subprocess.run([wrapper, compiler, '-vV'], input=b'do not capture', capture_output=True, env=environment)
    assert version.returncode == 0, version.stderr
    rows = [json.loads(p.read_text()) for p in cap.glob('compile-*.json')]
    probe = next(r for r in rows if r['args'] == ['-vV'])
    assert probe['stdin'] is None and probe['outputs'] == []
    overflow_args = args.copy()
    overflow_args[1] = 'autocfg_fedcba9876543210_0'
    overflow = subprocess.run([wrapper, compiler, *overflow_args], input=b'x' * 4097, capture_output=True, env=environment)
    assert overflow.returncode != 0
    rows = [json.loads(p.read_text()) for p in cap.glob('compile-*.json')]
    failure = next(r for r in rows if r.get('launch_error') is not None and '4096' in r['launch_error'])
    assert failure['outputs'] == [] and failure['stdin'] is None
"#;
        let output = Command::new(python).arg("-c").arg(script).arg(wrapper).arg(compiler).arg(host).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    }
    #[test]
    fn launch_failure_is_error() {
        let missing = OsString::from("/invalid/native-wrapper-probe");
        assert!(forward(&missing, &[], |cmd| cmd.status()).is_err());
    }
}
'''
