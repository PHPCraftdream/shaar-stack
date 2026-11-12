"""Bounded, event-driven ownership of namespace product processes."""

from collections import deque
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time

MAX_CHILDREN = 16
MAX_LINE = 8192
MAX_LOG = 1024 * 1024
MAX_EVENTS = 32


def privilege_evidence(text, pid, uid, gid):
    fields = dict(line.split(":", 1) for line in text.splitlines() if ":" in line)
    if type(pid) is not int or pid <= 0 or uid <= 0 or gid <= 0:
        raise ValueError("invalid owned process identity")
    for name, expected in (("Pid", [pid]), ("Uid", [uid] * 4), ("Gid", [gid] * 4)):
        if [int(value) for value in fields.get(name, "").split()] != expected:
            raise ValueError("owned child identity does not match its unprivileged role")
    for name in ("CapInh", "CapPrm", "CapEff", "CapAmb", "CapBnd"):
        if name not in fields or int(fields[name].strip(), 16) != 0:
            raise ValueError("owned child retained a capability")
    if fields.get("NoNewPrivs", "").strip() != "1" or "Groups" not in fields or fields["Groups"].strip():
        raise ValueError("owned child retained privilege acquisition or supplementary groups")
    return {"pid": pid, "uid": uid, "gid": gid, "capabilities": 0, "no_new_privileges": True}


def namespace_command(config, namespace, executable, arguments, ip, setpriv):
    prefix = config.get("prefix", "")
    if re.fullmatch(r"sn[0-9a-f]{6}", prefix) is None:
        raise ValueError("invalid owned namespace prefix")
    suffixes = {"wan": "wan", "host_a": "host-a", "host_b": "host-b"}
    if namespace not in suffixes or config.get("ns", {}).get(namespace) != prefix + "-" + suffixes[namespace]:
        raise ValueError("ordinary child namespace is not an owned product role")
    uid, gid = config.get("helper_uid"), config.get("helper_gid")
    if type(uid) is not int or type(gid) is not int or uid <= 0 or gid <= 0:
        raise ValueError("ordinary children cannot use root identity")
    for path in (executable, ip, setpriv):
        if not isinstance(path, (str, Path)) or not Path(path).is_absolute():
            raise ValueError("child tools and products require absolute verified paths")
    if not all(type(arg) is str and "\0" not in arg for arg in arguments):
        raise ValueError("invalid child arguments")
    return [str(ip), "netns", "exec", config["ns"][namespace], str(setpriv),
            "--reuid", str(uid), "--regid", str(gid), "--clear-groups",
            "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all",
            "--no-new-privs", "--", str(executable), *arguments]


def child_environment(extra):
    allowed = {"SHAAR_NAT_ROLE", "SHAAR_NAT_NONCE", "SHAAR_NAT_DIRECTORY", "SHAAR_NAT_SERVICE_KEY"}
    if not isinstance(extra, dict) or not set(extra) <= allowed:
        raise ValueError("unreviewed child environment entry")
    if not all(type(value) is str and len(value) <= 4096 and "\0" not in value for value in extra.values()):
        raise ValueError("unbounded or malformed child environment value")
    return {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", **extra}


@dataclass
class Child:
    name: str
    process: object
    pidfd: int
    logs: dict
    pending: dict = field(default_factory=lambda: {"stdout": bytearray(), "stderr": bytearray()})
    sizes: dict = field(default_factory=lambda: {"stdout": 0, "stderr": 0})
    events: deque = field(default_factory=deque)
    open_streams: int = 2
    exited: bool = False
    returncode: object = None
    signals: list = field(default_factory=list)
    markers: dict = field(default_factory=dict)


class Supervisor:
    """One owner; pidfds and pipe readiness replace child/readiness polling."""

    def __init__(self, directory, deadline):
        if not hasattr(os, "pidfd_open"):
            raise RuntimeError("Linux pidfd support is required for bounded child supervision")
        self.root = Path(directory)
        if not self.root.is_dir() or self.root.is_symlink():
            raise ValueError("owned process log directory is missing or indirect")
        self.deadline = deadline
        self.selector = selectors.DefaultSelector()
        self.children = []
        self.closed = False

    def spawn(self, name, argv, environment, markers=()):
        if self.closed or time.monotonic() >= self.deadline:
            raise TimeoutError("child admission deadline")
        if len(self.children) >= MAX_CHILDREN:
            raise ValueError("owned child admission budget exhausted")
        if re.fullmatch(r"[a-z][a-z0-9-]{0,31}", name) is None or any(c.name == name for c in self.children):
            raise ValueError("child log identity must be unique and closed")
        environment = child_environment(environment)
        logs, process, pidfd = {}, None, None
        try:
            for channel in ("stdout", "stderr"):
                logs[channel] = (self.root / f"{name}.{channel}").open("xb")
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, env=environment, close_fds=True)
            pidfd = os.pidfd_open(process.pid)
            child = Child(name, process, pidfd, logs, markers={bytes(item): None for item in markers})
            self.selector.register(pidfd, selectors.EVENT_READ, (child, "exit"))
            for channel in ("stdout", "stderr"):
                stream = getattr(process, channel)
                os.set_blocking(stream.fileno(), False)
                self.selector.register(stream, selectors.EVENT_READ, (child, channel))
            self.children.append(child)
            return child
        except BaseException:
            for key in list(self.selector.get_map().values()):
                if key.data[0].process is process:
                    self.selector.unregister(key.fileobj)
            if process is not None:
                process.kill()
                process.wait(timeout=5)
                for stream in (process.stdin, process.stdout, process.stderr):
                    stream.close()
            if pidfd is not None:
                os.close(pidfd)
            for stream in logs.values():
                stream.close()
            raise

    def _line(self, child, channel, line):
        if len(line) > MAX_LINE:
            raise ValueError("owned child exceeded its line byte budget")
        for needle, seen in child.markers.items():
            if seen is None and needle in line:
                child.markers[needle] = line[:512].decode("utf-8", errors="replace")
        if channel == "stdout" and line.startswith(b"SHAAR_NAT_"):
            prefix, separator, payload = line.partition(b" ")
            if not separator or prefix not in (b"SHAAR_NAT_READY", b"SHAAR_NAT_PUBLICATION", b"SHAAR_NAT_RESULT"):
                raise ValueError("unexpected owned helper protocol line")
            event = json.loads(payload.decode("utf-8", errors="strict"))
            if type(event) is not dict or len(child.events) >= MAX_EVENTS:
                raise ValueError("owned helper event queue exhausted or malformed")
            child.events.append((prefix.decode("ascii"), event))

    def step(self, deadline):
        remaining = min(deadline, self.deadline) - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("owned child phase deadline")
        ready = self.selector.select(remaining)
        if not ready:
            raise TimeoutError("owned child phase deadline")
        for key, _mask in ready:
            child, channel = key.data
            if channel == "exit":
                child.returncode = child.process.wait(timeout=0)
                child.exited = True
                self.selector.unregister(child.pidfd)
                continue
            stream = key.fileobj
            data = os.read(stream.fileno(), MAX_LINE)
            if not data:
                self.selector.unregister(stream)
                stream.close()
                child.open_streams -= 1
                if child.pending[channel]:
                    self._line(child, channel, bytes(child.pending[channel]))
                    child.pending[channel].clear()
                continue
            if child.sizes[channel] + len(data) > MAX_LOG:
                raise ValueError("owned child exceeded its log byte budget")
            child.sizes[channel] += len(data)
            child.logs[channel].write(data)
            child.logs[channel].flush()
            child.pending[channel].extend(data)
            while b"\n" in child.pending[channel]:
                line, _, tail = child.pending[channel].partition(b"\n")
                child.pending[channel] = bytearray(tail)
                self._line(child, channel, line)
            if len(child.pending[channel]) > MAX_LINE:
                raise ValueError("owned child exceeded its unterminated line byte budget")

    def event(self, child, kind, deadline):
        while True:
            if child.events:
                label, value = child.events.popleft()
                if label != kind:
                    raise ValueError("owned helper emitted an out-of-order event")
                return value
            if child.exited and child.open_streams == 0:
                raise RuntimeError(f"owned helper ended before {kind}: {child.name} rc={child.returncode}")
            self.step(deadline)

    def mark(self, child, needle, deadline):
        """Wait for a pre-registered output marker; an earlier child exit is a failure."""
        while child.markers[needle] is None:
            if child.exited and child.open_streams == 0:
                raise RuntimeError(f"owned child ended before marker: {child.name} rc={child.returncode}")
            self.step(deadline)
        return child.markers[needle]

    def interrupt(self, child):
        """Console stop through the exact pidfd; never a PID-number signal."""
        if child not in self.children or child.exited:
            raise ValueError("cannot signal an unowned or exited child")
        signal.pidfd_send_signal(child.pidfd, signal.SIGINT)

    def send_stdin(self, child, data):
        """One bounded terminal control frame; stdin is closed afterwards."""
        if child not in self.children or len(data) > 128:
            raise ValueError("invalid control frame target or size")
        try:
            child.process.stdin.write(data)
            child.process.stdin.close()
        except BrokenPipeError as error:
            raise RuntimeError("owned child closed its control pipe early") from error

    def verify_identity(self, child, uid, gid):
        if child not in self.children or child.exited:
            raise ValueError("cannot verify an unowned or exited child")
        # Called after that exact child reports readiness, not during ip/setpriv exec.
        text = Path(f"/proc/{child.process.pid}/status").read_text(encoding="ascii")
        return privilege_evidence(text, child.process.pid, uid, gid)

    def wait(self, child, deadline):
        while not child.exited or child.open_streams:
            self.step(deadline)
        return child.returncode

    def close(self):
        """Reap each exact child PID even when pipe/protocol collection has failed."""
        if self.closed:
            return []
        self.closed = True
        errors = []
        end = time.monotonic() + 5
        for child in self.children:
            if not child.exited:
                try:
                    child.process.send_signal(signal.SIGTERM)
                    child.signals.append("TERM")
                except ProcessLookupError:
                    pass
        for child in self.children:
            try:
                child.returncode = child.process.wait(timeout=max(0, end - time.monotonic()))
            except subprocess.TimeoutExpired:
                child.process.kill()
                child.signals.append("KILL")
        kill_end = time.monotonic() + 5
        for child in self.children:
            try:
                child.returncode = child.process.wait(timeout=max(0, kill_end - time.monotonic()))
                child.exited = True
            except subprocess.TimeoutExpired:
                errors.append({"name": child.name, "pid": child.process.pid, "error": "owned child survived KILL deadline"})
            for stream in (child.process.stdin, child.process.stdout, child.process.stderr):
                stream.close()
            for stream in child.logs.values():
                stream.close()
            os.close(child.pidfd)
        self.selector.close()
        return errors
