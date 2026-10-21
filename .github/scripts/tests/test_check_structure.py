"""Unit-тесты структурного guard'а check_structure.py.

Запуск -- только в CI: python -I -m unittest discover -s .github/scripts/tests
Git- и cargo-раннеры внедряются подменами; границы 700/701 строк, юникод
и структуры каталогов генерируются тестами во временных каталогах.
Тестовые данные создаются отдельно от скриптов во временных каталогах.
"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import check_structure as cs  # noqa: E402

class FakeProc:
    """Подмена результата subprocess с управляемым кодом возврата."""

    def __init__(self, returncode: int, stdout: bytes = b"", stderr: bytes = b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def lines(n: int) -> bytes:
    """n строк по одному символу."""
    return b"x\n" * n


def meta_json(packages: list[dict], members: list[str] | None = None) -> bytes:
    """Минимальный ответ cargo metadata для подмены."""
    if members is None:
        members = [p["id"] for p in packages]
    cfg = {"workspace_members": members, "packages": packages}
    return json.dumps(cfg).encode("utf-8")


def pkg(pkg_id: str, name: str, targets: list[dict]) -> dict:
    return {
        "id": pkg_id,
        "name": name,
        "manifest_path": "Cargo.toml",
        "targets": targets,
    }


def tgt(src_path: str, kind: list[str]) -> dict:
    return {"src_path": src_path, "kind": kind}


class TempCase(unittest.TestCase):
    def tmp(self) -> tempfile.TemporaryDirectory:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return tmp

    def write(self, tmp: str, rel: str, data: bytes) -> None:
        target = Path(tmp, rel)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


class LineLimitTests(TempCase):
    def test_700_lines_ok(self):
        with self.tmp() as tmp:
            self.write(tmp, "a.rs", lines(700))
            self.assertEqual(cs.check_line_limits(Path(tmp), [b"a.rs"]), [])

    def test_701_lines_error(self):
        with self.tmp() as tmp:
            self.write(tmp, "a.rs", lines(701))
            errors = cs.check_line_limits(Path(tmp), [b"a.rs"])
            self.assertEqual(len(errors), 1)
            self.assertIn("701", errors[0])

    def test_markdown_excluded_from_line_limit(self):
        # 701 строка в Markdown не нарушение: исключены только .md.
        with self.tmp() as tmp:
            self.write(tmp, "a.md", lines(701))
            self.assertEqual(cs.check_line_limits(Path(tmp), [b"a.md"]), [])
        self.assertFalse(cs.is_code(b"README.md"))
        self.assertTrue(cs.is_code(b"docs/tool.py"))
        self.assertFalse(cs.is_code(b"Cargo.lock"))
        self.assertTrue(cs.is_code(b"crates/shaar/Cargo.toml"))

    def test_unicode_name(self):
        with self.tmp() as tmp:
            self.write(tmp, "файл юникод.rs", lines(700))
            self.assertEqual(cs.check_line_limits(Path(tmp), ["файл юникод.rs".encode()]), [])


class ItemLimitTests(unittest.TestCase):
    def test_seven_items_ok(self):
        # dir_with_7: 7 файлов = 7 элементов, на границе.
        paths = [f"dir_with_7/{n}.rs".encode() for n in "abcdefg"]
        self.assertEqual(cs.check_item_limits(paths), [])

    def test_eight_items_error(self):
        # dir_with_8: 6 файлов + 2 подкаталога = 8 -> нарушение.
        paths = [f"dir_with_8/{n}.rs".encode() for n in "abcdef"]
        paths += [b"dir_with_8/sub1/x.rs", b"dir_with_8/sub2/x.rs"]
        errors = cs.check_item_limits(paths)
        self.assertEqual(len(errors), 1)
        self.assertIn("dir_with_8", errors[0])
        self.assertIn("8", errors[0])

    def test_files_counted_without_subdirs(self):
        # 8 файлов без подкаталогов тоже нарушают лимит.
        paths = [f"flat/{n}.rs".encode() for n in "abcdefgh"]
        errors = cs.check_item_limits(paths)
        self.assertEqual(len(errors), 1)
        self.assertIn("flat", errors[0])

    def test_subdirectories_counted(self):
        # 7 подкаталогов в p -- на границе, 8 -- нарушение.
        paths = [f"p/sub{i}/f.rs".encode() for i in range(1, 8)]
        self.assertEqual(cs.check_item_limits(paths), [])
        counted = cs.check_item_limits(paths + [b"p/sub8/f.rs"])
        self.assertEqual(len(counted), 1)

    def test_hidden_project_items_counted(self):
        # Корень: .gitignore + 7 скрытых файлов = 8 элементов.
        paths = [b".gitignore"] + [f".hidden{i}.rs".encode() for i in range(7)]
        self.assertEqual(len(cs.check_item_limits(paths)), 1)

    def test_service_prefixes_ignored(self):
        for p in (
            b".git/x.rs",
            b".claude/x.py",
            b".rush/x.sh",
            b"worktrees/w/x.rs",
            b"target/x.rs",
        ):
            self.assertTrue(cs.is_ignored(p), p)
        for p in (b".github/workflows/ci.yml", b".gitignore", b"crates/x.rs"):
            self.assertFalse(cs.is_ignored(p), p)
        paths = [f".git/{n}".encode() for n in "abcdefgh"]
        self.assertEqual(cs.check_item_limits(paths), [])


class PathParsingTests(unittest.TestCase):
    def test_ls_files_parsing(self):
        raw = b"a.rs\0b\nname.rs\0"
        self.assertEqual(cs.parse_ls_files(raw), [b"a.rs", b"b\nname.rs"])

    def test_unicode_and_spaces(self):
        # Пробелы и Unicode в путях не ломают подсчёт элементов.
        paths = ["каталог с пробелом/файл юникод.rs".encode(), "обычный.rs".encode()]
        self.assertEqual(cs.check_item_limits(paths), [])

    def test_newline_in_name(self):
        # Перенос строки в имени не разбивается NUL-парсером.
        paths = [b"d/name\nwith\nnewline.rs", b"d/other.rs"]
        self.assertEqual(cs.check_item_limits(paths), [])


class ReadableTests(TempCase):
    def test_all_read(self):
        with self.tmp() as tmp:
            self.write(tmp, "a.rs", b"fn main() {}\n")
            self.write(tmp, "b.md", lines(5))
            self.assertEqual(cs.check_readable(Path(tmp), [b"a.rs", b"b.md"]), [])

    def test_missing_files_are_errors(self):
        with self.tmp() as tmp:
            errors = cs.check_readable(Path(tmp), [b"missing.rs", b"missing.md"])
            self.assertEqual(len(errors), 2)
            for err in errors:
                self.assertIn("не удалось прочитать", err)

    def test_directory_path_is_error(self):
        with self.tmp() as tmp:
            Path(tmp, "sub").mkdir()
            errors = cs.check_readable(Path(tmp), [b"sub"])
            self.assertEqual(len(errors), 1)

    def test_permission_error_is_reported(self):
        # Подмена builtins.open: Path.resolve и is_symlink файлы не открывают,
        # поэтому сработает именно обработчик ошибки открытия.
        with self.tmp() as tmp:
            self.write(tmp, "a.rs", b"x\n")
            with mock.patch("builtins.open", side_effect=PermissionError("denied")):
                errors = cs.check_readable(Path(tmp), [b"a.rs"])
            self.assertEqual(len(errors), 1)
            self.assertIn("denied", errors[0])

    def test_direct_symlink_outside_tree_is_error(self):
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside, "secret.rs")
            target.write_bytes(b"x\n")
            with self.tmp() as tmp:
                link = Path(tmp, "link.rs")
                try:
                    os.symlink(target, link)
                except OSError:
                    self.skipTest("создание symlink недоступно на этой системе")
                errors = cs.check_readable(Path(tmp), [b"link.rs"])
                self.assertEqual(len(errors), 1)
                self.assertIn("вне дерева", errors[0])

    def test_parent_symlink_outside_tree_is_error(self):
        with tempfile.TemporaryDirectory() as outside:
            outside_dir = Path(outside, "real")
            outside_dir.mkdir()
            (outside_dir / "f.rs").write_bytes(b"x\n")
            with self.tmp() as tmp:
                link = Path(tmp, "link_dir")
                try:
                    os.symlink(outside_dir, link, target_is_directory=True)
                except OSError:
                    self.skipTest("создание symlink недоступно на этой системе")
                errors = cs.check_readable(Path(tmp), [b"link_dir/f.rs"])
                self.assertEqual(len(errors), 1)
                self.assertIn("вне дерева", errors[0])


class MetadataTests(TempCase):
    def targets(self, tmp: str, raw: bytes, tracked: list[bytes]):
        return cs.parse_metadata(raw, Path(tmp), set(tracked))

    def test_default_and_explicit_targets_together(self):
        with self.tmp() as tmp:
            # Оба target'а -- данные Cargo; guard проверяет оба.
            raw = meta_json([pkg("p1", "c1", [
                tgt(f"{tmp}/crates/c1/src/lib.rs", ["lib"]),
                tgt(f"{tmp}/crates/c1/tests/auto.rs", ["test"]),
            ])])
            tracked = [b"crates/c1/src/lib.rs", b"crates/c1/tests/auto.rs"]
            targets, errors = self.targets(tmp, raw, tracked)
            self.assertEqual(errors, [])
            self.assertEqual(sorted(targets), sorted([
                (b"crates/c1/src/lib.rs", "c1"),
                (b"crates/c1/tests/auto.rs", "c1"),
            ]))

    def test_all_kinds_checked(self):
        with self.tmp() as tmp:
            kinds = {
                b"src/lib.rs": ["lib"],
                b"src/main.rs": ["bin"],
                b"tests/t.rs": ["test"],
                b"examples/e.rs": ["example"],
                b"benches/b.rs": ["bench"],
                b"build.rs": ["custom-build"],
                b"proc/lib.rs": ["proc-macro"],
            }
            targets_json = [
                tgt(f"{tmp}/crates/c1/{rel.decode()}", kind) for rel, kind in kinds.items()
            ]
            raw = meta_json([pkg("p1", "c1", targets_json)])
            tracked = [b"crates/c1/" + rel for rel in kinds]
            targets, errors = self.targets(tmp, raw, tracked)
            self.assertEqual(errors, [])
            self.assertEqual(len(targets), len(kinds))
            # Каждый kind попал в lint-проверку.
            for rel in kinds:
                self.write(tmp, f"crates/c1/{rel.decode()}", cs.FORBID + b"\n")
            self.assertEqual(cs.check_unsafe_policy(Path(tmp), targets), [])
            for relative in kinds:
                with self.subTest(kind=kinds[relative]):
                    path = f"crates/c1/{relative.decode()}"
                    self.write(tmp, path, "//! атрибут отсутствует\n".encode())
                    errors = cs.check_unsafe_policy(Path(tmp), targets)
                    self.assertEqual(len(errors), 1)
                    self.assertIn(path, errors[0])
                    self.write(tmp, path, cs.FORBID + b"\n")

    def test_package_outside_crates_checked(self):
        with self.tmp() as tmp:
            raw = meta_json([pkg("p1", "myroot", [tgt(f"{tmp}/src/lib.rs", ["lib"])])])
            targets, errors = self.targets(tmp, raw, [b"src/lib.rs"])
            self.assertEqual(errors, [])
            self.assertEqual(targets, [(b"src/lib.rs", "myroot")])

    def test_custom_path_normalized(self):
        with self.tmp() as tmp:
            raw = meta_json([pkg("p1", "c1", [tgt(f"{tmp}/crates/c1/./x.rs", ["lib"])])])
            targets, errors = self.targets(tmp, raw, [b"crates/c1/x.rs"])
            self.assertEqual(errors, [])
            self.assertEqual(targets, [(b"crates/c1/x.rs", "c1")])

    def test_target_outside_root_is_error(self):
        with tempfile.TemporaryDirectory() as outside:
            with self.tmp() as tmp:
                raw = meta_json([pkg("p1", "c1", [tgt(f"{outside}/x.rs", ["lib"])])])
                targets, errors = self.targets(tmp, raw, [])
                self.assertEqual(targets, [])
                self.assertEqual(len(errors), 1)
                self.assertIn("вне корня", errors[0])

    def test_untracked_target_is_error(self):
        with self.tmp() as tmp:
            raw = meta_json([pkg("p1", "c1", [tgt(f"{tmp}/crates/c1/src/lib.rs", ["lib"])])])
            targets, errors = self.targets(tmp, raw, [b"crates/c1/Cargo.toml"])
            self.assertEqual(targets, [])
            self.assertEqual(len(errors), 1)
            self.assertIn("не является tracked", errors[0])

    def test_third_party_package_ignored(self):
        with self.tmp() as tmp:
            ours = pkg("p1", "c1", [tgt(f"{tmp}/crates/c1/src/lib.rs", ["lib"])])
            foreign = pkg("dep-999", "serde", [tgt("/opt/serde/src/lib.rs", ["lib"])])
            raw = meta_json([ours, foreign], members=["p1"])
            targets, errors = self.targets(tmp, raw, [b"crates/c1/src/lib.rs"])
            self.assertEqual(errors, [])
            self.assertEqual(targets, [(b"crates/c1/src/lib.rs", "c1")])

    def test_missing_workspace_package_rejected(self):
        with self.tmp() as tmp:
            targets, errors = self.targets(tmp, meta_json([], ["missing"]), [])
            self.assertEqual(targets, [])
            self.assertTrue(errors)
            self.assertIn("без пакетов", errors[0])

    def test_every_member_requires_package_and_targets(self):
        with self.tmp() as tmp:
            valid = pkg("p1", "c1", [tgt(f"{tmp}/lib.rs", ["lib"])])
            for extra in ([], [pkg("p2", "empty", [])]):
                with self.subTest(extra=extra):
                    raw = meta_json([valid] + extra, ["p1", "p2"])
                    targets, errors = self.targets(tmp, raw, [b"lib.rs"])
                    self.assertEqual(targets, [(b"lib.rs", "c1")])
                    self.assertTrue(errors)

    def test_empty_workspace_package_rejected(self):
        with self.tmp() as tmp:
            raw = meta_json([pkg("p1", "empty", [])])
            targets, errors = self.targets(tmp, raw, [])
            self.assertEqual(targets, [])
            self.assertIn("не содержит targets", errors[0])

    def test_invalid_member_ids_rejected(self):
        with self.tmp() as tmp:
            for members in ([], [None], [{}], [""], ["p1", "p1"]):
                with self.subTest(members=members):
                    targets, errors = self.targets(tmp, meta_json([], members), [])
                    self.assertEqual(targets, [])
                    self.assertTrue(errors)

    def test_invalid_package_schema_rejected(self):
        with self.tmp() as tmp:
            good = pkg("p1", "c1", [tgt(f"{tmp}/lib.rs", ["lib"])])
            invalid = [None, {}, {**good, "name": None},
                       {**good, "manifest_path": None}, {**good, "targets": None}]
            for package in invalid:
                with self.subTest(package=package):
                    raw = meta_json([package], ["p1"])
                    targets, errors = self.targets(tmp, raw, [b"lib.rs"])
                    self.assertEqual(targets, [])
                    self.assertTrue(errors)

    def test_invalid_target_schema_rejected(self):
        with self.tmp() as tmp:
            for kind in ("lib", [], [None], [""]):
                with self.subTest(kind=kind):
                    raw = meta_json([pkg("p1", "c1", [tgt(f"{tmp}/lib.rs", kind)])])
                    targets, errors = self.targets(tmp, raw, [b"lib.rs"])
                    self.assertEqual(targets, [])
                    self.assertTrue(errors)

    def test_duplicate_member_package_rejected(self):
        with self.tmp() as tmp:
            package = pkg("p1", "c1", [tgt(f"{tmp}/lib.rs", ["lib"])])
            raw = meta_json([package, package], ["p1"])
            _, errors = self.targets(tmp, raw, [b"lib.rs"])
            self.assertTrue(errors)
            self.assertIn("повтор пакета", errors[0])

    def test_manifest_outside_workspace_rejected(self):
        with tempfile.TemporaryDirectory() as outside, self.tmp() as tmp:
            package = pkg("p1", "c1", [tgt(f"{tmp}/lib.rs", ["lib"])])
            package["manifest_path"] = str(Path(outside, "Cargo.toml"))
            targets, errors = self.targets(tmp, meta_json([package]), [b"lib.rs"])
            self.assertEqual(targets, [])
            self.assertIn("manifest", errors[0])


class UnsafePolicyTests(TempCase):
    def root_errors(self, first_line: bytes, package: str = "fake") -> list[str]:
        with self.tmp() as tmp:
            self.write(tmp, "crates/fake/src/lib.rs", first_line + b"\n//! docs\n")
            targets = [(b"crates/fake/src/lib.rs", package)]
            return cs.check_unsafe_policy(Path(tmp), targets)

    def test_real_crate_roots_ok(self):
        with self.tmp() as tmp:
            targets = [
                (b"crates/shaar/src/lib.rs", "shaar"),
                (b"crates/shaar-p2p/src/lib.rs", "shaar-p2p"),
                (b"crates/shaar-server/src/main.rs", "shaar-server"),
                (b"crates/shaar-client/src/main.rs", "shaar-client"),
                (b"crates/shaar-ygg/src/lib.rs", "shaar-ygg"),
            ]
            self.assertEqual(cs.check_unsafe_policy(Path.cwd(), targets), [])

    def test_exact_attr_first_line_ok(self):
        self.assertEqual(self.root_errors(cs.FORBID), [])

    def test_other_attribute_after_policy_ok(self):
        self.assertEqual(self.root_errors(cs.FORBID + b"\n#![deny(warnings)]"), [])

    def test_bom_before_attr_ok(self):
        self.assertEqual(self.root_errors(cs.BOM + cs.FORBID), [])

    def test_bin_target_block_comment_rejected(self):
        # Негатив на bin-target: /*#!...]*/ первой строкой не атрибут.
        with self.tmp() as tmp:
            self.write(tmp, "src/main.rs", b"/*" + cs.FORBID + b"*/\nfn main() {}\n")
            targets = [(b"src/main.rs", "fake-bin")]
            errors = cs.check_unsafe_policy(Path(tmp), targets)
            self.assertEqual(len(errors), 1)

    def test_doc_comment_first_line_rejected(self):
        errors = self.root_errors(b"//! docs")
        self.assertEqual(len(errors), 1)

    def test_raw_string_first_line_rejected(self):
        errors = self.root_errors(b'r#"' + cs.FORBID + b'"#')
        self.assertEqual(len(errors), 1)

    def test_other_attr_rejected(self):
        errors = self.root_errors(b"#![no_std]")
        self.assertEqual(len(errors), 1)

    def test_deny_where_forbid_needed_rejected(self):
        errors = self.root_errors(cs.DENY)
        self.assertEqual(len(errors), 1)
        self.assertIn("forbid", errors[0])

    def test_ygg_requires_deny(self):
        with self.tmp() as tmp:
            self.write(tmp, "crates/shaar-ygg/src/lib.rs", cs.DENY + b"\n//! docs\n")
            targets = [(b"crates/shaar-ygg/src/lib.rs", "shaar-ygg")]
            self.assertEqual(cs.check_unsafe_policy(Path(tmp), targets), [])
            self.write(tmp, "crates/shaar-ygg/src/lib.rs", cs.FORBID + b"\n")
            errors = cs.check_unsafe_policy(Path(tmp), targets)
            self.assertEqual(len(errors), 1)
            self.assertIn("deny", errors[0])


class MainTests(TempCase):
    def valid_tree(self, tmp: str, count: int = 1):
        self.write(tmp, "f.rs", cs.FORBID + b"\n" + lines(count - 1))
        runner = mock.Mock(return_value=FakeProc(0, b"f.rs\0"))
        raw = meta_json([pkg("m1", "local", [tgt(str(Path(tmp, "f.rs")), ["lib"])])])
        metadata = mock.Mock(return_value=FakeProc(0, raw))
        return runner, metadata

    def test_git_failure_is_error(self):
        runner = lambda: FakeProc(returncode=1, stderr=b"boom")  # noqa: E731
        meta = lambda root: FakeProc(returncode=0)  # noqa: E731
        self.assertEqual(cs.main(runner=runner, metadata=meta), 1)

    def test_metadata_nonzero_is_error(self):
        runner = lambda: FakeProc(returncode=0, stdout=b"")  # noqa: E731
        meta = lambda root: FakeProc(returncode=1, stderr=b"lock error")  # noqa: E731
        self.assertEqual(cs.main(runner=runner, metadata=meta), 1)

    def test_metadata_malformed_json_is_error(self):
        with self.tmp() as tmp:
            runner, metadata = self.valid_tree(tmp)
            metadata.return_value = FakeProc(0, b"{not json")
            with mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
                self.assertEqual(cs.main(runner, metadata, Path(tmp)), 1)
            metadata.assert_called_once_with(Path(tmp))
            self.assertIn("невалидный JSON", stderr.getvalue())

    def test_metadata_missing_schema_is_error(self):
        invalid = (b"{}", json.dumps({"packages": []}).encode(),
                   meta_json([], ["m1"]))
        with self.tmp() as tmp:
            for raw in invalid:
                with self.subTest(schema=raw):
                    runner, metadata = self.valid_tree(tmp)
                    metadata.return_value = FakeProc(0, raw)
                    self.assertEqual(cs.main(runner, metadata, Path(tmp)), 1)
                    metadata.assert_called_once_with(Path(tmp))

    def test_main_detects_real_violation(self):
        with self.tmp() as tmp:
            runner, metadata = self.valid_tree(tmp, 701)
            with mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
                self.assertEqual(cs.main(runner, metadata, Path(tmp)), 1)
            self.assertIn("701 строк", stderr.getvalue())
            self.assertNotIn("cargo metadata:", stderr.getvalue())

    def test_main_ok_on_clean_tree(self):
        with self.tmp() as tmp:
            runner, metadata = self.valid_tree(tmp, 100)
            self.assertEqual(cs.main(runner, metadata, Path(tmp)), 0)
            metadata.assert_called_once_with(Path(tmp))

    def test_readable_failure_blocks_metadata(self):
        with self.tmp() as tmp:
            # Tracked symlink наружу: preflight должен отсечь до cargo metadata.
            with tempfile.TemporaryDirectory() as outside:
                target = Path(outside, "secret.rs")
                target.write_bytes(b"x\n")
                link = Path(tmp, "link.rs")
                try:
                    os.symlink(target, link)
                except OSError:
                    self.skipTest("создание symlink недоступно на этой системе")
                calls = []
                runner = lambda: FakeProc(returncode=0, stdout=b"link.rs\0")  # noqa: E731

                def meta(root):
                    calls.append(root)
                    return FakeProc(
                        returncode=0, stdout=meta_json([], members=["m1"])
                    )

                self.assertEqual(cs.main(runner=runner, metadata=meta, root=Path(tmp)), 1)
                self.assertEqual(calls, [])  # metadata не вызван


if __name__ == "__main__":
    unittest.main()
