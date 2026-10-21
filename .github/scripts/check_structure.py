"""Проверка структурных ограничений проекта Sha'ar Stack.

Правила (CLAUDE.md):
1. Не более 700 строк в каждом файле кода.
2. Не более 7 непосредственно вложенных элементов (файлы + подкаталоги)
   в каждом каталоге, по tracked-путям git.
3. Политика unsafe: у каждого target'а workspace-пакетов (все kinds: lib,
   bin, test, example, bench, custom-build, proc-macro) ПЕРВАЯ физическая
   строка -- ровно #![forbid(unsafe_code)]; у пакетов crates/shaar-ygg --
   ровно #![deny(unsafe_code)].

Кодовые расширения (подпадают под лимит строк):
    .rs, .go, .py, .sh, .bash, .ps1, .toml, .yml, .yaml
Решения по границам:
    - Cargo.toml считается кодом (конфигурация сборки).
    - Cargo.lock не код (генерируемый файл), лимит строк не применяется.
    - .yml/.yaml (в т.ч. .github/workflows) считаются кодом.
    - Из лимита строк исключены ТОЛЬКО Markdown-файлы (.md): документации
      со встроенными примерами лимит не положен. Самостоятельный код
      (например docs/tool.py) проверяется на общих основаниях.
    - Исключений для fixtures guard'а нет: tracked-фикстуры -- часть
      проекта и подчиняются тем же лимитам (oversized-фикстур в
      репозитории нет, границы генерируются тестами во временных
      каталогах).

Корневые target'ы: источник истины -- `cargo +stable metadata --no-deps
--format-version 1 --locked --offline`. Проверяются только пакеты из
workspace_members (сторонние игнорируются). src_path нормализуется через
Path.resolve + relative_to(root): ./, .., symlink-родители и диск
учитываются; target вне корня или не в tracked-наборе -- явная ошибка.
Файл, который Cargo не считает target'ом (например build.rs без
объявления), корнем не является и не требует атрибута.

Каноническое размещение unsafe-атрибута (сознательно простой проектный
контракт, НЕ полный разбор Rust): нужный точный атрибут обязан стоять
на ПЕРВОЙ физической строке файла (допустим UTF-8 BOM перед ним, без
пробелов); строка после снятия BOM и окончания строки должна быть ровно
байтами атрибута. Основной enforcement остаётся за rustc (forbid/deny);
скрипт -- структурный guard для раннего падения в CI.

Читаемость (preflight): каждый неслужебный tracked файл обязан читаться
(поток, кусками 64KB, без сохранения). Порядок в main: readable ->
line/item limits -> metadata -> unsafe: при нарушениях чтения metadata
не вызывается. Containment: путь открывается только если его resolve
лежит внутри realpath(root); это защищает от статических symlink в
checkout, но против враждебно изменяемого конкурентно filesystem
realpath+open не race-free -- полной защиты не заявляется.

Источник путей: `git ls-files -z` (bytes, разбор по \\0 -- безопасно для
пробелов, Unicode и переносов строк в именах). Служебные префиксы
(.git/, .claude/, .rush/, worktrees/, target/) игнорируются.

Git- и cargo-раннеры инъектируются параметрами main -- тесты подменяют
их данными, локально cargo и git guard'ом не запускаются. Возвращает
nonzero при любом нарушении; fail-closed: nonzero exit cargo, невалидный
JSON, неожиданная schema или пустой workspace -- нарушения.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

MAX_LINES = 700
MAX_ITEMS = 7
CHUNK = 65536
BOM = b"\xef\xbb\xbf"
FORBID = b"#![forbid(unsafe_code)]"
DENY = b"#![deny(unsafe_code)]"
DENY_PACKAGE = "shaar-ygg"
IGNORED_PREFIXES = (b".git/", b".claude/", b".rush/", b"worktrees/", b"target/")
CODE_EXTS = frozenset(
    (b".rs", b".go", b".py", b".sh", b".bash", b".ps1", b".toml", b".yml", b".yaml")
)
DOC_EXTS = frozenset((b".md",))


def parse_ls_files(raw: bytes) -> list[bytes]:
    """Разобрать вывод `git ls-files -z`: NUL-разделённые пути."""
    return [p for p in raw.split(b"\0") if p]


def run_git_ls_files() -> subprocess.CompletedProcess:
    """Получить список tracked-путей репозитория."""
    return subprocess.run(
        ["git", "ls-files", "-z"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def run_cargo_metadata(root: Path) -> subprocess.CompletedProcess:
    """Данные о target'ах workspace; cargo вызывается только в CI."""
    return subprocess.run(
        ["cargo", "+stable", "metadata", "--no-deps", "--format-version", "1",
         "--locked", "--offline"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def is_ignored(path: bytes) -> bool:
    """Служебные префиксы инструментов и артефактов не считаются проектом."""
    return path.startswith(IGNORED_PREFIXES)


def ext(path: bytes) -> bytes:
    """Расширение пути в нижнем регистре (bytes)."""
    slash = path.rfind(b"/")
    dot = path.rfind(b".")
    if dot <= slash:
        return b""
    return path[dot:].lower()


def is_code(path: bytes) -> bool:
    """Файл кода по расширению; исключены только Markdown-файлы."""
    if ext(path) in DOC_EXTS:
        return False
    return ext(path) in CODE_EXTS


def count_lines(data: bytes) -> int:
    """Число строк; непустой файл без завершающего перевода -- одна строка."""
    n = data.count(b"\n")
    if data and not data.endswith(b"\n"):
        n += 1
    return n


def _open_checked(root: Path, full: Path):
    """Проверить весь разрешённый путь, затем открыть файл."""
    try:
        full.resolve().relative_to(root.resolve())
    except (ValueError, RuntimeError) as exc:
        raise OSError(f"путь вне дерева проекта или цикл symlink: {full}") from exc
    return open(full, "rb")


def check_readable(root: Path, paths: list[bytes]) -> list[str]:
    """Preflight: каждый неслужебный tracked файл обязан читаться."""
    errors: list[str] = []
    for path in paths:
        if is_ignored(path):
            continue
        full = root / path.decode("utf-8", "surrogateescape")
        try:
            with _open_checked(root, full) as fh:
                while fh.read(CHUNK):
                    pass
        except OSError as exc:
            errors.append(f"не удалось прочитать {path.decode('utf-8', 'replace')}: {exc}")
    return errors


def check_line_limits(root: Path, paths: list[bytes]) -> list[str]:
    """Лимит 700 строк для каждого кодового файла. Ошибка чтения -- нарушение."""
    errors: list[str] = []
    for path in paths:
        if is_ignored(path) or not is_code(path):
            continue
        full = root / path.decode("utf-8", "surrogateescape")
        try:
            with _open_checked(root, full) as fh:
                lines = count_lines(fh.read())
        except OSError as exc:
            errors.append(f"не удалось прочитать {path.decode('utf-8', 'replace')}: {exc}")
            continue
        if lines > MAX_LINES:
            errors.append(
                f"{path.decode('utf-8', 'replace')}: {lines} строк (лимит {MAX_LINES})"
            )
    return errors


def check_item_limits(paths: list[bytes]) -> list[str]:
    """Лимит 7 элементов (файлы + подкаталоги) в каталоге по tracked-путям."""
    children: dict[bytes, set[bytes]] = defaultdict(set)
    for path in paths:
        if is_ignored(path):
            continue
        parts = path.split(b"/")
        # Каждый элемент, включая файл, считается элементом своего каталога.
        for i in range(len(parts)):
            parent = b"/".join(parts[:i])
            children[parent].add(parts[i])
    errors: list[str] = []
    for parent in sorted(children):
        n = len(children[parent])
        if n > MAX_ITEMS:
            name = parent.decode("utf-8", "replace") or "<корень репозитория>"
            errors.append(f"{name}: {n} элементов (лимит {MAX_ITEMS})")
    return errors


def parse_metadata(raw: bytes, root: Path, tracked: set[bytes]) -> tuple[list[tuple[bytes, str]], list[str]]:
    """Извлечь корневые target'ы workspace-пакетов: [(путь, имя пакета)].

    Fail-closed: невалидный JSON, неожиданная schema, target вне корня
    или вне tracked-набора -- ошибки, а не пропуск.
    """
    errors: list[str] = []
    try:
        cfg = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [], [f"cargo metadata: невалидный JSON: {exc}"]
    if not isinstance(cfg, dict):
        return [], ["cargo metadata: неожиданная schema (корень не объект)"]
    members = cfg.get("workspace_members")
    packages = cfg.get("packages")
    if not isinstance(members, list) or not isinstance(packages, list):
        return [], ["cargo metadata: неожиданная schema (нет workspace_members/packages)"]
    if not members:
        return [], ["cargo metadata: пустой workspace"]
    if any(not isinstance(member, str) or not member for member in members):
        return [], ["cargo metadata: некорректные workspace member ID"]
    member_ids = set(members)
    if len(member_ids) != len(members):
        return [], ["cargo metadata: повторяющиеся workspace member ID"]
    root_real = root.resolve()
    found_members: set[str] = set()
    targets: list[tuple[bytes, str]] = []

    def relative_path(value: str) -> Path:
        path = Path(value)
        if not path.is_absolute():
            path = root_real / path
        return path.resolve().relative_to(root_real)

    for package in packages:
        if (not isinstance(package, dict)
                or not isinstance(package.get("id"), str) or not package["id"]):
            errors.append("cargo metadata: некорректный пакет или package ID")
            continue
        package_id = package["id"]
        if package_id not in member_ids:
            continue
        if package_id in found_members:
            errors.append(f"cargo metadata: повтор пакета {package_id}")
            continue
        found_members.add(package_id)
        name = package.get("name")
        manifest = package.get("manifest_path")
        package_targets = package.get("targets")
        if (not isinstance(name, str) or not name
                or not isinstance(manifest, str) or not manifest
                or not isinstance(package_targets, list)):
            errors.append(f"cargo metadata: неожиданная schema пакета {package_id}")
            continue
        try:
            relative_path(manifest)
        except (OSError, ValueError, RuntimeError):
            errors.append(f"cargo metadata: manifest пакета {name} вне корня проекта")
            continue
        if not package_targets:
            errors.append(f"cargo metadata: пакет {name} не содержит targets")
            continue
        for target in package_targets:
            if not isinstance(target, dict):
                errors.append(f"cargo metadata: target пакета {name} не объект")
                continue
            source = target.get("src_path")
            kinds = target.get("kind")
            if (not isinstance(source, str) or not source
                    or not isinstance(kinds, list) or not kinds
                    or any(not isinstance(kind, str) or not kind for kind in kinds)):
                errors.append(f"cargo metadata: неожиданная schema target пакета {name}")
                continue
            try:
                relative = relative_path(source)
            except (OSError, ValueError, RuntimeError):
                errors.append(f"cargo metadata: target пакета {name} вне корня проекта")
                continue
            relative_bytes = relative.as_posix().encode("utf-8", "surrogateescape")
            if relative_bytes not in tracked or is_ignored(relative_bytes):
                errors.append(
                    f"cargo metadata: target пакета {name} не является tracked-файлом "
                    f"проекта: {relative.as_posix()}"
                )
                continue
            targets.append((relative_bytes, name))
    missing = member_ids - found_members
    if missing:
        errors.append(f"cargo metadata: workspace members без пакетов: {sorted(missing)}")
    if not targets and not errors:
        errors.append("cargo metadata: нет workspace targets")
    return targets, errors


def check_unsafe_policy(root: Path, targets: list[tuple[bytes, str]]) -> list[str]:
    """Первая строка каждого target -- ровно нужный unsafe-атрибут."""
    errors: list[str] = []
    for path, package in targets:
        expected = DENY if package == DENY_PACKAGE else FORBID
        full = root / path.decode("utf-8", "surrogateescape")
        try:
            with _open_checked(root, full) as fh:
                first = fh.readline()
        except OSError as exc:
            errors.append(f"не удалось прочитать {path.decode('utf-8', 'replace')}: {exc}")
            continue
        if first.startswith(BOM):
            first = first[len(BOM):]
        if first.rstrip(b"\r\n") != expected:
            found = first.rstrip(b"\r\n").decode("utf-8", "replace")
            errors.append(
                f"{path.decode('utf-8', 'replace')}: первая строка {found!r}, "
                f"ожидается ровно {expected.decode()}"
            )
    return errors


def main(runner=run_git_ls_files, metadata=run_cargo_metadata, root: Path | None = None) -> int:
    """Точка входа: tracked-пути git, затем проверки; metadata -- после preflight."""
    root = Path.cwd() if root is None else root
    try:
        proc = runner()
    except OSError as exc:
        print(f"ошибка запуска git: {exc}", file=sys.stderr)
        return 1
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", "replace").strip()
        print(f"git ls-files завершился с ошибкой: {stderr}", file=sys.stderr)
        return 1
    paths = parse_ls_files(proc.stdout)
    errors = check_readable(root, paths)
    if errors:
        # Preflight: не читать ничего дальше, если дерево читается не полностью.
        for err in errors:
            print(f"НАРУШЕНИЕ: {err}", file=sys.stderr)
        print(f"Итого нарушений: {len(errors)}", file=sys.stderr)
        return 1
    errors += check_line_limits(root, paths)
    errors += check_item_limits(paths)
    try:
        meta = metadata(root)
    except OSError as exc:
        print(f"ошибка запуска cargo metadata: {exc}", file=sys.stderr)
        return 1
    if meta.returncode != 0:
        stderr = meta.stderr.decode("utf-8", "replace").strip()
        print(f"cargo metadata завершился с ошибкой: {stderr}", file=sys.stderr)
        return 1
    targets, meta_errors = parse_metadata(meta.stdout, root, set(paths))
    errors += meta_errors
    errors += check_unsafe_policy(root, targets)
    if errors:
        for err in errors:
            print(f"НАРУШЕНИЕ: {err}", file=sys.stderr)
        print(f"Итого нарушений: {len(errors)}", file=sys.stderr)
        return 1
    print(f"OK: {len(paths)} tracked-путей, структурные ограничения соблюдены.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
