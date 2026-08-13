#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)

die() {
  printf 'ENDPOINT_MODULE_BOUNDARY_FAILURE: %s\n' "$*" >&2
  exit 1
}

command -v python3 >/dev/null 2>&1 || die 'python3 is required'

python3 - "$ROOT" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1])
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
USE_START = re.compile(r"\b(?:pub(?:\s*\([^)]*\))?\s+)?use\s+")
RUSQLITE = re.compile(r"\b(?:extern\s+crate\s+rusqlite|use\s+rusqlite\b|rusqlite\s*::)")


class Tok:
    def __init__(self, text: str) -> None:
        self.text = text
        self.i = 0

    def skip(self) -> None:
        while self.i < len(self.text) and self.text[self.i].isspace():
            self.i += 1

    def peek(self) -> str | None:
        self.skip()
        if self.i >= len(self.text):
            return None
        if self.text.startswith("::", self.i):
            return "::"
        char = self.text[self.i]
        if char in "{}.,;*":
            return char
        match = IDENT.match(self.text, self.i)
        return match.group(0) if match else char

    def take(self, expected: str | None = None) -> str | None:
        token = self.peek()
        if token is None or (expected is not None and token != expected):
            return None
        self.i += 2 if token == "::" else len(token)
        return token


def rust_files(relative_dir: str) -> list[Path]:
    directory = ROOT / relative_dir
    if not directory.is_dir():
        return []
    return sorted(path for path in directory.rglob("*.rs") if path.is_file())


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def strip_comments(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", " ", source, flags=re.S)
    return re.sub(r"//[^\n]*", " ", source)


def module_path_for_file(path: Path) -> tuple[str, ...]:
    parts = list(path.relative_to(ROOT / "src").parts)
    if parts[-1] == "mod.rs":
        parts = parts[:-1]
    elif parts[-1].endswith(".rs"):
        parts[-1] = parts[-1][:-3]
    return ("crate", *parts)


def resolve_super(
    file_mod: tuple[str, ...], supers: int, rest: tuple[str, ...]
) -> tuple[str, ...]:
    base = list(file_mod[:-1] or ("crate",))
    for _ in range(max(supers - 1, 0)):
        if len(base) > 1:
            base.pop()
    if not base:
        base = ["crate"]
    return tuple(base + list(rest))


def normalize_path(
    file_mod: tuple[str, ...], path: tuple[str, ...]
) -> tuple[str, ...] | None:
    if not path:
        return None
    if path[0] == "crate":
        return path
    if path[0] == "super":
        supers = 0
        index = 0
        while index < len(path) and path[index] == "super":
            supers += 1
            index += 1
        return resolve_super(file_mod, supers, path[index:])
    return None


def parse_use_tree(tok: Tok, prefix: list[str]) -> list[tuple[str, ...]]:
    paths: list[tuple[str, ...]] = []
    tok.skip()
    if tok.peek() == "{":
        tok.take("{")
        while True:
            tok.skip()
            if tok.peek() in (None, "}"):
                tok.take("}")
                break
            paths.extend(parse_use_tree(tok, prefix[:]))
            tok.skip()
            if tok.peek() == ",":
                tok.take(",")
                continue
            if tok.peek() == "}":
                tok.take("}")
                break
            break
        return paths

    while True:
        token = tok.peek()
        if token is None or token in "{}.,;":
            break
        if token == "::":
            tok.take("::")
            if tok.peek() == "{":
                return parse_use_tree(tok, prefix)
            if tok.peek() == "*":
                prefix.append("*")
                tok.take("*")
                break
            continue
        if token == "as":
            tok.take("as")
            tok.take()
            break
        if token == "*":
            prefix.append("*")
            tok.take("*")
            break
        if IDENT.match(token):
            prefix.append(token)
            tok.take()
            continue
        break
    if prefix:
        paths.append(tuple(prefix))
    return paths


def slice_use_stmt(text: str, start: int) -> str | None:
    depth = 0
    index = start
    while index < len(text):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        elif char == ";" and depth == 0:
            return text[start:index]
        index += 1
    return None


def extract_use_paths(text: str, file_mod: tuple[str, ...]) -> list[tuple[str, ...]]:
    paths: list[tuple[str, ...]] = []
    for match in USE_START.finditer(text):
        stmt = slice_use_stmt(text, match.end())
        if stmt is None:
            continue
        stripped = stmt.lstrip()
        if not re.match(r"(?:crate|super)\b", stripped):
            continue
        for raw in parse_use_tree(Tok(stmt), []):
            normalized = normalize_path(file_mod, raw)
            if normalized:
                paths.append(normalized)
    return paths


PATH_EXPR = re.compile(
    r"\b((?:crate|super)(?:\s*::\s*super)*)(?:\s*::\s*([A-Za-z_][A-Za-z0-9_]*))+"
)


def extract_path_exprs(text: str, file_mod: tuple[str, ...]) -> list[tuple[str, ...]]:
    paths: list[tuple[str, ...]] = []
    for match in PATH_EXPR.finditer(text):
        parts = [part for part in re.sub(r"\s+", "", match.group(0)).split("::") if part]
        normalized = normalize_path(file_mod, tuple(parts))
        if normalized:
            paths.append(normalized)
    return paths


def crate_head(path: tuple[str, ...]) -> str | None:
    if len(path) >= 2 and path[0] == "crate":
        return path[1]
    return None


def refs_in(path: Path) -> tuple[str, list[tuple[str, ...]], str]:
    source = strip_comments(path.read_text(encoding="utf-8"))
    file_mod = module_path_for_file(path)
    refs = extract_use_paths(source, file_mod) + extract_path_exprs(source, file_mod)
    return rel(path), refs, source


failures: list[str] = []


def fail(location: str, rule: str, detail: str) -> None:
    failures.append(f"{location}: {rule}: {detail}")


for path in rust_files("src/timer"):
    location, refs, _source = refs_in(path)
    for ref in refs:
        head = crate_head(ref)
        rendered = "::".join(ref)
        if head in {"storage", "api", "http", "provider", "tools"}:
            fail(
                location,
                "timer must not import storage, api/http, provider, or tools",
                rendered,
            )
        if head == "runtime" and (len(ref) < 3 or ref[2] != "ports"):
            fail(location, "timer may import crate::runtime::ports only", rendered)

for directory in ("src/http", "src/api"):
    for path in rust_files(directory):
        location, refs, _source = refs_in(path)
        for ref in refs:
            head = crate_head(ref)
            if head in {"storage", "replicas", "provider"}:
                fail(
                    location,
                    "http/api must not import storage, replicas, or provider",
                    "::".join(ref),
                )

for path in rust_files("src/provider"):
    location, refs, _source = refs_in(path)
    for ref in refs:
        head = crate_head(ref)
        if head in {"replicas", "storage"}:
            fail(
                location,
                "provider must not import replicas or storage",
                "::".join(ref),
            )

for path in rust_files("src/runtime"):
    relative = path.relative_to(ROOT / "src" / "runtime")
    if relative.parts and relative.parts[0] == "ports":
        continue
    location, refs, source = refs_in(path)
    if RUSQLITE.search(source):
        fail(location, "runtime (except ports) must not import rusqlite", "rusqlite")
    for ref in refs:
        if crate_head(ref) == "storage":
            fail(
                location,
                "runtime (except ports) must not import storage",
                "::".join(ref),
            )

for path in rust_files("src/domain"):
    location, refs, _source = refs_in(path)
    for ref in refs:
        head = crate_head(ref)
        if head in {"runtime", "storage", "http", "api", "provider", "timer"}:
            fail(
                location,
                "domain must not import runtime, storage, http/api, provider, or timer",
                "::".join(ref),
            )

if failures:
    unique = list(dict.fromkeys(failures))
    sys.stderr.write("ENDPOINT_MODULE_BOUNDARY_FAILURE: forbidden Endpoint import(s)\n")
    sys.stderr.write("\n".join(unique) + "\n")
    raise SystemExit(1)
PY

printf '%s\n' 'Endpoint module boundary audit: adapter imports stay isolated'
