"""Pre-push leak scan: refuse to publish anything that names a person, a machine, or a secret.

Two layers:
  1. Generic patterns that should never appear in a public repository — machine paths,
     credentials, e-mail addresses, private-network addresses. These ship with the tool.
  2. A local deny-list in `.leak_patterns` (one term per line, gitignored) for the
     things only you would think to check: your own login, your internal project names,
     the repositories you watch private forks of.

A third file, `.leak_allow` (also gitignored), lists literal strings that are public on
purpose — an author's name on a copyright line, the project's own URL. A deny-list hit is
dropped only when the same line contains one of those strings, so attribution passes while
a stray handle or a private term on any other line still blocks.

Exit code 1 means do not push.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

GENERIC = {
    "machine path": re.compile(r"[A-Za-z]:\\\\?Users[\\\\/]|/c/Users/|/home/[a-z]+/\.(?!config)|AppData[\\\\/]Local"),
    "credential": re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY"),
    "e-mail": re.compile(r"[\w.+-]+@[\w-]+\.[a-z]{2,}", re.I),
    "private network": re.compile(r"\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b"),
}

# Files that are allowed to mention the things above, because their job is to describe them.
EXEMPT_SUFFIX = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".pdf", ".zip"}
EXEMPT_NAMES = {"leak_scan.py", ".leak_patterns", ".leak_allow"}


def tracked_files() -> list[Path]:
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return [p for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts]
    return [ROOT / p for p in out.decode("utf-8", "replace").split("\0") if p]


def local_terms() -> list[str]:
    f = ROOT / ".leak_patterns"
    if not f.exists():
        return []
    return [ln.strip() for ln in f.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")]


def allow_phrases() -> list[str]:
    """Literal strings that are deliberately public, e.g. the author's name on a license line.

    A deny-list hit is suppressed only when the same line also contains one of these
    phrases, matched case-sensitively. So `Copyright (c) 2026 Simin Yuan` passes while a
    bare `simin` or a handle-like `simin-yuan` on any other line still blocks.
    """
    f = ROOT / ".leak_allow"
    if not f.exists():
        return []
    return [ln.rstrip("\n") for ln in f.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")]


def main() -> int:
    terms = local_terms()
    allowed = allow_phrases()
    findings = []
    for p in tracked_files():
        if not p.exists() or p.suffix.lower() in EXEMPT_SUFFIX or p.name in EXEMPT_NAMES:
            continue
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        if b"\0" in raw[:4096]:
            continue
        text = raw.decode("utf-8", "replace")
        for label, pat in GENERIC.items():
            for m in pat.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                findings.append((p.relative_to(ROOT).as_posix(), line, label, m.group(0)[:60]))
        for term in terms:
            for m in re.finditer(re.escape(term), text, re.I):
                line = text.count("\n", 0, m.start()) + 1
                lstart = text.rfind("\n", 0, m.start()) + 1
                lend = text.find("\n", m.start())
                linetext = text[lstart: lend if lend != -1 else len(text)]
                if any(ph in linetext for ph in allowed):
                    continue
                findings.append((p.relative_to(ROOT).as_posix(), line, f"deny-list: {term}", m.group(0)))

    if not findings:
        print(f"leak scan: clean ({len(tracked_files())} files, {len(terms)} local terms)")
        return 0
    print(f"leak scan: {len(findings)} finding(s) — do not push", file=sys.stderr)
    for path, line, label, frag in findings:
        print(f"  {path}:{line}  [{label}]  {frag}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
