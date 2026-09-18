#!/usr/bin/env python3
"""secret-vacuum: find plaintext secrets on this machine, remove the ones you approve.

Detection is entirely gitleaks' default ruleset -- this tool writes no regexes. It is
glue: run the scanner, show the hits, move the approved ones to a local trash.

Four guarantees, each covered by a test in test_secret_vacuum.py:
  1. no secret value is ever written to disk by this tool
  2. "remove" moves a file to a local trash; nothing is ever unlinked
  3. the HTTP server binds loopback only and requires a per-run token
  4. nothing is ever sent off the machine
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HOME = Path.home()
STATE = Path(os.environ.get("SECRET_VACUUM_HOME", HOME / ".secret-vacuum"))
TRASH = STATE / "trash"
IGNORE_FILE = STATE / ".gitleaksignore"
UI_FILE = Path(__file__).with_name("ui.html")
CONFIG_FILE = Path(__file__).with_name("gitleaks.toml")
PLACEHOLDER = "<removed by secret-vacuum>"
DOT = "\u2022"

# Credential stores worth scanning by default. Personal directories
# (~/Documents, ~/Downloads, ~/Desktop) are deliberately absent: heavy noise,
# and no engineer's credentials belong there. Add them with --root.
DEFAULT_ROOTS = [
    "~/Documents/GitHub",
    "~/.aws",
    "~/.ssh",
    "~/.dbt",
    "~/.config/gcloud",
    "~/.docker/config.json",
    "~/.kube",
    "~/.netrc",
    "~/.npmrc",
    "~/.pypirc",
    "~/.zshrc",
    "~/.zsh_history",
    "~/.claude.json",
    "~/.cursor",
]

# Rewriting shell history is its own kind of damage, so history files are
# shown and redactable but never removable as a whole file.
REDACT_ONLY = ("/.zsh_history", "/.bash_history")

ACTIONS = ("remove", "redact", "ignore")

# The server is threaded, so two clicks can land at once. apply_actions and undo
# both take this for their whole body, so the guarantee holds for any caller and
# not just for the request handler.
MUTATE = threading.Lock()

# Roots the last scan could not read. Surfaced in the CLI and in the UI, because a
# root that failed is not a root that is clean.
SCAN_FAILURES: list[str] = []


def _binary(name: str) -> str:
    """Resolve once, absolutely. A security tool should not let PATH decide which
    scanner it runs."""
    found = shutil.which(name)
    if not found:
        sys.exit(f"{name} not found on PATH. Install it first: brew install {name}")
    return found

# Files that exist only to hold credentials: removing the whole thing is right.
# Anything else is a file you still want, so the default is to redact the line.
CREDENTIAL_FILES = re.compile(
    r"(^|/)(\.env[^/]*|\.netrc|\.npmrc|\.pypirc|credentials|id_[a-z0-9]+|[^/]+\.(pem|key|p12|pfx|jks))$"
)


# --------------------------------------------------------------------------- model


@dataclass
class Finding:
    """One gitleaks hit. `secret` lives in memory for the lifetime of the run and
    is never serialized -- `public()` is the only thing the UI or disk ever sees."""

    fingerprint: str
    path: str
    rule: str
    description: str
    start_line: int
    end_line: int
    entropy: float
    secret: str = field(repr=False)
    tracked: bool = False

    @property
    def digest(self) -> str:
        """Full SHA-256. Grouping keys off this: a 32-bit prefix collides once in
        roughly a million at this scale, and a collision would apply one secret's
        removal to a different secret's files."""
        return hashlib.sha256(self.secret.encode()).hexdigest()

    @property
    def sha8(self) -> str:
        """Short form, for display and for the manifest. Not reversible."""
        return self.digest[:8]

    @property
    def suggested(self) -> str:
        """Pre-selected action. Never destructive by surprise: whole-file removal is
        only the default for files that are nothing but credential."""
        return "remove" if self.removable and CREDENTIAL_FILES.search(self.path) else "redact"

    @property
    def removable(self) -> bool:
        return not self.path.endswith(REDACT_ONLY)

    def public(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "path": self.path,
            "display": display_path(self.path),
            "rule": self.rule,
            "description": self.description,
            "line": self.start_line,
            "lines": self.end_line - self.start_line + 1,
            "entropy": round(self.entropy, 2),
            "sha8": self.sha8,
            "masked": mask(self.secret),
            "length": len(self.secret),
            "tracked": self.tracked,
            "removable": self.removable,
            "suggested": self.suggested,
        }


@dataclass
class Group:
    """One distinct secret value, wherever it appears. The same credential copied
    across seven worktrees is one thing to deal with, not seven, so the UI lists
    values and an action applies to every copy."""

    key: str  # full sha256 of the value
    members: list[Finding]

    @property
    def lead(self) -> Finding:
        return self.members[0]

    @property
    def tracked(self) -> bool:
        return any(m.tracked for m in self.members)

    @property
    def removable(self) -> bool:
        return all(m.removable for m in self.members)

    @property
    def suggested(self) -> str:
        return "remove" if all(m.suggested == "remove" for m in self.members) else "redact"

    def public(self) -> dict:
        return {
            "key": self.key,
            "sha8": self.lead.sha8,
            "rule": self.lead.rule,
            "description": self.lead.description,
            "masked": mask(self.lead.secret),
            "length": len(self.lead.secret),
            "copies": len(self.members),
            "display": display_path(self.lead.path),
            "line": self.lead.start_line,
            "paths": [f"{display_path(m.path)}:{m.start_line}" for m in self.members[:40]],
            "tracked": self.tracked,
            "tracked_copies": sum(m.tracked for m in self.members),
            "removable": self.removable,
            "suggested": self.suggested,
        }


def group_findings(findings: list[Finding]) -> list[Group]:
    by_value: dict[str, list[Finding]] = {}
    for f in findings:
        by_value.setdefault(f.digest, []).append(f)
    groups = [Group(k, sorted(v, key=lambda m: m.path)) for k, v in by_value.items()]
    return sorted(groups, key=lambda g: (not g.tracked, -len(g.members), g.lead.path))


def mask(value: str) -> str:
    """First four and last four. You should not need to read a secret to decide on it."""
    v = value.strip()
    return DOT * len(v) if len(v) <= 12 else v[:4] + DOT * 6 + v[-4:]


def display_path(path: str) -> str:
    try:
        return "~/" + str(Path(path).relative_to(HOME))
    except ValueError:
        return path


# --------------------------------------------------------------------------- scan


@functools.lru_cache(maxsize=None)
def git_tracked(path: str) -> bool:
    """True if git has this file committed, which means deleting it here does not
    unleak it -- the value is in every clone and needs rotating instead."""
    p = Path(path)
    r = subprocess.run(
        [_binary("git"), "-C", str(p.parent), "ls-files", "--error-unmatch", "--", p.name],
        capture_output=True,
        text=True,
    )
    return r.returncode == 0


@functools.lru_cache(maxsize=1)
def gitleaks_version() -> str:
    return subprocess.run([_binary("gitleaks"), "version"], capture_output=True,
                          text=True).stdout.strip() or "unknown"


def scan_root(root: Path) -> list[dict]:
    """Report goes to stdout, so no file holding secrets is ever created."""
    cmd = [
        _binary("gitleaks"), "dir", str(root),
        "--report-format", "json", "--report-path", "-",
        "--no-banner", "--log-level", "error", "--exit-code", "0",
        "--max-target-megabytes", "10",
        # Explicit config, so a scanned repo's own .gitleaks.toml cannot
        # allowlist away its leaks behind our back.
        "--config", str(CONFIG_FILE),
    ]
    if IGNORE_FILE.exists():
        cmd += ["--gitleaks-ignore-path", str(IGNORE_FILE)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    out = r.stdout.strip()
    # Success is the exit code, not the shape of stdout. With --exit-code 0 gitleaks
    # returns 0 for a completed scan whether or not it found anything, and non-zero
    # for a real error. Judging by stdout instead would be version-fragile, and a
    # scanner that failed must never read as "nothing found" in a tool whose whole
    # job is finding things.
    if r.returncode != 0:
        raise RuntimeError(f"gitleaks failed on {root}: {(r.stderr or out).strip()[:400]}")
    if not out:
        return []  # completed, found nothing
    try:
        return json.loads(out)
    except ValueError as e:
        raise RuntimeError(f"gitleaks returned unreadable output for {root}: {e}") from None


def scan(roots: list[str], progress: bool = False) -> list[Finding]:
    """A first run over a developer's whole code directory takes minutes, so say
    what is happening rather than looking hung."""
    paths = [p for p in (Path(r).expanduser() for r in roots) if p.exists()]
    raw: list[dict] = []
    failures: list[str] = []
    SCAN_FAILURES.clear()
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(scan_root, p): p for p in paths}
        for done, future in enumerate(as_completed(futures), start=1):
            root = display_path(str(futures[future]))
            try:
                hits = future.result()
            except RuntimeError as e:
                # One unreadable root must not throw away what the others found,
                # but it must not pass unnoticed either.
                failures.append(f"{root}: {e}")
                if progress:
                    print(f"  [{done}/{len(paths)}] {root} FAILED", flush=True)
                continue
            raw += hits
            if progress:
                print(f"  [{done}/{len(paths)}] {root} "
                      f"({len(hits)} hit{'' if len(hits) == 1 else 's'})", flush=True)
    if failures:
        SCAN_FAILURES.extend(failures)
        if len(failures) == len(paths):
            # Nothing was scanned at all. Returning an empty list here would read as
            # a clean machine, which is the one thing this tool must never do.
            raise RuntimeError("; ".join(failures))
        if progress:
            print(f"  {len(failures)} root(s) could not be scanned:", flush=True)
            for f in failures:
                print(f"    {f[:200]}", flush=True)

    found: dict[str, Finding] = {}
    for h in raw:
        path = h.get("SymlinkFile") or h["File"]
        f = Finding(
            fingerprint=h["Fingerprint"],
            path=path,
            rule=h["RuleID"],
            description=h["Description"],
            start_line=h["StartLine"],
            end_line=h["EndLine"],
            entropy=h.get("Entropy", 0.0),
            secret=h["Secret"],
        )
        found.setdefault(f.fingerprint, f)

    for f in found.values():
        f.tracked = git_tracked(f.path)
    return sorted(found.values(), key=lambda f: (not f.tracked, f.path, f.start_line))


# --------------------------------------------------------------------------- actions


def _batch_dir() -> Path:
    # Microseconds, because two applies in the same second would otherwise share a
    # directory and a single undo would put both of them back. The format still
    # sorts lexicographically, which is how batches() orders them.
    d = TRASH / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    (d / "files").mkdir(parents=True, exist_ok=True)
    return d


def _stash(batch: Path, src: Path) -> Path:
    """Copy a file into the batch preserving its absolute path, so undo is a reversal."""
    dest = batch / "files" / str(src).lstrip("/")
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    return dest


def redact_lines(lines: list[str], f: Finding) -> tuple[list[str], bool]:
    """Replace the secret inside its own line. Locating it by value rather than by
    gitleaks' column offsets keeps this exact and self-validating: if the value is
    not on the line any more, we refuse instead of corrupting the file."""
    lo, hi = f.start_line - 1, f.end_line
    if not 0 <= lo < len(lines):
        return lines, False
    out = list(lines)
    if f.end_line > f.start_line:  # multi-line, e.g. a PEM block
        # Collapsing a block shortens the file, so a later finding's line numbers
        # no longer mean what gitleaks said. Checking that the value is still in
        # the slice catches that: two overlapping blocks would otherwise eat the
        # lines between them.
        if f.secret.strip() not in "".join(out[lo:hi]):
            return lines, False
        out[lo:hi] = [f"{PLACEHOLDER}\n"]
        return out, True
    if f.secret not in out[lo]:
        return lines, False
    out[lo] = out[lo].replace(f.secret, PLACEHOLDER)
    return out, True


def apply_actions(groups: dict[str, Group], requested: list[dict]) -> dict:
    """One trash batch per call. Removals win over redactions on the same file.
    An action on a group applies to every copy of that value."""
    with MUTATE:
        return _apply_actions(groups, requested)


def _apply_actions(groups: dict[str, Group], requested: list[dict]) -> dict:
    chosen = [
        (member, r["action"])
        for r in requested
        if r.get("key") in groups and r.get("action") in ACTIONS
        for member in groups[r["key"]].members
    ]
    owner = {m.fingerprint: r["key"] for r in requested if r.get("key") in groups
             for m in groups[r["key"]].members}
    remove = {f.path for f, a in chosen if a == "remove" and f.removable}
    results, entries = [], []
    batch = _batch_dir() if any(a != "ignore" for _, a in chosen) else None

    # Redact first: a file also queued for removal is skipped, not double-handled.
    by_file: dict[str, list[Finding]] = {}
    for f, a in chosen:
        if a == "redact" and f.path not in remove:
            by_file.setdefault(f.path, []).append(f)

    for path, group in by_file.items():
        src = Path(path)
        if not src.is_file():
            results += [{"fingerprint": f.fingerprint, "ok": False, "detail": "file is gone"} for f in group]
            continue
        lines = src.read_text(encoding="utf-8", errors="surrogateescape").splitlines(keepends=True)
        changed = False
        for f in sorted(group, key=lambda f: -f.start_line):
            lines, ok = redact_lines(lines, f)
            results.append({
                "fingerprint": f.fingerprint, "ok": ok,
                "detail": "redacted" if ok else "value no longer on that line, left alone",
            })
            if ok:
                changed = True
                entries.append({"path": path, "action": "redact", "rule": f.rule,
                                "sha8": f.sha8, "line": f.start_line})
        # Only touch the file if something actually changed. Stashing regardless
        # would leave an orphaned copy of the secret in the trash and bump the
        # mtime of a file we did not edit. The original is still on disk here.
        if changed:
            _stash(batch, src)
            src.write_text("".join(lines), encoding="utf-8", errors="surrogateescape")

    moved: set[str] = set()
    for f, a in chosen:
        if a == "remove":
            if not f.removable:
                results.append({"fingerprint": f.fingerprint, "ok": False,
                                "detail": "history file: redact instead of removing"})
            elif f.path in moved:
                # Two secrets in one file: the first move took care of both.
                results.append({"fingerprint": f.fingerprint, "ok": True, "detail": "moved to trash"})
            elif not Path(f.path).exists():
                results.append({"fingerprint": f.fingerprint, "ok": False, "detail": "already gone"})
            else:
                dest = batch / "files" / f.path.lstrip("/")
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(f.path, dest)  # move, never unlink
                moved.add(f.path)
                entries.append({"path": f.path, "action": "remove", "rule": f.rule, "sha8": f.sha8})
                results.append({"fingerprint": f.fingerprint, "ok": True, "detail": "moved to trash"})
        elif a == "ignore":
            add_ignore(f.fingerprint)
            results.append({"fingerprint": f.fingerprint, "ok": True, "detail": "ignored from now on"})

    # A redaction on a file that was also removed never ran, but the value went with
    # the file. Say so, rather than leaving that row with no outcome at all.
    for f, a in chosen:
        if a == "redact" and f.path in remove:
            gone = f.path in moved
            results.append({
                "fingerprint": f.fingerprint, "ok": gone,
                "detail": "removed with the file" if gone else "the file could not be removed",
            })

    rolled: dict[str, dict] = {}
    for r in results:
        key = owner.get(r["fingerprint"])
        if key is None:
            continue
        agg = rolled.setdefault(key, {"key": key, "ok": False, "done": 0, "failed": 0, "detail": ""})
        agg["done" if r["ok"] else "failed"] += 1
        if not r["ok"] and not agg["detail"]:
            agg["detail"] = r["detail"]
    for agg in rolled.values():
        agg["ok"] = agg["done"] > 0 and agg["failed"] == 0
        if agg["ok"]:
            agg["detail"] = f"handled {agg['done']} cop{'y' if agg['done'] == 1 else 'ies'}"
        elif agg["done"]:
            agg["detail"] = f"{agg['done']} done, {agg['failed']} skipped: {agg['detail']}"
    results = list(rolled.values())

    if batch:
        # Paths, rule ids and hashes only. No secret value reaches this file.
        (batch / "manifest.json").write_text(
            json.dumps({"created": datetime.now(timezone.utc).isoformat(), "entries": entries}, indent=1)
        )
        if not entries:
            shutil.rmtree(batch, ignore_errors=True)
            batch = None
    return {"batch": batch.name if batch else None, "results": results}


def add_ignore(fingerprint: str) -> None:
    """gitleaks' own ignore format: fingerprints, never values."""
    IGNORE_FILE.parent.mkdir(parents=True, exist_ok=True)
    current = IGNORE_FILE.read_text().splitlines() if IGNORE_FILE.exists() else []
    if fingerprint not in current:
        with IGNORE_FILE.open("a") as fh:
            fh.write(fingerprint + "\n")


def batches() -> list[Path]:
    """Batches holding at least one file. An empty directory left behind by a
    failed cleanup would otherwise make undo report restoring nothing as success."""
    if not TRASH.exists():
        return []
    return sorted(
        d for d in TRASH.iterdir()
        if d.is_dir() and not d.name.endswith(".restored")
        and any(f.is_file() for f in (d / "files").rglob("*"))
    )


def undo(batch: Path | None = None) -> dict:
    """Put a batch back where it came from. This moves rather than copies, so a
    restored secret does not also stay behind in the trash as a second plaintext
    copy the user never asked for."""
    with MUTATE:
        # One listing, taken under the lock: a second caller must see the trash as
        # this one leaves it, not as it was before.
        existing = batches()
        batch = batch or (existing[-1] if existing else None)
        if not batch or not batch.is_dir():
            return {"ok": False, "detail": "nothing in the trash"}
        files = batch / "files"
        restored, stuck = 0, 0
        for src in sorted(files.rglob("*")):
            if not src.is_file():
                continue
            dest = Path("/") / src.relative_to(files)
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(src), dest)
                restored += 1
            except OSError:
                stuck += 1
        if stuck:
            # Something could not go home. Keep the batch rather than lose it.
            batch.rename(batch.with_name(batch.name + ".restored"))
            return {"ok": False, "detail": f"restored {restored}, {stuck} could not be put back"}
        shutil.rmtree(batch, ignore_errors=True)
        return {"ok": True, "detail": f"restored {restored} file(s) from {batch.name}"}


# --------------------------------------------------------------------------- server


class Handler(BaseHTTPRequestHandler):
    server_version = "secret-vacuum"
    state: dict = {}

    # The URL carries the token, and the default handler logs every URL to stderr.
    def log_message(self, *_args):  # noqa: D102
        pass

    def _authorized(self) -> bool:
        port = self.state["port"]
        if (self.headers.get("Host") or "") != f"127.0.0.1:{port}":
            return False  # DNS-rebinding guard: only the literal loopback host
        origin = self.headers.get("Origin")
        if origin and origin != f"http://127.0.0.1:{port}":
            return False
        sent = self.headers.get("X-SV-Token") or parse_qs(urlparse(self.path).query).get("t", [""])[0]
        # Bytes, not str: compare_digest raises TypeError on a non-ASCII string, and
        # a bad token must fail the check rather than crash the handler.
        return hmac.compare_digest(sent.encode("utf-8", "replace"),
                                   self.state["token"].encode())

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()  # no CORS header is ever emitted
        self.wfile.write(body)

    def _json(self, payload: dict, code: int = 200) -> None:
        self._send(code, json.dumps(payload).encode(), "application/json")

    def do_GET(self) -> None:  # noqa: N802
        if not self._authorized():
            return self._send(403, b"forbidden", "text/plain")
        route = urlparse(self.path).path
        if route == "/":
            return self._send(200, UI_FILE.read_bytes(), "text/html; charset=utf-8")
        if route == "/api/findings":
            return self._json(self.snapshot())
        self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        if not self._authorized():
            return self._send(403, b"forbidden", "text/plain")
        route = urlparse(self.path).path
        if route == "/api/rescan":
            git_tracked.cache_clear()  # a file may have been committed since the last scan
            self.state["groups"] = {g.key: g for g in group_findings(scan(self.state["roots"]))}
            self.state["scanned_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            return self._json(self.snapshot())
        if not self.state["apply"]:
            return self._json({"error": "preview mode: restart with --apply to make changes"}, 403)
        length = int(self.headers.get("Content-Length") or 0)
        if length > 1_000_000:
            return self._json({"error": "request too large"}, 413)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._json({"error": "malformed request body"}, 400)
        if not isinstance(body, dict):
            return self._json({"error": "malformed request body"}, 400)
        if route == "/api/apply":
            out = apply_actions(self.state["groups"], body.get("actions", []))
        elif route == "/api/undo":
            out = undo()
        else:
            return self._send(404, b"not found", "text/plain")
        # Handled findings stay in the list so the UI can show what happened to
        # each one. Rescan is what clears them.
        self._json({**out, **self.snapshot()})

    def snapshot(self) -> dict:
        groups = list(self.state["groups"].values())
        return {
            "findings": [g.public() for g in groups],
            "locations": sum(len(g.members) for g in groups),
            "apply": self.state["apply"],
            "roots": [display_path(r) for r in self.state["roots"]],
            "scanned_at": self.state["scanned_at"],
            "gitleaks": self.state["gitleaks"],
            "batches": [b.name for b in batches()],
            "failures": list(SCAN_FAILURES),
        }


def serve(findings: list[Finding], roots: list[str], apply_mode: bool, open_browser: bool = True) -> str:
    Handler.state = {
        "groups": {g.key: g for g in group_findings(findings)},
        "roots": roots,
        "apply": apply_mode,
        "token": secrets.token_urlsafe(32),
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "gitleaks": gitleaks_version(),
        "port": 0,
    }
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)  # loopback only
    Handler.state["port"] = httpd.server_address[1]
    url = f"http://127.0.0.1:{httpd.server_address[1]}/?t={Handler.state['token']}"
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    # flush: the URL must reach a pipe immediately, not sit in a block buffer
    print(f"  {'APPLY - changes are live' if apply_mode else 'PREVIEW - read only, --apply to enable changes'}")
    print(f"  {url}\n  ctrl-c to stop", flush=True)
    if open_browser:
        webbrowser.open(url)
    return url


# --------------------------------------------------------------------------- cli


def print_table(findings: list[Finding]) -> None:
    groups = group_findings(findings)
    if not groups:
        print("No secrets found.")
        return
    print(f"{'VALUE':<18}  {'RULE':<24}  {'COPIES':>6}  {'FLAGS':<10}  FIRST SEEN")
    for g in groups:
        print(f"{mask(g.lead.secret):<18}  {g.lead.rule[:24]:<24}  {len(g.members):>6}  "
              f"{'committed' if g.tracked else '':<10}  {display_path(g.lead.path)[-60:]}:{g.lead.start_line}")
    for f in SCAN_FAILURES:
        print(f"  WARNING unscanned: {f[:200]}")
    tracked = sum(g.tracked for g in groups)
    print(f"\n{len(groups)} distinct secret(s) across {len(findings)} location(s). "
          f"{tracked} appear in a committed file: rotate those, removing the file does not unleak them.")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="secret-vacuum", description=__doc__.splitlines()[0])
    ap.add_argument("command", nargs="?", default="ui", choices=("ui", "scan", "undo"))
    ap.add_argument("--root", action="append", default=[], metavar="PATH",
                    help="scan this path instead of the defaults (repeatable)")
    ap.add_argument("--apply", action="store_true", help="allow changes; without it the UI is read only")
    ap.add_argument("--json", action="store_true", help="with scan: emit findings as JSON (masked, never values)")
    ap.add_argument("--no-browser", action="store_true", help="do not open a browser")
    a = ap.parse_args(argv)

    if a.command == "undo":
        r = undo()
        print(r["detail"])
        return 0 if r["ok"] else 1

    roots = a.root or DEFAULT_ROOTS
    if not (a.command == "scan" and a.json):
        print(f"secret-vacuum  |  gitleaks {gitleaks_version()}  |  scanning {len(roots)} root(s)...")
    findings = scan(roots, progress=not (a.command == "scan" and a.json))

    if a.command == "scan":
        if a.json:
            print(json.dumps([g.public() for g in group_findings(findings)], indent=1))
        else:
            print_table(findings)
        return 0

    serve(findings, roots, a.apply, open_browser=not a.no_browser)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
