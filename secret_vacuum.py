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
import base64
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
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePath
from urllib.parse import parse_qs, quote, unquote, urlparse

HOME = Path.home()
STATE = Path(os.environ.get("SECRET_VACUUM_HOME", HOME / ".secret-vacuum"))
TRASH = STATE / "trash"
IGNORE_FILE = STATE / ".gitleaksignore"
UI_FILE = Path(__file__).with_name("ui.html")
CONFIG_FILE = Path(__file__).with_name("gitleaks.toml")
PLACEHOLDER = "<removed by secret-vacuum>"
DOT = "\u2022"

# Credential stores an infostealer walks, per platform. Used by --quick; the
# default scope is the whole home directory minus DENY, because an allow-list is
# wrong again the next time a vendor invents a dotfile.
QUICK_ROOTS = [
    ".aws", ".azure", ".config/gcloud", ".oci", ".kube", ".docker/config.json",
    ".terraform.d", ".snowflake", ".databrickscfg", ".dbt",
    ".ssh", ".netrc", "_netrc", ".config/rclone",
    ".npmrc", ".pypirc", ".config/pip", ".gem/credentials", ".composer/auth.json",
    ".m2/settings.xml", ".gradle/gradle.properties", ".cargo/credentials.toml",
    ".git-credentials", ".config/git", ".config/gh", ".pgpass", ".my.cnf",
    # editors and agents: 2026 stealers target these directly
    ".claude.json", ".claude", ".cursor", ".continue", ".codeium", ".aider.conf.yml",
    ".config/configstore",
    # every shell startup file, because an exported token lives in whichever one
    # set it and the live environment has no file to remove
    ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".bashrc", ".bash_profile",
    ".bash_login", ".profile", ".config/fish/config.fish",
    ".zsh_history", ".bash_history", ".zsh_sessions",
    "Documents/WindowsPowerShell", "Documents/PowerShell",
    "AppData/Roaming/gcloud", "AppData/Roaming/pip",
    "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine",
]

# Trees no credential of yours is authored in. Skipped for speed. This is the only
# kind of skipping done silently; anything that drops an actual finding is a
# SUPPRESSOR, which is counted and shown.
DENY = [
    "Library/Caches", "Library/Containers", "Library/Group Containers",
    "Library/Developer/CoreSimulator", "Library/Developer/Xcode/DerivedData",
    "Library/Application Support/Docker Desktop",
    "AppData/Local/Temp", "AppData/Local/Packages",
    ".Trash", ".local/share/Trash", "$RECYCLE.BIN", ".cache",
    "OrbStack", ".orbstack", ".docker/desktop", ".vagrant.d", "VirtualBox VMs",
]


def quick_roots() -> list[str]:
    """The curated sweep: seconds rather than minutes."""
    home = Path.home()
    return [str(home / r) for r in QUICK_ROOTS if (home / r).exists()]


def default_roots() -> list[str]:
    """Everything you own. The deny-list, not an allow-list, decides what is out."""
    return [str(Path.home())]


# Rewriting shell history is its own kind of damage, so history files are
# shown and redactable but never removable as a whole file.
def base_name(path: str) -> str:
    """Final component, splitting on both separators. PurePath would use only the
    host's separator, so a Windows path inspected on POSIX is one long filename and
    every name-based guard below silently stops matching."""
    return re.split(r"[\\/]", str(path))[-1]


# Matched on the file name: the old suffix test looked for "/.bash_history",
# which no Windows path contains, so the guard quietly did nothing there.
REDACT_ONLY = frozenset({
    ".zsh_history", ".bash_history", ".sh_history", ".history",
    ".python_history", ".node_repl_history", ".psql_history", ".mysql_history",
    "ConsoleHost_history.txt",
})

ACTIONS = ("remove", "redact", "ignore")

# Editing these corrupts something. Terraform state is the clear case: the JSON
# stays parseable after a line-level replace but no longer describes reality, and
# the next apply destroys and recreates. Deleting the file is worse. So they are
# reported, and the only honest action is to rotate the credential upstream.
ROTATE_ONLY = re.compile(r"\.tfstate(\.backup)?$", re.IGNORECASE)

# Formats where a successful write still has to produce a parseable document.
STRUCTURED = {
    ".json": json.loads,
    ".tfstate": json.loads,
}


@dataclass(frozen=True)
class Suppressor:
    """A filter that drops a real finding.

    These used to live in gitleaks.toml, where the effect was invisible: a scan
    that filtered everything and a scan that found nothing both printed nothing.
    One of them matched the *line* and so suppressed an AKIA access key id
    embedded in a presigned S3 URL, and there was no way to see that had
    happened. Now every drop is counted, attributed to a named rule, and can be
    revealed or switched off.

    `generic_only` is the structural half of that fix: a filter that reasons
    about surrounding context may never overrule a typed, high-confidence rule."""

    name: str
    reason: str
    pattern: re.Pattern
    target: str = "secret"  # "secret" or "match" (the surrounding text gitleaks matched)
    generic_only: bool = False

    def hides(self, f: Finding) -> bool:
        if self.generic_only and "generic" not in f.rule:
            return False
        return bool(self.pattern.search(f.secret if self.target == "secret" else f.match))


SUPPRESSORS = [
    Suppressor("placeholder", "documentation placeholder, not a value", re.compile(
        r"""(?ix) ^(bearer\s+)? [<{\[]? (your|my)[-_ ] | ^[<{].+[>}]$
            | (changeme|change[-_]me|replace[-_]?me|insert[-_]?your|placeholder
               |redacted|^dummy|^sample[-_]|^example[-_]|^test[-_]token|^fake[-_])""")),
    Suppressor("env-reference", "a pointer to a secret, not one",
               re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$")),
    Suppressor("filler", "keyboard-mash or one character repeated", re.compile(
        r"(?i)^(0?123456789|1234567890|abcdef|deadbeef|0123456789abcdef|1234567890abcdef)"
        # Python has backreferences, unlike the RE2 engine gitleaks uses, so this
        # is one pattern instead of the six spelled-out ones it replaces.
        r"|^(.)\2{5,}$")),
    Suppressor("aws-example-key", "the key id from AWS' own documentation",
               re.compile(r"^AKIAIOSFODNN7EXAMPLE$")),
    # Scoped to generic rules and to the surrounding text. An S3 presigned URL is a
    # time-limited signature, but it carries a real AKIA id, and the typed
    # aws-access-token hit for that id must survive this filter.
    Suppressor("presigned-url", "an expiring S3 signature, not a stored credential",
               re.compile(r"X-Amz-(Signature|Credential)="), target="match",
               generic_only=True),
]


def partition(findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    """Kept, and dropped-with-a-reason. Nothing leaves without being counted."""
    kept, dropped = [], []
    for f in findings:
        hit = next((s for s in SUPPRESSORS if s.hides(f)), None)
        if hit:
            f.suppressed_by, f.suppressed_why = hit.name, hit.reason
            dropped.append(f)
        else:
            kept.append(f)
    return kept, dropped

# The server is threaded, so two clicks can land at once. apply_actions and undo
# both take this for their whole body, so the guarantee holds for any caller and
# not just for the request handler.
MUTATE = threading.Lock()

# Roots the last scan could not read. Surfaced in the CLI and in the UI, because a
# root that failed is not a root that is clean.



def _binary(name: str) -> str:
    """Resolve once, absolutely. A security tool should not let PATH decide which
    scanner it runs. Raises rather than exiting: this is called from worker
    threads and from request handlers, where sys.exit would surface as a
    traceback instead of the message. FileNotFoundError is an OSError, so the
    scan-failure handlers already cover it."""
    found = shutil.which(name)
    if not found:
        how = {"darwin": f"brew install {name}",
               "win32": f"winget install {name}"}.get(sys.platform, f"your package manager: {name}")
        raise FileNotFoundError(f"{name} not found on PATH. Install it first: {how}")
    return found

# Files that exist only to hold credentials: removing the whole thing is right.
# Anything else is a file you still want, so the default is to redact the line.
# Matched against the name alone, so a backslash-separated path works too.
CREDENTIAL_FILES = re.compile(
    r"^(\.env.*|\.netrc|_netrc|\.npmrc|\.pypirc|credentials|credentials\.tfrc\.json"
    r"|auth\.json|\.pgpass|id_[a-z0-9]+|.+\.(pem|key|p12|pfx|jks|ovpn|keystore))$",
    re.IGNORECASE,
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
    match: str = field(default="", repr=False)
    # "pattern" (gitleaks matched a regex) or "schema" (we parsed the format and
    # read a field that is a credential by definition). Different trust, so the
    # UI ranks on it and can hide one.
    detector: str = "pattern"
    # Set only by an explicit --verify live run; ("", "") otherwise.
    live: tuple[str, str] = ("", "")
    tracked: bool = False
    suppressed_by: str = ""
    suppressed_why: str = ""

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
        if not self.editable:
            return "ignore"
        return "remove" if self.removable and CREDENTIAL_FILES.match(base_name(self.path)) else "redact"

    @property
    def removable(self) -> bool:
        return base_name(self.path) not in REDACT_ONLY and self.editable

    @property
    def editable(self) -> bool:
        """False where any edit is worse than the leak it removes."""
        return not ROTATE_ONLY.search(base_name(self.path))

    @property
    def state(self) -> tuple[str, str]:
        """What can be known about this value without asking anyone."""
        return offline_check(self.secret)

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
            "editable": self.editable,
            "suggested": self.suggested,
            "detector": self.detector,
            "state": self.state[0],
            "state_detail": self.state[1],
            "live": self.live[0],
            "live_detail": self.live[1],
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
    def editable(self) -> bool:
        return all(m.editable for m in self.members)

    @property
    def suggested(self) -> str:
        if not self.editable:
            return "ignore"
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
            # Every location, not a sample. The UI scrolls them; a caller piping
            # --json into automation must not silently lose any.
            "paths": [f"{display_path(m.path)}:{m.start_line}" for m in self.members],
            "tracked": self.tracked,
            "tracked_copies": sum(m.tracked for m in self.members),
            "removable": self.removable,
            "editable": self.editable,
            "suggested": self.suggested,
            "detector": "schema" if any(m.detector == "schema" for m in self.members) else "pattern",
            "state": self.lead.state[0],
            "state_detail": self.lead.state[1],
            "live": self.lead.live[0],
            "live_detail": self.lead.live[1],
        }


def group_findings(findings: list[Finding]) -> list[Group]:
    by_value: dict[str, list[Finding]] = {}
    for f in findings:
        by_value.setdefault(f.digest, []).append(f)
    groups = [Group(k, sorted(v, key=lambda m: m.path)) for k, v in by_value.items()]
    # Exploitability, not presence: proven live first, then committed, then shape.
    rank = {"live": 0, "": 1, "skipped": 1, "unknown": 1, "revoked": 3}
    return sorted(groups, key=lambda g: (rank.get(g.lead.live[0], 2), not g.tracked,
                                         g.lead.state[0] == "expired",
                                         -len(g.members), g.lead.path))


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


# Every field group_findings reads off a report entry. Anything else is optional.
REPORT_KEYS = ("Fingerprint", "File", "RuleID", "Description", "StartLine", "EndLine", "Secret")


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
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
    except OSError as e:
        # The binary was there when we resolved it and is not now, or cannot be
        # executed. Same contract as any other scan failure: loud, not empty.
        raise RuntimeError(f"could not run gitleaks for {root}: {e}") from None
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
        hits = json.loads(out)
        missing = {k for h in hits for k in REPORT_KEYS if k not in h}
    except (ValueError, TypeError, AttributeError) as e:
        raise RuntimeError(f"gitleaks returned unreadable output for {root}: {e}") from None
    if missing:
        # Checked here, where the report is parsed, so a schema change in some future
        # gitleaks reads as a scan failure like any other rather than as a KeyError
        # tracebacking out of the CLI or dropping a request half way through.
        raise RuntimeError(f"gitleaks report for {root} is missing "
                           + ", ".join(sorted(missing)))
    return hits


def scan(roots: list[str], progress: bool = False,
         failures: list[str] | None = None,
         suppressed: list[Finding] | None = None) -> list[Finding]:
    """A first run over a developer's whole code directory takes minutes, so say
    what is happening rather than looking hung."""
    wanted = [Path(r).expanduser() for r in roots]
    paths = [p for p in wanted if p.exists()]
    if wanted and not paths:
        # Nothing to scan is not the same as nothing found. Returning [] here would
        # report a clean machine for a typo in --root.
        raise RuntimeError("none of the requested roots exist: "
                           + ", ".join(display_path(str(p)) for p in wanted[:8]))
    # The caller owns this list, so two concurrent scans cannot overwrite each
    # other's failures the way a module global did.
    failures = [] if failures is None else failures
    suppressed = [] if suppressed is None else suppressed
    del failures[:], suppressed[:]
    raw: list[dict] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(scan_root, p): p for p in paths}
        for done, future in enumerate(as_completed(futures), start=1):
            root = display_path(str(futures[future]))
            try:
                hits = future.result()
            except (RuntimeError, OSError) as e:
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
            match=h.get("Match", ""),
        )
        found.setdefault(f.fingerprint, f)

    # Schema parsers walk the same roots: a file gitleaks found nothing in can
    # still be a kubeconfig full of credentials. Where both detectors see the same
    # value in the same file, gitleaks' entry wins -- it carries the real line
    # number, which is what redaction edits.
    seen = {(f.path, f.digest) for f in found.values()}
    skip = ignored_fingerprints()
    for f in parse_roots(paths):
        if f.fingerprint in skip or f"sv:{f.sha8}" in skip:
            continue
        if (f.path, f.digest) not in seen:
            seen.add((f.path, f.digest))
            found.setdefault(f.fingerprint, f)

    found = {k: f for k, f in found.items() if f"sv:{f.sha8}" not in skip}
    kept, dropped = partition(list(found.values()))
    suppressed.extend(dropped)
    if progress and dropped:
        by_rule = Counter(f.suppressed_by for f in dropped)
        print(f"  {len(dropped)} finding(s) suppressed: "
              + ", ".join(f"{n} {k}" for k, n in by_rule.most_common()), flush=True)
    for f in kept:
        f.tracked = git_tracked(f.path)
    return sorted(kept, key=lambda f: (not f.tracked, f.path, f.start_line))


# --------------------------------------------------------------------------- schema parsers
#
# gitleaks matches patterns against lines. That misses two whole categories: a
# value whose variable name is not in its keyword list (cs=, setup_token=), and a
# value inside a format where the field name already tells you it is a
# credential. Parsing the format has no false positives to trade away -- a
# kubeconfig client-key-data IS a private key -- so these run beside gitleaks
# rather than instead of it, and carry detector="schema" so the UI can rank them
# above a pattern match.

# Names that are public by definition. Validated against a real corpus before it
# shipped: on 15 .env files it keeps 14 candidates and drops 27, and the dropped
# set is exactly URLs, anon keys, site keys, ids and display names.
PUBLIC_NAME = re.compile(
    # suffixes: what the value IS
    r"(_URL|_URI|_HOST|_PORT|_ID|_NAME|_REGION|_BUCKET|_EMAIL|_USER|_ENV|_PATH|_DIR"
    r"|_VERSION|_MODEL|CLIENT_ID)$"
    # anywhere: a key that says on its face it is meant to be published. Anchoring
    # these too let VITE_SUPABASE_ANON_KEY through, because it ends in _KEY.
    r"|(PUBLIC|ANON|SITE_KEY|PUBLISHABLE)", re.IGNORECASE)
PUBLIC_VALUE = re.compile(r"^(https?://|/|\./|\d+$|true$|false$|<|\$\{|~/)", re.IGNORECASE)
ASSIGN = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.\-]*)\s*[=:]\s*(.+?)\s*$")

# Field names that are a credential wherever they appear in a structured document.
SECRET_FIELD = re.compile(
    r"(password|passwd|secret|token|private[-_]?key|client[-_]?secret|access[-_]?key"
    r"|credential|api[-_]?key|session|(^|[-_])auth([-_]|$))", re.IGNORECASE)

# Names that contain a secret-ish word and are public by definition. A cluster's
# certificate_authority matched "auth"; a CA certificate is meant to be handed out.
NOT_SECRET_FIELD = re.compile(
    r"(certificate_authority|ca_cert|authority_data|auth_provider|authentication_mode"
    r"|token_endpoint|token_uri|auth_url|auth_uri|public_key|_fingerprint)", re.IGNORECASE)

ENV_FILES = re.compile(r"^(\.env.*|.+\.env|\.npmrc|\.pypirc|\.netrc|_netrc|credentials"
                       r"|connections\.toml|\.pgpass|\.aider\.conf\.yml|\.envrc)$", re.IGNORECASE)


# An enum constant reads like a secret field's value but is one of a fixed set:
# authentication_mode = API_AND_CONFIG_MAP is configuration, not a credential.
ENUMISH = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _secret_shaped(value: str) -> bool:
    return (len(value) >= 8 and " " not in value and not ENUMISH.match(value)
            and not value.startswith(("arn:", "http://", "https://", "/", "{", "[")))


def _plausible(name: str, value: str) -> bool:
    value = value.strip().strip('"').strip("'")
    return (len(value) >= 8 and not PUBLIC_NAME.search(name)
            and not PUBLIC_VALUE.match(value) and " " not in value)


def _mk(path: str, line: int, rule: str, desc: str, value: str) -> Finding:
    return Finding(
        fingerprint=f"{path}:{rule}:{line}:{hashlib.sha256(value.encode()).hexdigest()[:8]}",
        path=path, rule=rule, description=desc, start_line=line, end_line=line,
        entropy=0.0, secret=value, match=f"{rule} at line {line}", detector="schema")


def parse_assignments(path: Path, text: str) -> list[Finding]:
    """Every assignment in a file whose whole purpose is credentials. gitleaks'
    generic rule keys off the variable name, so cs= and setup_token= are invisible
    to it; in a .env the file name has already told us what the values are."""
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("#", ";")):
            continue
        m = ASSIGN.match(line)
        if m and _plausible(m.group(1), m.group(2)):
            out.append(_mk(str(path), i, "credential-file-assignment",
                           f"{m.group(1)} in a file that exists to hold credentials",
                           m.group(2).strip().strip('"').strip("'")))
    return out


def _walk_json(node: object, path: list[str]):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk_json(v, path + [str(k)])
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk_json(v, path + [f"[{i}]"])
    else:
        yield ".".join(path), node


# Wrappers that carry no meaning of their own: the name of an output is the key
# above its "value", not the word "value".
WRAPPER_KEYS = frozenset({"value", "attributes", "data", "instances", "resources",
                          "outputs", "root_module", "values", "primary"})


def _is_secret_field(name: str) -> bool:
    return bool(SECRET_FIELD.search(name)) and not NOT_SECRET_FIELD.search(name)


def _leaf_name(where: str) -> str:
    for part in reversed(where.split(".")):
        if part and not part.startswith("[") and part not in WRAPPER_KEYS:
            return part
    return ""


def parse_tfstate(path: Path, text: str) -> list[Finding]:
    """Terraform writes outputs and resource attributes to state in plaintext; the
    `sensitive` flag hides them from CLI output and does not encrypt them. Values
    are frequently base64, which defeats entropy scoring entirely."""
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    out, seen = [], set()

    def add(name: str, value: str, why: str):
        if _secret_shaped(value) and (name, value) not in seen:
            seen.add((name, value))
            out.append(_mk(str(path), 1, "tfstate-attribute",
                           f"{name} in terraform state, {why}", value))

    # Terraform's own signal, which needs no name heuristic at all.
    for name, spec in (doc.get("outputs") or {}).items():
        if isinstance(spec, dict) and spec.get("sensitive") and isinstance(spec.get("value"), str):
            add(name, spec["value"], "an output marked sensitive and stored in plaintext")

    for where, value in _walk_json(doc, []):
        name = _leaf_name(where)
        if isinstance(value, str) and _is_secret_field(name):
            add(name, value, "stored in plaintext")
    return out


def parse_docker_config(path: Path, text: str) -> list[Finding]:
    """auths[].auth is base64 of user:password. Not encryption, and gitleaks sees
    one opaque blob."""
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    out = []
    for registry, entry in (doc.get("auths") or {}).items():
        blob = (entry or {}).get("auth")
        if not blob:
            continue
        try:
            decoded = base64.b64decode(blob + "==").decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - malformed base64 is just not a credential
            continue
        if ":" in decoded:
            out.append(_mk(str(path), 1, "docker-registry-auth",
                           f"base64 user:password for {registry}", decoded.split(":", 1)[1]))
    return out


def parse_kubeconfig(path: Path, text: str) -> list[Finding]:
    """token, password and client-key-data live under users[].user. Parsed rather
    than pattern-matched because removing one has to take its contexts with it."""
    out = []
    user, name = None, ""
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("- name:"):
            name = stripped.split(":", 1)[1].strip()
        m = re.match(r"^\s*(token|password|client-key-data|id-token|refresh-token):\s*(\S+)", line)
        if m and len(m.group(2)) >= 8:
            out.append(_mk(str(path), i, "kubeconfig-credential",
                           f"{m.group(1)} for user {name or '?'}", m.group(2)))
    del user
    return out


def parse_container_env(path: Path, text: str) -> list[Finding]:
    """ENV and ARG in a Dockerfile, environment: in a compose file. A literal here
    is baked into an image or a repo."""
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^\s*(?:ENV|ARG)\s+([A-Za-z_][\w]*)\s*=\s*(\S+)", line) \
            or re.match(r"^\s*-?\s*([A-Z_][A-Z0-9_]{3,})\s*[:=]\s*(\S+)\s*$", line)
        if m and _plausible(m.group(1), m.group(2)):
            out.append(_mk(str(path), i, "container-env",
                           f"{m.group(1)} set literally in a container definition",
                           m.group(2).strip().strip('"').strip("'")))
    return out


# name-or-suffix -> parser. Checked against the file name, cheapest test first.
PARSERS: list[tuple[re.Pattern, object]] = [
    (re.compile(r"\.tfstate(\.backup)?$", re.I), parse_tfstate),
    (re.compile(r"^config\.json$"), parse_docker_config),
    (re.compile(r"^(config|kubeconfig)(\.ya?ml)?$", re.I), parse_kubeconfig),
    (re.compile(r"^(docker-)?compose.*\.ya?ml$|^Dockerfile", re.I), parse_container_env),
    (ENV_FILES, parse_assignments),
]
MAX_PARSE_BYTES = 8 << 20


def parse_file(path: Path) -> list[Finding]:
    """Run whichever parsers claim this file name. A parser that raises is a bug in
    us, never a reason to lose the rest of the scan."""
    name = base_name(str(path))
    claims = [fn for rx, fn in PARSERS if rx.search(name)]
    if not claims:
        return []
    try:
        if path.stat().st_size > MAX_PARSE_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: list[Finding] = []
    for fn in claims:
        try:
            out += fn(path, text)
        except Exception:  # noqa: BLE001
            continue
    return out


def ignored_fingerprints() -> set[str]:
    """gitleaks applies .gitleaksignore to its own findings. The schema parsers are
    ours, so the Ignore action has to reach them here or an ignored value comes
    straight back on the next scan."""
    if not IGNORE_FILE.exists():
        return set()
    try:
        lines = IGNORE_FILE.read_text().splitlines()
    except OSError:
        return set()
    return {ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")}


def parse_roots(roots: list[Path]) -> list[Finding]:
    """One metadata walk, pruned by the same deny-list gitleaks uses."""
    out: list[Finding] = []
    for root in roots:
        if root.is_file():
            out += parse_file(root)
            continue
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda _e: None):
            dirnames[:] = [d for d in dirnames
                           if not any(f"{dirpath}/{d}".endswith(x) or d == x.split("/")[-1]
                                      for x in DENY)
                           and d not in SKIP_DIRS]
            for fn in filenames:
                out += parse_file(Path(dirpath) / fn)
    return out


SKIP_DIRS = frozenset({
    "node_modules", ".venv", "venv", "site-packages", "__pycache__", ".git",
    ".terraform", "dist", "build", "target", ".next", ".cache", "Caches",
    "vendor", "Pods", "dbt_packages", ".mypy_cache", ".pytest_cache", ".Trash",
})


# --------------------------------------------------------------------------- offline checks
#
# "You have 92 secrets" is a list. "7 of these still parse as live credentials and
# 3 expired in March" is a queue. Everything here reaches that second sentence
# without a single packet: a JWT carries its own expiry, a private key either
# parses or does not, an AWS key id has a fixed shape. Live verification -- asking
# the provider -- lives in verify.py, which this module never imports, so the
# scanner, the server and the UI keep their no-network guarantee structurally
# rather than by policy.

JWT_RE = re.compile(r"^[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*$")
AWS_ID_RE = re.compile(r"^(AKIA|ASIA|AIDA|AROA|AGPA|ANPA|ANVA|APKA)[A-Z2-7]{16}$")


def _b64pad(chunk: str) -> bytes:
    return base64.urlsafe_b64decode(chunk + "=" * (-len(chunk) % 4))


def offline_check(value: str) -> tuple[str, str]:
    """(state, detail) with no network. States: live-shape, expired, malformed, unknown.

    "live-shape" never means the credential works -- only that nothing locally
    checkable rules it out. Nothing here is evidence of safety."""
    v = value.strip()
    if JWT_RE.match(v):
        try:
            claims = json.loads(_b64pad(v.split(".")[1]))
        except Exception:  # noqa: BLE001
            return "malformed", "looks like a JWT but the payload does not decode"
        exp = claims.get("exp")
        if isinstance(exp, (int, float)):
            left = exp - datetime.now(timezone.utc).timestamp()
            when = datetime.fromtimestamp(exp, timezone.utc).date().isoformat()
            return ("expired", f"JWT expired {when}") if left <= 0 else \
                   ("live-shape", f"JWT valid until {when}")
        return "live-shape", "JWT with no expiry claim"
    if AWS_ID_RE.match(v):
        return "live-shape", "well-formed AWS key id"
    if "BEGIN" in v and "PRIVATE KEY" in v:
        body = "".join(ln for ln in v.splitlines() if "-----" not in ln)
        try:
            _b64pad(body.replace("/", "_").replace("+", "-"))
        except Exception:  # noqa: BLE001
            return "malformed", "PEM header present but the body does not decode"
        return "live-shape", "private key, parses"
    return "unknown", ""


# --------------------------------------------------------------------------- actions


def _batch_dir() -> Path:
    # Microseconds, because two applies in the same second would otherwise share a
    # directory and a single undo would put both of them back. The format still
    # sorts lexicographically, which is how batches() orders them.
    d = TRASH / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    (d / "files").mkdir(parents=True, exist_ok=True)
    return d


def trash_rel(path: str | PurePath, flavour: type[PurePath] | None = None) -> PurePath:
    """An absolute path encoded as a relative one, for storing inside a batch.

    The root has to become an ordinary component. Joining a rooted path discards
    everything to its left, so `batch / "files" / "C:/Users/x/.env"` is just
    `C:/Users/x/.env` -- the computed trash destination was the original file,
    and the move was a no-op that got recorded as a success. The same is true of
    a UNC share, so the whole anchor is percent-encoded into one component rather
    than guessed at: it is ugly in the tree and exactly reversible, which is the
    right trade on a path that has to put your file back.

    POSIX keeps the layout it always had, so batches from earlier versions still
    restore. `flavour` exists so the Windows behaviour is testable from a POSIX
    machine, which is the only way this stays correct between Windows CI runs."""
    cls = flavour or PurePath
    q = cls(path)
    rest = str(q)[len(q.anchor):]
    if q.anchor in ("", "/"):
        return cls(rest)
    return cls(quote(q.anchor, safe=""), rest)


def trash_abs(rel: PurePath, windows: bool | None = None) -> Path:
    """Inverse of trash_rel, on the platform that wrote the batch."""
    windows = (os.name == "nt") if windows is None else windows
    parts = tuple(rel.parts)
    if windows and parts:
        return Path(unquote(parts[0]), *parts[1:])
    return Path("/", *parts)


def _stash(batch: Path, src: Path) -> Path:
    """Copy a file into the batch preserving its absolute path, so undo is a reversal."""
    dest = batch / "files" / trash_rel(src)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    return dest


def _parse_error(path: Path) -> str:
    """Empty string when the file still parses as whatever its extension claims."""
    parser = STRUCTURED.get(PurePath(base_name(str(path))).suffix.lower())
    if not parser:
        return ""
    try:
        parser(path.read_text(encoding="utf-8", errors="surrogateescape"))
    except (ValueError, OSError) as e:
        return str(e)[:80]
    return ""


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


def valid_actions(requested: object) -> list[dict]:
    """This comes off the wire, so it is checked here once rather than blowing up
    somewhere inside the apply. Raises ValueError, which the handler turns into a
    400; every shape that is not a list of {key, action} is rejected."""
    if not isinstance(requested, list):
        raise ValueError("actions must be a list")
    checked = []
    for r in requested:
        if not isinstance(r, dict):
            raise ValueError("each action must be an object")
        key, action = r.get("key"), r.get("action")
        if not isinstance(key, str) or not key:
            raise ValueError("each action needs a string key")
        if action not in ACTIONS:
            raise ValueError(f"action must be one of {', '.join(ACTIONS)}")
        checked.append({"key": key, "action": action})
    return checked


def apply_actions(groups: dict[str, Group], requested: object) -> dict:
    """One trash batch per call. Removals win over redactions on the same file.
    An action on a group applies to every copy of that value."""
    checked = valid_actions(requested)
    with MUTATE:
        return _apply_actions(groups, checked)


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
    blocked = [(f, a) for f, a in chosen if a != "ignore" and not f.editable]
    results += [{"fingerprint": f.fingerprint, "ok": False,
                 "detail": "terraform state: rotate the credential, editing state corrupts it"}
                for f, _ in blocked]
    stop = {f.fingerprint for f, _ in blocked}

    for f, a in chosen:
        if a == "redact" and f.path not in remove and f.fingerprint not in stop:
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
            stashed = _stash(batch, src)
            src.write_text("".join(lines), encoding="utf-8", errors="surrogateescape")
            # A line-level replace inside a structured document can leave it
            # unparseable. Check, and put the original back rather than hand the
            # user a broken kubeconfig in exchange for a redacted line.
            broke = _parse_error(src)
            if broke:
                shutil.copy2(stashed, src)
                for r in results[-len(group):]:
                    r["ok"], r["detail"] = False, f"left alone: editing it broke the file ({broke})"

    moved: set[str] = set()
    for f, a in chosen:
        if f.fingerprint in stop:
            continue
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
                dest = batch / "files" / trash_rel(f.path)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(f.path, dest)  # move, never unlink
                moved.add(f.path)
                entries.append({"path": f.path, "action": "remove", "rule": f.rule, "sha8": f.sha8})
                results.append({"fingerprint": f.fingerprint, "ok": True, "detail": "moved to trash"})
        elif a == "ignore":
            add_ignore(f)
            results.append({"fingerprint": f.fingerprint, "ok": True, "detail": "ignored from now on"})

    # A redaction on a file that was also removed never ran, but the value went with
    # the file. Say so, rather than leaving that row with no outcome at all.
    for f, a in chosen:
        if a == "redact" and f.path in remove and f.fingerprint not in stop:
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


def add_ignore(f: Finding) -> None:
    """gitleaks' own ignore format: fingerprints, never values.

    Two lines, because there are two detectors. The fingerprint is what gitleaks
    itself honours. The `sv:` line is a SHA-256 prefix of the value, which is how
    the schema parsers honour it -- without it, ignoring the gitleaks hit simply
    let our own finding for the same value take its place on the next scan. It
    also matches what the UI says the button does: the row is a value, and the
    action applies to every copy. gitleaks ignores a line it cannot parse."""
    IGNORE_FILE.parent.mkdir(parents=True, exist_ok=True)
    current = IGNORE_FILE.read_text().splitlines() if IGNORE_FILE.exists() else []
    with IGNORE_FILE.open("a") as fh:
        for line in (f.fingerprint, f"sv:{f.sha8}"):
            if line not in current:
                fh.write(line + "\n")


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
            dest = trash_abs(src.relative_to(files))
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


# --------------------------------------------------------------------------- report-only
#
# Three places a credential can sit where deletion is not the answer. An exported
# variable has no file to remove; a container's environment belongs to the
# container; the OS keystore is where secrets are *supposed* to live. Reporting
# them is still worth doing, because "it is not in a file" is exactly why people
# forget they are there.

CRED_NAME = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API[-_]?KEY|_KEY$"
                       r"|PRIVATE|SESSION|COOKIE|BEARER|_PAT$|SIGNING)", re.IGNORECASE)
# Canonical UUID only. Matching any long hex string would drop real tokens, which
# are frequently 32 hex characters.
UUIDISH = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def env_report(environ: dict | None = None, roots: list[str] | None = None) -> list[dict]:
    """Credential-shaped variables, each traced back to the file that set it.

    Three outcomes, and the middle one is the reason this exists: a value with no
    file behind it cannot be fixed by anything else this tool does."""
    environ = os.environ if environ is None else environ
    sources = [Path(r) for r in (roots or quick_roots())]
    files = [p for p in sources if p.is_file()]
    out = []
    for name, value in sorted(environ.items()):
        # The name is the actionable signal. A high-entropy value under a name
        # that claims nothing is as likely to be a socket path or an instance id,
        # and this report exists to be acted on rather than skimmed past.
        if (not _secret_shaped(value) or len(value) < 16 or UUIDISH.match(value)
                or PUBLIC_NAME.search(name) or not CRED_NAME.search(name)):
            continue
        holders = []
        for f in files:
            try:
                if value in f.read_text(errors="replace"):
                    holders.append(display_path(str(f)))
            except OSError:
                continue
        out.append({
            "name": name, "length": len(value), "sha8": hashlib.sha256(value.encode()).hexdigest()[:8],
            "sources": holders,
            "advice": (f"remove it from {holders[0]}, then `unset {name}` in shells already running"
                       if holders else
                       f"no file on this machine sets this; `unset {name}` clears it here only"),
        })
    return out


def docker_report() -> list[dict]:
    """Variable names and image per running container. Never a value: the point is
    to remind you the container has them, not to copy them out."""
    try:
        ids = subprocess.run([_binary("docker"), "ps", "-q"], capture_output=True,
                             text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return []
    if ids.returncode != 0 or not ids.stdout.strip():
        return []
    out = []
    for cid in ids.stdout.split():
        try:
            r = subprocess.run([_binary("docker"), "inspect", cid], capture_output=True,
                               text=True, timeout=10)
            spec = json.loads(r.stdout)[0]
        except (OSError, subprocess.SubprocessError, ValueError, IndexError, KeyError):
            continue
        names = [e.split("=", 1)[0] for e in (spec.get("Config", {}).get("Env") or [])
                 if CRED_NAME.search(e.split("=", 1)[0])]
        if names:
            out.append({"container": spec.get("Name", cid).lstrip("/"),
                        "image": spec.get("Config", {}).get("Image", "?"), "names": sorted(names)})
    return out


def keystore_report() -> list[dict]:
    """Item and service names only. Nothing here reads a value, and there is no
    delete action: the keystore is the right place for a secret to be."""
    if sys.platform == "darwin":
        cmd, pat = ["security", "dump-keychain"], re.compile(r'"svce"<blob>="([^"]*)"')
    elif os.name == "nt":
        cmd, pat = ["cmdkey", "/list"], re.compile(r"Target:\s*(\S+)")
    else:
        return []
    try:
        # No -d: attributes only, so this never asks for a value and never prompts.
        r = subprocess.run([_binary(cmd[0]), *cmd[1:]], capture_output=True,
                           text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return []
    counts = Counter(m for m in pat.findall(r.stdout) if m)
    return [{"service": k, "items": n} for k, n in counts.most_common(40)]


def print_report(env_rows: list[dict], docker_rows: list[dict], keys: list[dict]) -> None:
    traced = [r for r in env_rows if r["sources"]]
    orphan = [r for r in env_rows if not r["sources"]]
    print(f"\n{len(env_rows)} credential-shaped environment variable(s).")
    for label, rows in (("set by a file you can fix", traced), ("no file sets these", orphan)):
        if not rows:
            continue
        print(f"\n  {label}:")
        for r in rows:
            where = ", ".join(r["sources"]) if r["sources"] else "-"
            print(f"    {r['name']:<34} {r['sha8']}  {where}")
            print(f"        {r['advice']}")
    print("\n  Redacting the file does not change a shell that is already running.")
    if docker_rows:
        print(f"\n{len(docker_rows)} running container(s) hold credential-shaped variables:")
        for d in docker_rows:
            print(f"    {d['container']:<28} {d['image'][:38]:<40} {', '.join(d['names'])[:60]}")
    if keys:
        print(f"\n{sum(k['items'] for k in keys)} keystore item(s) across {len(keys)} service(s). "
              "This is where secrets belong; nothing to remove.")
        for k in keys[:12]:
            print(f"    {k['service'][:52]:<54} {k['items']}")


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
        self._guard(self._get)

    def do_POST(self) -> None:  # noqa: N802
        self._guard(self._post)

    def _guard(self, handler) -> None:
        """Answer every request, even a failing one. Anything reaching here is a
        filesystem error the route did not expect."""
        try:
            handler()
        except OSError as e:
            self._json({"error": f"{type(e).__name__}: {e}"}, 500)

    def _get(self) -> None:
        if not self._authorized():
            return self._send(403, b"forbidden", "text/plain")
        route = urlparse(self.path).path
        if route == "/":
            return self._send(200, UI_FILE.read_bytes(), "text/html; charset=utf-8")
        if route == "/api/findings":
            return self._json(self.snapshot())
        self._send(404, b"not found", "text/plain")

    def _post(self) -> None:
        if not self._authorized():
            return self._send(403, b"forbidden", "text/plain")
        route = urlparse(self.path).path
        if route == "/api/rescan":
            git_tracked.cache_clear()  # a file may have been committed since the last scan
            failures: list[str] = []
            dropped: list[Finding] = []
            try:
                found = scan(self.state["roots"], failures=failures, suppressed=dropped)
                published = _scan_state(found, failures, dropped)
            except (RuntimeError, OSError) as e:
                # scan raises when no root could be read at all, and grouping
                # shells out to git. Answer with the reason rather than dropping
                # the connection.
                return self._json({"error": f"scan failed: {e}", **self.snapshot()}, 503)
            self.state["scan"] = published
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
            try:
                out = apply_actions(self.state["scan"]["groups"], body.get("actions"))
            except ValueError as e:
                return self._json({"error": str(e)}, 400)
        elif route == "/api/undo":
            out = undo()
        else:
            return self._send(404, b"not found", "text/plain")
        # Handled findings stay in the list so the UI can show what happened to
        # each one. Rescan is what clears them.
        self._json({**out, **self.snapshot()})

    def snapshot(self) -> dict:
        # Read the scan once. Reading groups, failures and the timestamp as three
        # separate lookups is what lets a rescan land between them.
        scanned = self.state["scan"]
        groups = list(scanned["groups"].values())
        return {
            "findings": [g.public() for g in groups],
            "locations": sum(len(g.members) for g in groups),
            "apply": self.state["apply"],
            "roots": [display_path(r) for r in self.state["roots"]],
            "scanned_at": scanned["at"],
            "gitleaks": self.state["gitleaks"],
            "batches": [b.name for b in batches()],
            "failures": list(scanned["failures"]),
            "suppressed": scanned["suppressed"],
        }


def _scan_state(findings: list[Finding], failures: list[str] | None,
                suppressed: list[Finding] | None = None) -> dict:
    """Everything a rescan replaces, in one object. Assigning groups, failures and
    the timestamp separately lets a reader pair one scan's findings with another
    scan's failure list, and a run whose roots could not be read would then show
    findings next to an empty failure banner: a clean bill of health for a machine
    that was never fully scanned."""
    return {
        "groups": {g.key: g for g in group_findings(findings)},
        "failures": list(failures or []),
        "suppressed": suppression_summary(suppressed or []),
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def serve(findings: list[Finding], roots: list[str], apply_mode: bool,
          open_browser: bool = True, failures: list[str] | None = None,
          suppressed: list[Finding] | None = None) -> str:
    Handler.state = {
        "scan": _scan_state(findings, failures, suppressed),
        "roots": roots,
        "apply": apply_mode,
        "token": secrets.token_urlsafe(32),
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


def suppression_summary(suppressed: list[Finding]) -> list[dict]:
    """What was filtered, by rule. The UI renders this and can reveal it; the point
    is that a scan which filtered everything never again looks like a clean one."""
    by_rule: dict[str, list[Finding]] = {}
    for f in suppressed:
        by_rule.setdefault(f.suppressed_by, []).append(f)
    return sorted(
        ({"rule": k, "reason": v[0].suppressed_why, "count": len(v),
          "paths": sorted({display_path(m.path) for m in v})[:50]} for k, v in by_rule.items()),
        key=lambda r: -r["count"])


def run_live_verification(findings: list[Finding]) -> list[Finding]:
    """Opt-in, and loud about it. verify.py is imported here and nowhere else, so
    the scanner and server have no network capability to misuse."""
    import verify  # noqa: PLC0415 - deliberately not a module-level import

    rules = sorted({f.rule for f in findings if verify.verifiable(f.rule)})
    if not rules:
        print("  nothing here has a verifier; leaving them as offline checks only")
        return findings
    print(f"  asking {', '.join(verify.destinations(rules))} whether these still work.")
    print("  this is a real request with your credential and lands in their audit log.")
    canaries = verify.load_registry(STATE / "canaries.txt")
    done: dict[str, tuple[str, str]] = {}
    for f in findings:
        if not verify.verifiable(f.rule):
            continue
        if verify.is_canary(f.secret, f.path, canaries):
            f.live = ("skipped", "looks like a honeytoken; verifying one is the alarm")
            continue
        if f.digest not in done:  # one request per distinct value, never per copy
            done[f.digest] = verify.verify(f.rule, f.secret)
        f.live = done[f.digest]
    return findings


def print_table(findings: list[Finding], failures: list[str] | None = None,
                suppressed: list[Finding] | None = None) -> None:
    groups = group_findings(findings)
    if not groups:
        print("No secrets found.")
        _print_suppressed(suppressed)
        return
    print(f"{'VALUE':<18}  {'RULE':<24}  {'COPIES':>6}  {'FLAGS':<10}  FIRST SEEN")
    for g in groups:
        print(f"{mask(g.lead.secret):<18}  {g.lead.rule[:24]:<24}  {len(g.members):>6}  "
              f"{'committed' if g.tracked else '':<10}  {display_path(g.lead.path)[-60:]}:{g.lead.start_line}")

    for f in failures or []:
        print(f"  WARNING unscanned: {f[:200]}")
    tracked = sum(g.tracked for g in groups)
    print(f"\n{len(groups)} distinct secret(s) across {len(findings)} location(s). "
          f"{tracked} appear in a committed file: rotate those, removing the file does not unleak them.")
    _print_suppressed(suppressed)


def _print_suppressed(suppressed: list[Finding] | None) -> None:
    for row in suppression_summary(suppressed or []):
        print(f"  suppressed {row['count']:>4}  {row['rule']:<16} {row['reason']}")
    if suppressed:
        print("  re-run with --no-filter to see them.")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="secret-vacuum", description=__doc__.splitlines()[0])
    ap.add_argument("command", nargs="?", default="ui",
                    choices=("ui", "scan", "undo", "env"))
    ap.add_argument("--root", action="append", default=[], metavar="PATH",
                    help="scan this path instead of the defaults (repeatable)")
    ap.add_argument("--apply", action="store_true", help="allow changes; without it the UI is read only")
    ap.add_argument("--json", action="store_true", help="with scan: emit findings as JSON (masked, never values)")
    ap.add_argument("--no-browser", action="store_true", help="do not open a browser")
    ap.add_argument("--quick", action="store_true",
                    help="scan the known credential stores only, not the whole home directory")
    ap.add_argument("--verify", choices=("never", "offline", "live"), default="offline",
                    help="offline (default) checks shape and expiry with no network; "
                         "live also asks each provider, which writes to their audit log")
    ap.add_argument("--docker", action="store_true",
                    help="with env: also list credential-shaped variables in running containers")
    ap.add_argument("--keychain", action="store_true",
                    help="with env: also inventory the OS keystore (names only, never values)")
    ap.add_argument("--no-filter", action="store_true",
                    help="report every finding, including the ones the suppressors would drop")
    a = ap.parse_args(argv)

    if a.command == "env":
        print_report(env_report(roots=a.root or None),
                     docker_report() if a.docker else [],
                     keystore_report() if a.keychain else [])
        return 0

    if a.command == "undo":
        r = undo()
        print(r["detail"])
        return 0 if r["ok"] else 1

    if a.no_filter:
        SUPPRESSORS.clear()
    roots = a.root or (quick_roots() if a.quick else default_roots())
    failures: list[str] = []
    dropped: list[Finding] = []
    try:
        if not (a.command == "scan" and a.json):
            scope = "quick" if a.quick else ("custom" if a.root else "home")
            print(f"secret-vacuum  |  gitleaks {gitleaks_version()}  |  "
                  f"{scope} scope, {len(roots)} root(s)...")
        findings = scan(roots, progress=not (a.command == "scan" and a.json),
                        failures=failures, suppressed=dropped)
    except (RuntimeError, OSError) as e:
        # Every root failed, or the scanner is not installed at all. Say why,
        # rather than printing a traceback.
        return print(f"scan failed: {e}", file=sys.stderr) or 2

    if a.verify == "live":
        findings = run_live_verification(findings)

    if a.command == "scan":
        if a.json:
            print(json.dumps({"findings": [g.public() for g in group_findings(findings)],
                              "suppressed": suppression_summary(dropped)}, indent=1))
        else:
            print_table(findings, failures, dropped)
        return 0

    serve(findings, roots, a.apply, open_browser=not a.no_browser, failures=failures,
          suppressed=dropped)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
