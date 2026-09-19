#!/usr/bin/env python3
"""Tests for secret-vacuum. Plain asserts, no framework -- `python3 test_secret_vacuum.py`
or `pytest` both work.

Test secrets are assembled at runtime from split literals so this file does not itself
trip a secret scanner. Nothing here is a real credential.
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import time
import threading
import urllib.error
import urllib.request
from pathlib import Path

import secret_vacuum as sv

# Fabricated, and split so the source text does not read as a live credential.
# The gitleaks:allow markers keep this repo's own scanner honest about them.
FAKE_AWS_ID = "AKIA" + "3QZ7XK2LMNP4WRTV"  # gitleaks:allow
FAKE_AWS_SECRET = "hT8vQm2NxL9pRzK4" + "wYcE7bJfA1sD6gU3nV0iZoXq"  # gitleaks:allow
FAKE_STRIPE = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"  # gitleaks:allow


def finding(path: str, secret: str, line: int = 1, end: int | None = None) -> sv.Finding:
    return sv.Finding(
        fingerprint=f"{path}:test-rule:{line}",
        path=path,
        rule="test-rule",
        description="a test rule",
        start_line=line,
        end_line=end or line,
        entropy=4.2,
        secret=secret,
    )


def act(action: str, *findings: sv.Finding) -> dict:
    """Apply one action to the group each finding belongs to."""
    groups = {g.key: g for g in sv.group_findings(list(findings))}
    return sv.apply_actions(groups, [{"key": k, "action": action} for k in groups])


def sandbox(tmp_path: Path) -> None:
    """Point all tool state at a temp dir so tests never touch the real ~/.secret-vacuum."""
    sv.STATE = tmp_path / "state"
    sv.TRASH = sv.STATE / "trash"
    sv.IGNORE_FILE = sv.STATE / ".gitleaksignore"


# --------------------------------------------------------------- guarantee 1: no value on disk


def test_mask_never_reveals_more_than_eight_characters():
    assert sv.mask(FAKE_AWS_SECRET) == FAKE_AWS_SECRET[:4] + sv.DOT * 6 + FAKE_AWS_SECRET[-4:]
    assert FAKE_AWS_SECRET[4:-4] not in sv.mask(FAKE_AWS_SECRET)
    # Short values give up nothing at all: 8 of 10 characters would be most of it.
    assert sv.mask("short1234") == sv.DOT * 9
    assert sv.mask("") == ""
    assert len(sv.mask("x" * 500)) == 14


def test_public_payload_carries_no_secret_value():
    f = finding("/tmp/x/.env", FAKE_AWS_SECRET)
    blob = json.dumps(f.public())
    assert FAKE_AWS_SECRET not in blob
    assert FAKE_AWS_SECRET[4:-4] not in blob
    assert f.public()["sha8"] == f.sha8 and len(f.sha8) == 8
    # repr is used by tracebacks and debuggers, so it must be quiet too.
    assert FAKE_AWS_SECRET not in repr(f)


def test_ignore_store_holds_fingerprints_only(tmp_path: Path):
    sandbox(tmp_path)
    f = finding("/tmp/x/.env", FAKE_STRIPE)
    sv.add_ignore(f)
    sv.add_ignore(f)  # idempotent
    body = sv.IGNORE_FILE.read_text()
    assert body.split() == [f.fingerprint, f"sv:{f.sha8}"], body
    assert FAKE_STRIPE not in body, "the store never holds a value"
    assert f.secret[:8] not in body, "not even a prefix of one"


def test_manifest_records_paths_not_values(tmp_path: Path):
    sandbox(tmp_path)
    target = tmp_path / "creds.env"
    target.write_text(f"token={FAKE_STRIPE}\n")
    f = finding(str(target), FAKE_STRIPE)
    act("remove", f)
    manifest = next(sv.TRASH.rglob("manifest.json")).read_text()
    assert FAKE_STRIPE not in manifest
    assert str(target) in manifest


# --------------------------------------------------------------- guarantee 2: move, never unlink


def test_remove_moves_to_trash_and_undo_restores_byte_identical(tmp_path: Path):
    sandbox(tmp_path)
    target = tmp_path / "repo" / ".env"
    target.parent.mkdir()
    original = f"AWS_ACCESS_KEY_ID={FAKE_AWS_ID}\nOTHER=keep-me\n"
    target.write_text(original)

    f = finding(str(target), FAKE_AWS_ID)
    out = act("remove", f)

    assert out["results"][0]["ok"] and not target.exists()
    stashed = sv.TRASH / out["batch"] / "files" / str(target).lstrip("/")
    assert stashed.read_text() == original, "the file must survive intact in the trash"

    assert sv.undo()["ok"]
    assert target.read_text() == original
    # Undo moves rather than copies, so no plaintext copy is left in the trash.
    assert not list(sv.TRASH.rglob("*.env")), "a restored secret must not stay in the trash"
    # And a restored batch is not replayed by the next undo.
    assert sv.undo()["detail"] == "nothing in the trash"


def test_history_files_are_redact_only(tmp_path: Path):
    sandbox(tmp_path)
    hist = tmp_path / ".zsh_history"
    hist.write_text(f"curl -H 'Authorization: Bearer {FAKE_STRIPE}'\n")
    f = finding(str(hist), FAKE_STRIPE)
    assert not f.removable
    out = act("remove", f)
    assert not out["results"][0]["ok"]
    assert hist.exists(), "a shell history file must never be removed wholesale"


def test_remove_wins_over_redact_on_the_same_file(tmp_path: Path):
    sandbox(tmp_path)
    target = tmp_path / "two.env"
    target.write_text(f"a={FAKE_AWS_ID}\nb={FAKE_STRIPE}\n")
    a, b = finding(str(target), FAKE_AWS_ID, 1), finding(str(target), FAKE_STRIPE, 2)
    groups = {g.key: g for g in sv.group_findings([a, b])}
    out = sv.apply_actions(groups, [
        {"key": a.digest, "action": "remove"},
        {"key": b.digest, "action": "redact"},
    ])
    assert not target.exists()
    # The redaction never ran, but its value went with the file, so both selected
    # groups must report an outcome. A row that silently shows nothing reads as
    # "the tool ignored me" when the secret is in fact gone.
    assert {r["key"] for r in out["results"]} == set(groups)
    assert all(r["ok"] for r in out["results"]), out["results"]

    assert sv.undo()["ok"] and target.exists()


def test_one_value_in_many_places_is_one_row_and_one_action(tmp_path: Path):
    """The multiplier that makes a real machine unreadable: the same credential
    copied across worktrees. It is one secret, and removing it clears every copy."""
    sandbox(tmp_path)
    copies = []
    for tree in ("repo-main", "repo-featureA", "repo-featureB"):
        f = tmp_path / tree / ".env"
        f.parent.mkdir(parents=True)
        f.write_text(f"KEY={FAKE_STRIPE}\n")
        copies.append(f)
    other = tmp_path / "unrelated" / ".env"
    other.parent.mkdir()
    other.write_text(f"KEY={FAKE_AWS_ID}\n")

    found = sv.scan([str(tmp_path)])
    groups = sv.group_findings(found)
    assert len(found) == 4 and len(groups) == 2, "four locations, two distinct values"

    shared = next(g for g in groups if g.lead.secret == FAKE_STRIPE)
    assert shared.public()["copies"] == 3
    assert FAKE_STRIPE not in json.dumps(shared.public())

    out = sv.apply_actions({shared.key: shared}, [{"key": shared.key, "action": "remove"}])
    assert out["results"][0]["ok"] and out["results"][0]["detail"] == "handled 3 copies"
    assert not any(c.exists() for c in copies), "every copy of the value is gone"
    assert other.exists(), "an unrelated secret is untouched"

    assert sv.undo()["ok"]
    assert all(c.exists() for c in copies)


def test_a_group_is_committed_if_any_copy_is(tmp_path: Path):
    a = finding("/x/loose/.env", FAKE_STRIPE)
    b = finding("/x/repo/.env", FAKE_STRIPE)
    b.tracked = True
    g = sv.group_findings([a, b])[0]
    assert g.tracked and g.public()["tracked_copies"] == 1


def test_two_secrets_in_one_file_both_report_success(tmp_path: Path):
    """The first remove takes the file; the second must not read as a failure."""
    sandbox(tmp_path)
    target = tmp_path / "svc" / ".env"
    target.parent.mkdir()
    target.write_text(f"AWS_ACCESS_KEY_ID={FAKE_AWS_ID}\nSTRIPE={FAKE_STRIPE}\n")

    groups = {g.key: g for g in sv.group_findings(sv.scan([str(tmp_path)]))}
    assert len(groups) == 2, "two distinct values in one file"

    out = sv.apply_actions(groups, [{"key": k, "action": "remove"} for k in groups])
    assert all(r["ok"] for r in out["results"]), out["results"]
    assert not target.exists()
    assert sv.undo()["ok"] and target.exists()


def test_a_group_containing_a_history_file_cannot_be_removed_wholesale(tmp_path: Path):
    """One value in both a .env and ~/.zsh_history: the group must not offer to
    delete the history file just because the .env would be safe to delete."""
    mixed = sv.group_findings([finding("/h/proj/.env", FAKE_STRIPE),
                               finding("/h/.zsh_history", FAKE_STRIPE)])[0]
    assert mixed.removable is False and mixed.suggested == "redact"

    pure = sv.group_findings([finding("/h/a/.env", FAKE_STRIPE),
                              finding("/h/b/.env", FAKE_STRIPE)])[0]
    assert pure.removable is True and pure.suggested == "remove"

    config = sv.group_findings([finding("/h/.cursor/settings.json", FAKE_STRIPE)])[0]
    assert config.removable is True and config.suggested == "redact"


def test_every_selected_group_gets_an_outcome(tmp_path: Path):
    """Whatever combination is applied, no row may come back with nothing. A blank
    result reads as "the tool ignored me" even when the secret is gone."""
    sandbox(tmp_path)
    keep = tmp_path / "rc"
    keep.write_text(f"export K={FAKE_STRIPE}\n")
    creds = tmp_path / "svc" / ".env"
    creds.parent.mkdir()
    creds.write_text(f"A={FAKE_AWS_ID}\nB={FAKE_AWS_SECRET}\n")
    hist = tmp_path / ".zsh_history"
    hist.write_text(f"curl -H 'x: {FAKE_AWS_SECRET}'\n")

    findings = [
        finding(str(keep), FAKE_STRIPE, 1),
        finding(str(creds), FAKE_AWS_ID, 1),
        finding(str(creds), FAKE_AWS_SECRET, 2),
        finding(str(hist), FAKE_AWS_SECRET, 1),
    ]
    for i, f in enumerate(findings):
        f.fingerprint += f":{i}"
    groups = {g.key: g for g in sv.group_findings(findings)}

    for actions in (["remove"] * len(groups), ["redact"] * len(groups),
                    ["remove", "redact", "ignore"][: len(groups)]):
        sandbox(tmp_path / f"state-{'-'.join(actions)}")
        keep.write_text(f"export K={FAKE_STRIPE}\n")
        creds.write_text(f"A={FAKE_AWS_ID}\nB={FAKE_AWS_SECRET}\n")
        hist.write_text(f"curl -H 'x: {FAKE_AWS_SECRET}'\n")
        req = [{"key": k, "action": a} for k, a in zip(groups, actions)]
        out = sv.apply_actions(groups, req)
        assert {r["key"] for r in out["results"]} == {r["key"] for r in req}, (
            f"missing outcomes for {actions}: {out['results']}"
        )


# --------------------------------------------------------------- redaction is surgical


def test_redaction_replaces_only_the_secret(tmp_path: Path):
    sandbox(tmp_path)
    target = tmp_path / ".zshrc"
    before = f"# comment\nexport TOKEN={FAKE_STRIPE}  # trailing\nexport PATH=$PATH:/usr/local/bin\n"
    target.write_text(before)

    f = finding(str(target), FAKE_STRIPE, line=2)
    act("redact", f)

    after = target.read_text().splitlines(keepends=True)
    assert FAKE_STRIPE not in target.read_text()
    assert after[1] == f"export TOKEN={sv.PLACEHOLDER}  # trailing\n"
    assert [after[0], after[2]] == before.splitlines(keepends=True)[::2], "other lines untouched"


def test_redaction_refuses_when_the_value_moved(tmp_path: Path):
    sandbox(tmp_path)
    target = tmp_path / "moved.env"
    target.write_text("nothing to see here\n")
    f = finding(str(target), FAKE_STRIPE, line=1)
    out = act("redact", f)
    assert not out["results"][0]["ok"]
    assert target.read_text() == "nothing to see here\n", "refuse rather than corrupt"


def test_multiline_block_is_replaced_whole(tmp_path: Path):
    sandbox(tmp_path)
    pem = tmp_path / "id_rsa"
    body = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\nBBBB\n-----END RSA PRIVATE KEY-----\n"
    pem.write_text("keep\n" + body)
    f = finding(str(pem), body, line=2, end=5)
    act("redact", f)
    assert pem.read_text() == f"keep\n{sv.PLACEHOLDER}\n"


def test_a_clean_scan_returns_nothing_whatever_gitleaks_prints(tmp_path: Path):
    """Success is the exit code, not the shape of stdout. gitleaks 8.30.1 prints "[]"
    on a clean scan, but keying off that would break on any version that prints
    nothing, so an empty stdout with a zero exit is simply no findings."""
    sandbox(tmp_path)
    (tmp_path / "boring.txt").write_text("nothing secret here\n")
    assert sv.scan([str(tmp_path)]) == []

    real_run = subprocess.run

    def silent_success(cmd, **kw):  # gitleaks that completes but prints nothing
        if "gitleaks" in cmd[0] and "dir" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return real_run(cmd, **kw)

    sv.subprocess.run = silent_success
    try:
        assert sv.scan_root(tmp_path) == [], "empty stdout with exit 0 is a clean scan"
    finally:
        sv.subprocess.run = real_run

    def noisy_failure(cmd, **kw):  # gitleaks that dies
        if "gitleaks" in cmd[0] and "dir" in cmd:
            return subprocess.CompletedProcess(cmd, 1, "", "FTL something broke")
        return real_run(cmd, **kw)

    sv.subprocess.run = noisy_failure
    try:
        raised = False
        try:
            sv.scan_root(tmp_path)
        except RuntimeError as e:
            raised = "something broke" in str(e)
        assert raised, "a non-zero exit must raise even though stdout was empty too"
    finally:
        sv.subprocess.run = real_run


def test_a_scanner_failure_is_loud_not_an_empty_result(tmp_path: Path):
    """A broken config or a missing binary must never read as "you are clean"."""
    sandbox(tmp_path)
    broken = tmp_path / "broken.toml"
    broken.write_text("this is not valid toml [[[\n")
    original, sv.CONFIG_FILE = sv.CONFIG_FILE, broken
    try:
        raised = False
        try:
            sv.scan([str(tmp_path)])
        except RuntimeError as e:
            raised = "gitleaks failed" in str(e)
        assert raised, "when every root fails, scan must raise rather than return []"
    finally:
        sv.CONFIG_FILE = original


def test_suggested_action_never_defaults_to_removing_a_file_you_need():
    cred = finding("/home/u/project/.env", FAKE_STRIPE)
    key = finding("/home/u/.ssh/id_ed25519", FAKE_STRIPE)
    pem = finding("/home/u/certs/server.pem", FAKE_STRIPE)
    rc = finding("/home/u/.zshrc", FAKE_STRIPE)
    settings = finding("/home/u/.cursor/settings.json", FAKE_STRIPE)
    hist = finding("/home/u/.zsh_history", FAKE_STRIPE)
    assert [f.suggested for f in (cred, key, pem)] == ["remove"] * 3
    assert [f.suggested for f in (rc, settings, hist)] == ["redact"] * 3


# Every allowlisted tree in gitleaks.toml. A typo in one of those regexes fails
# silently, so each pattern gets a planted secret here.
GENERATED_TREES = [
    "node_modules/p/c.env", "bower_components/p/c.env", "vendor/p/c.env", "Pods/p/c.env",
    "dbt_packages/p/c.env", ".venv/l/c.env", "venv/l/c.env", "x/site-packages/p/c.env",
    "__pycache__/c.env", ".mypy_cache/c.env", ".pytest_cache/c.env", ".tox/c.env",
    "dist/c.env", "build/c.env", "out/c.env", "target/c.env", ".next/c.env",
    ".gradle/c.env", ".terraform/c.env", "coverage/c.env", "htmlcov/c.env",
    "package-lock.json", "app.min.js",
]


def test_generated_trees_are_not_reported(tmp_path: Path):
    """A dependency cache full of other people's fixtures is not your leak."""
    sandbox(tmp_path)
    for rel in [*GENERATED_TREES, "real/service.env"]:
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(f"aws_access_key_id = {FAKE_AWS_ID}\n")
    paths = [Path(f.path).name for f in sv.scan([str(tmp_path)])]
    assert paths == ["service.env"], f"only the authored file should surface, got {paths}"


def test_overlapping_multiline_redactions_do_not_eat_the_file(tmp_path: Path):
    """Collapsing a block shortens the file, so a second overlapping block's line
    numbers stop meaning what gitleaks said. Before this was guarded, redacting
    two overlapping PEM-shaped findings destroyed everything between them."""
    sandbox(tmp_path)
    body = [f"line{i}\n" for i in range(1, 16)]
    target = tmp_path / "overlap.txt"
    target.write_text("".join(body))

    def block(start: int, end: int) -> sv.Finding:
        return sv.Finding(f"{target}:private-key:{start}", str(target), "private-key",
                          "d", start, end, 4.0, "".join(body[start - 1:end]))

    a, b = block(5, 10), block(8, 15)
    out = list(body)
    applied = []
    for f in sorted([a, b], key=lambda f: -f.start_line):
        out, ok = sv.redact_lines(out, f)
        applied.append(ok)

    assert applied == [True, False], "the second, now-stale block must be refused"
    # Lines 1-4 are outside every finding and must be untouched.
    assert out[:4] == body[:4]
    # Nothing is invented and nothing outside the applied block is lost.
    assert out == body[:7] + [f"{sv.PLACEHOLDER}\n"]
    assert sum(l == f"{sv.PLACEHOLDER}\n" for l in out) == 1


def test_two_single_line_secrets_on_one_line_both_get_redacted(tmp_path: Path):
    """Single-line redaction does not shift indices, so overlapping on the same
    line must still work -- the multi-line guard must not over-refuse."""
    sandbox(tmp_path)
    target = tmp_path / "pair.env"
    target.write_text(f"A={FAKE_AWS_ID} B={FAKE_STRIPE}\n")
    one = finding(str(target), FAKE_AWS_ID, line=1)
    two = finding(str(target), FAKE_STRIPE, line=1)
    two.fingerprint += ":2"

    groups = {g.key: g for g in sv.group_findings([one, two])}
    out = sv.apply_actions(groups, [{"key": k, "action": "redact"} for k in groups])
    assert all(r["ok"] for r in out["results"]), out["results"]
    text = target.read_text()
    assert FAKE_AWS_ID not in text and FAKE_STRIPE not in text
    assert text.count(sv.PLACEHOLDER) == 2


def test_a_failed_redaction_leaves_no_backup_and_does_not_touch_the_file(tmp_path: Path):
    """An orphaned stash is an extra plaintext copy of a secret we did not remove."""
    sandbox(tmp_path)
    target = tmp_path / "unchanged.env"
    target.write_text("nothing to redact here\n")
    before = target.stat().st_mtime_ns

    stale = finding(str(target), FAKE_STRIPE, line=1)  # value is not in the file
    out = act("redact", stale)

    assert not out["results"][0]["ok"]
    assert target.read_text() == "nothing to redact here\n"
    assert target.stat().st_mtime_ns == before, "an untouched file must keep its mtime"
    assert out["batch"] is None, "no batch should be recorded"
    assert not list(sv.TRASH.rglob("unchanged.env")), "no orphaned copy in the trash"


def test_a_partial_redaction_still_backs_the_file_up(tmp_path: Path):
    """One of two succeeding must still produce a recoverable original."""
    sandbox(tmp_path)
    target = tmp_path / "partial.env"
    original = f"A={FAKE_AWS_ID}\nB=plain\n"
    target.write_text(original)

    good = finding(str(target), FAKE_AWS_ID, line=1)
    stale = finding(str(target), FAKE_STRIPE, line=2)
    stale.fingerprint += ":2"
    groups = {g.key: g for g in sv.group_findings([good, stale])}
    out = sv.apply_actions(groups, [{"key": k, "action": "redact"} for k in groups])

    assert sorted(r["ok"] for r in out["results"]) == [False, True]
    assert FAKE_AWS_ID not in target.read_text()
    stashed = list(sv.TRASH.rglob("partial.env"))
    assert len(stashed) == 1 and stashed[0].read_text() == original
    assert sv.undo()["ok"] and target.read_text() == original


def test_two_applies_never_share_a_trash_batch(tmp_path: Path):
    """Second-granularity batch names collided, so two applies in the same second
    landed in one directory and a single undo put both of them back."""
    sandbox(tmp_path)
    first, second = tmp_path / "one.env", tmp_path / "two.env"
    first.write_text(f"K={FAKE_AWS_ID}\n")
    second.write_text(f"K={FAKE_STRIPE}\n")

    a = act("remove", finding(str(first), FAKE_AWS_ID))
    b = act("remove", finding(str(second), FAKE_STRIPE))
    assert a["batch"] != b["batch"], "each apply needs its own batch"
    assert sv.batches() == sorted(sv.batches()), "batch names must still sort chronologically"

    assert sv.undo()["ok"]
    assert second.exists() and not first.exists(), "undo restores only the newest batch"
    assert sv.undo()["ok"]
    assert first.exists()


def test_the_mutation_lock_is_released_even_when_apply_raises(tmp_path: Path):
    """A leaked lock deadlocks every later action, which is worse than the crash."""
    raised = False
    try:
        sv.apply_actions(None, [{"key": "x", "action": "remove"}])
    except Exception:  # noqa: BLE001
        raised = True
    assert raised
    assert not sv.MUTATE.locked(), "the lock must not survive an exception"


def test_undo_is_safe_when_the_trash_empties_underneath_it(tmp_path: Path):
    """undo listed the trash twice, so a concurrent undo between the two calls
    turned it into an IndexError instead of a clean "nothing in the trash"."""
    sandbox(tmp_path)
    assert sv.undo() == {"ok": False, "detail": "nothing in the trash"}

    target = tmp_path / "solo.env"
    target.write_text(f"K={FAKE_STRIPE}\n")
    act("remove", finding(str(target), FAKE_STRIPE))

    done, errors = [], []

    def race():
        try:
            done.append(sv.undo())
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=race) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"concurrent undo raised: {errors}"
    assert sum(r["ok"] for r in done) == 1, "exactly one undo does the work"
    assert target.exists()


def test_vendored_content_and_placeholders_are_not_reported(tmp_path: Path):
    """A real dotfile scan was 28% signal: editor extensions, downloaded plugin
    docs and YOUR_TOKEN placeholders drowned the handful of real credentials."""
    sandbox(tmp_path)

    def put(rel: str, secret: str) -> Path:
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(f"aws_access_key_id = {secret}\n")
        return f

    # somebody else's vendored code and downloaded docs
    for rel in (".cursor/extensions/vendor.x/extension.js",
                ".vscode/extensions/vendor.y/lib.py",
                ".dbt/wizard/.tmp/plugins/zoom/skills/guide.md",
                "ext/bundled_skills/thing/SKILL.md",
                "chats/abc/store.db-wal"):
        put(rel, FAKE_AWS_ID)

    # documentation placeholders
    for i, ph in enumerate(("YOUR_ACCESS_TOKEN", "<your-token-here>", "CHANGEME",
                            "REPLACE_ME", "${MY_TOKEN}", "1234567890abcdef",
                            "xxxxxxxxxxxx")):
        (tmp_path / f"doc{i}.md").write_text(
            f'curl -H "Authorization: Bearer {ph}" https://api.example.com\n')

    mine = put("work/service/.env", FAKE_AWS_ID)

    found = sv.scan([str(tmp_path)])
    assert [Path(f.path) for f in found] == [mine], (
        f"only the authored credential should surface, got {[f.path for f in found]}"
    )


def test_every_location_is_reported_not_a_sample(tmp_path: Path):
    """paths was capped at 40 entries. The UI said "and N more", but --json is a
    machine surface and silently dropped the rest, so a caller piping it into
    automation would miss locations that are really there."""
    sandbox(tmp_path)
    for i in range(45):
        f = tmp_path / f"copy{i:03d}" / ".env"
        f.parent.mkdir()
        f.write_text(f"K={FAKE_STRIPE}\n")

    group = sv.group_findings(sv.scan([str(tmp_path)]))[0]
    pub = group.public()
    assert pub["copies"] == 45
    assert len(pub["paths"]) == 45, f"all locations must be listed, got {len(pub['paths'])}"
    assert FAKE_STRIPE not in json.dumps(pub)


def test_all_shell_startup_files_are_scanned(tmp_path: Path):
    """An exported token lives in whichever startup file set it. Only ~/.zshrc was
    covered, so a token exported from ~/.zprofile was invisible."""
    roots = set(sv.QUICK_ROOTS)
    for rc in (".zshrc", ".zshenv", ".zprofile", ".zlogin", ".bashrc",
               ".bash_profile", ".bash_login", ".profile",
               ".config/fish/config.fish",
               "Documents/PowerShell", "Documents/WindowsPowerShell"):
        assert rc in roots, f"{rc} is a place an export can hide"
    for hist in (".zsh_history", ".bash_history", "ConsoleHost_history.txt"):
        assert not sv.Finding("f", str(Path.home() / hist), "r", "d", 1, 1, 0.0,
                              FAKE_STRIPE).removable, "history stays redact-only"
    # and the default scope is the whole home directory, not an allow-list
    assert sv.default_roots() == [str(Path.home())]


# --------------------------------------------------------------- guarantee 3: server is locked down


def send(req: urllib.request.Request) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def request(url: str, headers: dict | None = None, method: str = "GET") -> tuple[int, str]:
    return send(urllib.request.Request(url, headers=headers or {}, method=method))


def test_server_rejects_everything_without_the_right_token_host_and_origin(tmp_path: Path):
    sandbox(tmp_path)
    f = finding("/tmp/x/.env", FAKE_STRIPE)
    url = sv.serve([f], ["/tmp/x"], apply_mode=False, open_browser=False)
    base, token = url.split("/?t=")
    port = base.rsplit(":", 1)[1]

    assert request(base + "/api/findings")[0] == 403, "no token"
    assert request(base + "/api/findings?t=wrong")[0] == 403, "wrong token"
    assert request(base + f"/api/findings?t={token}", {"Host": "evil.test"})[0] == 403, "rebinding host"
    assert request(base + f"/api/findings?t={token}", {"Origin": "https://evil.test"})[0] == 403, "foreign origin"

    code, body = request(base + f"/api/findings?t={token}")
    assert code == 200
    assert FAKE_STRIPE not in body, "the API must never serve a secret value"
    assert json.loads(body)["findings"][0]["masked"] == sv.mask(FAKE_STRIPE)

    code, body = request(base + "/api/findings", {"X-SV-Token": token, "Host": f"127.0.0.1:{port}"})
    assert code == 200, "the header form of the token works too"

    # Preview mode refuses writes.
    code, body = request(base + f"/api/apply?t={token}", method="POST")
    assert code == 403 and "preview mode" in body


def test_server_never_emits_a_cors_header(tmp_path: Path):
    sandbox(tmp_path)
    url = sv.serve([], [], apply_mode=False, open_browser=False)
    base, token = url.split("/?t=")
    req = urllib.request.Request(base + f"/api/findings?t={token}")
    with urllib.request.urlopen(req, timeout=5) as r:
        assert not any(h.lower().startswith("access-control") for h in r.headers)
        assert r.headers["Cache-Control"] == "no-store"


def test_malformed_and_oversized_requests_are_refused_not_crashed(tmp_path: Path):
    sandbox(tmp_path)
    url = sv.serve([], [], apply_mode=True, open_browser=False)
    base, token = url.split("/?t=")

    req = urllib.request.Request(base + f"/api/apply?t={token}", data=b"not json", method="POST")
    assert send(req)[0] == 400

    req = urllib.request.Request(base + f"/api/apply?t={token}", data=b'"a string"', method="POST")
    assert send(req)[0] == 400

    req = urllib.request.Request(base + f"/api/apply?t={token}", method="POST",
                                 data=b"{}", headers={"Content-Length": "2000000"})
    assert send(req)[0] == 413


def test_scan_json_output_is_grouped_and_carries_no_values(tmp_path: Path):
    """--json is the scriptable surface, so it must agree with the table and stay clean."""
    sandbox(tmp_path)
    for tree in ("a", "b"):
        f = tmp_path / tree / ".env"
        f.parent.mkdir()
        f.write_text(f"K={FAKE_STRIPE}\n")

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        sv.main(["scan", "--json", "--root", str(tmp_path)])
    payload = out.getvalue()

    doc = json.loads(payload)
    groups = doc["findings"]
    assert len(groups) == 1 and groups[0]["copies"] == 2
    assert FAKE_STRIPE not in payload
    assert "key" in groups[0] and "paths" in groups[0]
    assert "suppressed" in doc, "the machine surface must report what was filtered too"


def test_a_non_ascii_token_is_refused_not_a_crash(tmp_path: Path):
    """hmac.compare_digest raises TypeError on a non-ASCII str, so comparing the
    decoded query token as a string turned a bad token into a 500."""
    sandbox(tmp_path)
    url = sv.serve([], [], apply_mode=False, open_browser=False)
    base, token = url.split("/?t=")

    for bad in ("%C3%A9caf%C3%A9", "caf%C3%A9", "%F0%9F%92%A9"):
        code, _ = request(f"{base}/api/findings?t={bad}")
        assert code == 403, f"non-ascii token {bad} should be refused, got {code}"

    code, _ = request(base + f"/api/findings?t={token}")
    assert code == 200, "the real token still works"


def test_grouping_keys_on_the_whole_digest(tmp_path: Path):
    """A 32-bit prefix collides about once in a million at this scale, and the
    consequence is removing a different secret's files."""
    f = finding("/x/.env", FAKE_STRIPE)
    assert len(f.digest) == 64 and f.sha8 == f.digest[:8]
    group = sv.group_findings([f])[0]
    assert group.key == f.digest, "the group key must be the full digest"
    assert group.public()["sha8"] == f.sha8, "the short form is still shown"
    assert FAKE_STRIPE not in json.dumps(group.public())


def test_an_empty_batch_is_not_treated_as_restorable(tmp_path: Path):
    """A stale empty directory made undo report restoring nothing as success."""
    sandbox(tmp_path)
    stale = sv.TRASH / "20260101T000000.000000Z" / "files"
    stale.mkdir(parents=True)
    assert sv.batches() == [], "an empty batch is not a batch"
    assert sv.undo() == {"ok": False, "detail": "nothing in the trash"}

    target = tmp_path / "real.env"
    target.write_text(f"K={FAKE_STRIPE}\n")
    act("remove", finding(str(target), FAKE_STRIPE))
    assert len(sv.batches()) == 1, "the stale empty one is still ignored"
    assert sv.undo()["ok"] and target.exists()


def test_an_oserror_from_the_scanner_is_a_failure_not_a_crash(tmp_path: Path):
    """The binary is resolved once, so it can vanish or lose its execute bit before
    it runs. subprocess.run then raises OSError, which is not a RuntimeError."""
    sandbox(tmp_path)
    (tmp_path / "s.env").write_text(f"k = {FAKE_AWS_ID}\n")

    real_run = subprocess.run

    def gone(cmd, **kw):
        if "gitleaks" in cmd[0] and "dir" in cmd:
            raise OSError(8, "Exec format error")
        return real_run(cmd, **kw)

    sv.subprocess.run = gone
    try:
        raised = False
        try:
            sv.scan([str(tmp_path)])
        except RuntimeError as e:
            raised = "could not run gitleaks" in str(e)
        assert raised, "an OSError must surface as a scan failure, not escape the scan"
    finally:
        sv.subprocess.run = real_run


def test_one_bad_root_does_not_discard_the_others(tmp_path: Path):
    """A permission error on one root must not throw away what every other root
    found, and must not pass unnoticed either."""
    sandbox(tmp_path)
    good = tmp_path / "good"
    good.mkdir()
    (good / "svc.env").write_text(f"aws_access_key_id = {FAKE_AWS_ID}\n")
    bad = tmp_path / "bad"
    bad.mkdir()

    real_root = sv.scan_root

    def flaky(root: Path):
        if root.name == "bad":
            raise RuntimeError(f"gitleaks failed on {root}: boom")
        return real_root(root)

    sv.scan_root = flaky
    try:
        failures: list[str] = []
        found = sv.scan([str(good), str(bad)], failures=failures)
        assert len(found) == 1, "the healthy root's findings survive"
        assert failures and "bad" in failures[0], "the failure is reported to the caller"
    finally:
        sv.scan_root = real_root


def test_rescan_reasks_git_so_a_committed_badge_cannot_go_stale(tmp_path: Path):
    """git_tracked is cached for the life of the process. Without clearing it, a
    file committed between scans keeps reporting untracked."""
    sandbox(tmp_path)
    repo = tmp_path / "r"
    repo.mkdir()
    run = lambda *a: subprocess.run(a, cwd=repo, capture_output=True, check=True)
    run("git", "init", "-q")
    run("git", "config", "user.email", "t@t.test")
    run("git", "config", "user.name", "t")
    target = repo / "later.env"
    target.write_text(f"k = {FAKE_STRIPE}\n")

    sv.git_tracked.cache_clear()
    assert sv.scan([str(repo)])[0].tracked is False

    run("git", "add", "later.env")
    run("git", "commit", "-q", "-m", "committed now")

    assert sv.scan([str(repo)])[0].tracked is False, "the cache is why this is stale"
    sv.git_tracked.cache_clear()  # what /api/rescan now does
    assert sv.scan([str(repo)])[0].tracked is True


def test_rescan_answers_with_an_error_when_every_root_fails(tmp_path: Path):
    """scan raises when nothing could be read. The handler must turn that into a
    response, not drop the connection with no reply at all."""
    sandbox(tmp_path)
    url = sv.serve([], [str(tmp_path)], apply_mode=True, open_browser=False)
    base, token = url.split("/?t=")

    real_root = sv.scan_root
    sv.scan_root = lambda root: (_ for _ in ()).throw(RuntimeError("gitleaks failed: nope"))
    try:
        req = urllib.request.Request(base + f"/api/rescan?t={token}", data=b"{}", method="POST")
        code, body = send(req)
        assert code == 503, f"expected a 503, got {code}"
        assert "scan failed" in body and "nope" in body
    finally:
        sv.scan_root = real_root

    req = urllib.request.Request(base + f"/api/rescan?t={token}", data=b"{}", method="POST")
    assert send(req)[0] == 200, "a healthy rescan still works afterwards"


def test_the_cli_reports_a_total_scan_failure_instead_of_a_traceback(tmp_path: Path):
    sandbox(tmp_path)
    real_root = sv.scan_root
    sv.scan_root = lambda root: (_ for _ in ()).throw(RuntimeError("gitleaks failed: nope"))
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            code = sv.main(["scan", "--root", str(tmp_path)])
    finally:
        sv.scan_root = real_root
    assert code == 2 and "scan failed" in err.getvalue()


def test_roots_that_do_not_exist_are_an_error_not_a_clean_bill(tmp_path: Path):
    """A typo in --root returned [], which reads as "your machine is clean"."""
    sandbox(tmp_path)
    raised = False
    try:
        sv.scan([str(tmp_path / "nope"), str(tmp_path / "also-nope")])
    except RuntimeError as e:
        raised = "none of the requested roots exist" in str(e)
    assert raised

    # A root that is simply absent among others that are present is fine: the
    # defaults list many paths that only some machines have.
    real = tmp_path / "here"
    real.mkdir()
    (real / "svc.env").write_text(f"k = {FAKE_AWS_ID}\n")
    assert len(sv.scan([str(real), str(tmp_path / "missing")])) == 1

    assert sv.scan([]) == [], "no roots requested at all is not an error"


def test_concurrent_scans_do_not_clobber_each_others_failures(tmp_path: Path):
    """Failures used to live in a module global, so one scan clearing it while
    another was mid-flight lost the other's result. Each caller owns its list."""
    sandbox(tmp_path)
    good = tmp_path / "good"
    good.mkdir()
    (good / "s.env").write_text(f"k = {FAKE_AWS_ID}\n")
    bad = tmp_path / "bad"
    bad.mkdir()

    real_root = sv.scan_root

    def flaky(root: Path):
        if root.name == "bad":
            raise RuntimeError(f"gitleaks failed on {root}: boom")
        return real_root(root)

    sv.scan_root = flaky
    errors, seen = [], []

    def race():
        mine: list[str] = []
        try:
            sv.scan([str(good), str(bad)], failures=mine)
            seen.append(mine)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    try:
        threads = [threading.Thread(target=race) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        sv.scan_root = real_root

    assert not errors, errors
    assert all(len(f) == 1 for f in seen), f"each scan sees exactly its own failure: {seen}"


MALFORMED_ACTIONS = [
    None, "string", 42, True, {"a": 1}, [None], ["x"], [42], [[]],
    [{}], [{"key": None}], [{"key": ""}], [{"key": "k"}],
    [{"action": "remove"}], [{"key": "k", "action": None}],
    [{"key": "k", "action": "rm -rf /"}], [{"key": 5, "action": "remove"}],
    [{"key": "ok", "action": "remove"}, None],
]


def test_every_malformed_action_payload_is_rejected_not_crashed(tmp_path: Path):
    """The apply endpoint takes JSON off the wire. One report was about
    {"actions": null}; the same shape of bug covered most of these."""
    sandbox(tmp_path)
    for bad in MALFORMED_ACTIONS:
        try:
            sv.apply_actions({}, bad)
        except ValueError:
            pass
        except Exception as e:  # noqa: BLE001
            raise AssertionError(f"{bad!r} raised {type(e).__name__}, expected ValueError") from None
        else:
            raise AssertionError(f"{bad!r} should not have been accepted")
        assert not sv.MUTATE.locked(), f"the lock leaked while rejecting {bad!r}"


def test_the_apply_endpoint_answers_400_on_a_malformed_payload(tmp_path: Path):
    sandbox(tmp_path)
    url = sv.serve([], [], apply_mode=True, open_browser=False)
    base, token = url.split("/?t=")

    for bad in ('{"actions": null}', '{"actions": "nope"}', '{"actions": [null]}',
                '{"actions": [{"key": "k", "action": "sudo"}]}', "{}"):
        req = urllib.request.Request(base + f"/api/apply?t={token}",
                                     data=bad.encode(), method="POST")
        code, body = send(req)
        assert code == 400, f"{bad} should be a 400, got {code} {body[:120]}"

    req = urllib.request.Request(base + f"/api/apply?t={token}",
                                 data=b'{"actions": []}', method="POST")
    assert send(req)[0] == 200, "an empty action list is valid and does nothing"


# --------------------------------------------------------------- guarantee 4: no network


def test_the_scanner_has_no_outbound_network_capability():
    """Still structural, not a flag. The scanner, the local server and the UI
    cannot make a request even if something asked them to: live verification lives
    in verify.py, which secret_vacuum.py imports only inside the one function that
    --verify live reaches."""
    source = Path(sv.__file__).read_text()
    for banned in ("import requests", "import urllib.request", "from urllib.request",
                   "import http.client", "import socket", "urlopen("):
        assert banned not in source, f"secret_vacuum.py must not reference {banned}"
    assert source.count("import verify") == 1, "verify must not become a module-level import"
    assert "    import verify" in source, "and it must stay inside the function"


def test_a_verifier_may_only_talk_to_the_issuer_of_the_credential():
    """A verifier that can be pointed anywhere is an exfiltration primitive."""
    import verify
    for rule, (host, url, _headers) in verify.VERIFIERS.items():
        assert url.startswith(f"https://{host}/"), f"{rule} targets {url}, not {host}"
    assert verify.destinations(["github-pat", "stripe-access-token", "nonexistent"]) == [
        "api.github.com", "api.stripe.com"]


def test_verification_is_off_unless_asked_for(tmp_path: Path):
    sandbox(tmp_path)
    (tmp_path / "a.env").write_text(f"K={FAKE_STRIPE}\n")
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        sv.main(["scan", "--json", "--root", str(tmp_path)])
    doc = json.loads(out.getvalue())
    assert doc["findings"][0]["live"] == "", "a default scan must never have asked anyone"


def test_a_throttled_check_is_unknown_not_revoked():
    """429 says the provider would not answer, not that the key is dead. Reporting
    it as revoked tells someone a live credential is safe to leave alone."""
    import verify

    class Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def throttled(_req, timeout=0):
        raise urllib.error.HTTPError("u", 429, "Too Many Requests", {}, None)

    def rejected(_req, timeout=0):
        raise urllib.error.HTTPError("u", 401, "Unauthorized", {}, None)

    def offline(_req, timeout=0):
        raise OSError("network is unreachable")

    assert verify.verify("github-pat", "x", opener=throttled)[0] == "unknown"
    assert verify.verify("github-pat", "x", opener=rejected)[0] == "revoked"
    assert verify.verify("github-pat", "x", opener=offline)[0] == "unknown"
    assert verify.verify("github-pat", "x", opener=lambda *a, **k: Resp())[0] == "live"
    assert verify.verify("no-such-rule", "x", opener=offline)[0] == "unknown"


def test_a_honeytoken_is_never_verified():
    """A canary exists so that any use raises an alarm. Verifying one IS the alarm,
    and the alarm would say this machine is compromised."""
    import verify
    # A canary is built to be indistinguishable from a real credential, so the
    # value is not the signal. The path is, and so is a registry the owner keeps.
    assert verify.is_canary("x", "/x/from-canarytokens.org/creds")
    assert verify.is_canary("x", "/home/d/.aws/honeytoken-profile")
    assert not verify.is_canary(FAKE_STRIPE, "/x/.env"), "an unknown value is treated as real"
    reg = {verify._sha8(FAKE_STRIPE)}
    assert verify.is_canary(FAKE_STRIPE, "/x/.env", reg), "the owner can mark one"


def test_offline_checks_separate_expired_from_plausible():
    import base64 as b64
    enc = lambda d: b64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    jwt = lambda exp: f"{enc({'alg': 'HS256'})}.{enc({'sub': 'a', 'exp': exp})}.c2ln"
    now = int(time.time())
    assert sv.offline_check(jwt(now - 86400))[0] == "expired"
    assert sv.offline_check(jwt(now + 86400))[0] == "live-shape"
    assert sv.offline_check(FAKE_AWS_ID)[0] == "live-shape"
    assert sv.offline_check("just some high entropy text here")[0] == "unknown"
    assert sv.offline_check("aaaa.bbbb.cccc")[0] == "malformed"


def test_a_live_credential_sorts_above_a_merely_present_one(tmp_path: Path):
    """The point of verification is triage order, not a badge."""
    dead = finding("/x/a.env", "sk_" + "live_dead000000000000000")
    alive = finding("/x/b.env", "sk_" + "live_alive00000000000000")
    alive.live = ("live", "accepted")
    dead.live = ("revoked", "rejected")
    order = [g.lead.live[0] for g in sv.group_findings([dead, alive])]
    assert order == ["live", "revoked"], order


# --------------------------------------------------------------- end to end, real gitleaks


def test_real_gitleaks_finds_a_planted_secret_and_the_round_trip_clears_it(tmp_path: Path):
    sandbox(tmp_path)
    root = tmp_path / "fixture"
    root.mkdir()
    (root / "config.env").write_text(f"aws_access_key_id = {FAKE_AWS_ID}\n")

    found = sv.scan([str(root)])
    assert found, "gitleaks should flag a plausible AWS key id"
    f = next(x for x in found if x.secret == FAKE_AWS_ID)
    assert f.rule == "aws-access-token" and not f.tracked

    act("remove", f)
    assert sv.scan([str(root)]) == [], "rescan is clean once the file is gone"

    sv.undo()
    assert len(sv.scan([str(root)])) == 1, "and the finding is back after undo"


def test_ignoring_a_finding_hides_it_from_the_next_scan(tmp_path: Path):
    sandbox(tmp_path)
    root = tmp_path / "fixture2"
    root.mkdir()
    (root / "app.env").write_text(f"stripe = {FAKE_STRIPE}\n")

    found = sv.scan([str(root)])
    assert found
    sv.add_ignore(found[0])
    assert sv.scan([str(root)]) == [], ("an ignored value must stay gone: the fingerprint "
                                        "stops gitleaks, the sv: digest stops our parsers")


def test_tracked_files_are_flagged_as_committed(tmp_path: Path):
    sandbox(tmp_path)
    repo = tmp_path / "repo2"
    repo.mkdir()
    run = lambda *a: subprocess.run(a, cwd=repo, capture_output=True, check=True)
    run("git", "init", "-q")
    run("git", "config", "user.email", "t@t.test")
    run("git", "config", "user.name", "t")
    (repo / "committed.env").write_text(f"key = {FAKE_STRIPE}\n")
    (repo / "loose.env").write_text(f"key2 = {FAKE_AWS_ID}\n")
    run("git", "add", "committed.env")
    run("git", "commit", "-q", "-m", "x")

    sv.git_tracked.cache_clear()
    by_name = {Path(f.path).name: f for f in sv.scan([str(repo)])}
    assert by_name["committed.env"].tracked is True
    assert by_name["loose.env"].tracked is False


def test_a_missing_binary_raises_instead_of_exiting_the_process():
    """_binary runs inside worker threads and inside request handlers. sys.exit
    there raises SystemExit, which the scan loop does not catch (it is not an
    Exception) and which kills the caller with a traceback instead of a message."""
    try:
        sv._binary("secret-vacuum-no-such-binary")
    except SystemExit:
        raise AssertionError("sys.exit from a worker thread does not exit cleanly")
    except FileNotFoundError as e:
        assert "not found on PATH" in str(e)
    else:
        raise AssertionError("a missing binary must fail")


def test_a_missing_scanner_reads_as_a_scan_failure(tmp_path: Path):
    """gitleaks absent must surface as the same loud scan failure as any other,
    never as an empty result and never as a SystemExit out of a worker."""
    sandbox(tmp_path)
    (tmp_path / "s.env").write_text(f"k = {FAKE_AWS_ID}\n")
    real_which = sv.shutil.which
    sv.shutil.which = lambda n: None if n == "gitleaks" else real_which(n)
    try:
        detail = ""
        try:
            sv.scan([str(tmp_path)])
        except SystemExit:
            raise AssertionError("a worker thread must not try to exit the process")
        except RuntimeError as e:
            detail = str(e)
        assert "gitleaks not found on PATH" in detail, detail
    finally:
        sv.shutil.which = real_which


def test_a_filesystem_error_in_a_route_answers_the_request():
    """Every route touches the filesystem. A handler that raises OSError without
    the guard drops the connection, so the UI shows nothing at all -- including
    after a partial apply that already moved files into the trash."""
    sent = {}

    class Stub:
        _guard = sv.Handler._guard

        def _json(self, payload, code=200):
            sent.update(payload=payload, code=code)

    def boom():
        raise PermissionError(13, "Permission denied")

    Stub()._guard(boom)
    assert sent["code"] == 500, sent
    assert "PermissionError" in sent["payload"]["error"], sent


def test_an_unexpected_report_shape_is_a_scan_failure(tmp_path: Path):
    """group_findings indexes the report directly. If a future gitleaks renames a
    field, that must read as a scan failure, not a KeyError out of the CLI or a
    request dropped half way through."""
    sandbox(tmp_path)
    (tmp_path / "s.env").write_text(f"k = {FAKE_AWS_ID}\n")
    real_run = subprocess.run

    class Fake:
        returncode = 0
        stderr = ""
        stdout = json.dumps([{"Fingerprint": "f", "File": "x", "Description": "d",
                              "StartLine": 1, "EndLine": 1, "Secret": "s"}])

    def renamed(cmd, **kw):
        return Fake() if "gitleaks" in cmd[0] and "dir" in cmd else real_run(cmd, **kw)

    sv.subprocess.run = renamed
    try:
        detail = ""
        try:
            sv.scan([str(tmp_path)])
        except RuntimeError as e:
            detail = str(e)
        assert "missing RuleID" in detail, detail
    finally:
        sv.subprocess.run = real_run


def test_a_rescan_never_tears_a_snapshot(tmp_path: Path):
    """snapshot does real work between reading the findings and reading the failure
    list. Published as separate keys, a rescan lands in that window and the page
    shows one scan's findings beside another's failures: with the two-lookup shape
    this tears on roughly half of all snapshots, so a machine with roots that could
    not be read renders as fully scanned and clean."""
    sandbox(tmp_path)
    gens = [
        sv._scan_state(
            [finding(str(tmp_path / f"g{g}.env"), FAKE_AWS_ID, line=i) for i in range(1, 300)],
            [f"gen{g}"],
        )
        for g in (0, 1)
    ]

    class Stub:
        snapshot = sv.Handler.snapshot
        state = {"scan": gens[0], "roots": [str(tmp_path)], "apply": False,
                 "gitleaks": "test", "token": "t", "port": 1}

    stub, stop, torn = Stub(), [False], []

    def flip():
        i = 0
        while not stop[0]:
            stub.state["scan"] = gens[i % 2]
            i += 1

    writer = threading.Thread(target=flip, daemon=True)
    writer.start()
    try:
        for _ in range(60):
            snap = stub.snapshot()
            want = "gen0" if "g0.env" in snap["findings"][0]["paths"][0] else "gen1"
            if snap["failures"] != [want]:
                torn.append(snap["failures"])
    finally:
        stop[0] = True
        writer.join()
    assert not torn, torn[:3]


# ----------------------------------------------------- portability of the delete path


def test_a_trash_destination_never_escapes_its_batch(tmp_path: Path):
    """The old encoding stripped a leading slash, which does nothing to a Windows
    path. Joining a rooted path discards everything left of it, so the computed
    trash destination WAS the original file and the move was a no-op recorded as a
    success. Checked for every root shape, from a POSIX machine, because a Windows
    runner is not in the loop on every commit."""
    from pathlib import PurePosixPath, PureWindowsPath
    cases = [
        (PureWindowsPath, r"C:\Users\dev\project\.env"),
        (PureWindowsPath, r"D:\x\y.pem"),
        (PureWindowsPath, r"\\server\share\dev\.env"),
        (PurePosixPath, "/home/dev/project/.env"),
        (PurePosixPath, "/Users/dev/.aws/credentials"),
    ]
    for flavour, raw in cases:
        rel = sv.trash_rel(raw, flavour=flavour)
        assert not rel.is_absolute(), f"{raw} escaped the batch as {rel}"
        assert ".." not in rel.parts, f"{raw} could climb out of the batch"
        back = sv.trash_abs(rel, windows=flavour is PureWindowsPath)
        assert flavour(str(back)) == flavour(raw), f"{raw} restored to {back}"


def test_posix_trash_layout_is_unchanged(tmp_path: Path):
    """Batches written by earlier versions still restore, so the encoding change
    cannot strand a file someone already moved to the trash."""
    from pathlib import PurePosixPath
    assert sv.trash_rel("/home/dev/x.env", flavour=PurePosixPath) == PurePosixPath("home/dev/x.env")


def test_history_files_are_redact_only_on_every_platform(tmp_path: Path):
    """The guard used to test for "/.bash_history" as a suffix, which no Windows
    path contains, so on Windows the whole-file delete was offered for a shell
    history. PowerShell history was never covered at all."""
    for raw in (r"C:\Users\dev\.bash_history", "/home/dev/.bash_history",
                r"C:\Users\d\AppData\Roaming\Microsoft\Windows\PowerShell"
                r"\PSReadLine\ConsoleHost_history.txt"):
        f = finding(raw, FAKE_STRIPE)
        assert not f.removable, f"{raw} must never be removable as a whole file"
        assert f.suggested == "redact"


def test_credential_files_are_recognised_with_either_separator(tmp_path: Path):
    for raw in (r"C:\Users\dev\project\.env", "/home/dev/project/.env",
                r"C:\Users\dev\.aws\credentials", r"C:\certs\server.pem"):
        assert finding(raw, FAKE_STRIPE).suggested == "remove", raw


def test_no_authors_home_directory_is_baked_into_the_tool(tmp_path: Path):
    """~/Documents/GitHub was hardcoded in the defaults: my folder, shipped in a
    public tool, so everyone else got a root that does not exist while their own
    code was never scanned."""
    src = Path(sv.__file__).read_text()
    assert str(Path.home()) not in src, "this machine's home directory is in the source"
    assert "Documents/GitHub" not in src, "one person's code folder is not a default"
    # Every curated root is relative to whatever home the tool runs as.
    for r in sv.QUICK_ROOTS:
        assert not r.startswith(("/", "~", "\\")) and ":" not in r, f"{r} is not portable"
    assert sv.default_roots() == [str(Path.home())]


# ----------------------------------------------------- suppression is visible


def test_a_context_filter_never_overrules_a_typed_rule(tmp_path: Path):
    """The bug this whole layer exists for. An S3 presigned URL is an expiring
    signature, so a filter suppressed it -- but the URL carries a real AKIA key id,
    and the typed aws-access-token hit for that id was suppressed along with it.
    The scan then reported the file clean."""
    url = "https://b.s3.amazonaws.com/k?X-Amz-Credential=" + FAKE_AWS_ID + "/20260101/us-east-1"
    akia = finding("/x/terraform.tfstate", FAKE_AWS_ID)
    akia.rule, akia.match = "aws-access-token", url
    signature = finding("/x/terraform.tfstate", "9f2c1a" * 10)
    signature.rule = "generic-api-key"
    signature.match = "X-Amz-" + "Signature=" + "9f2c1a" * 10

    kept, dropped = sv.partition([akia, signature])
    assert [f.rule for f in kept] == ["aws-access-token"], "the key id must survive"
    assert [f.suppressed_by for f in dropped] == ["presigned-url"]


def test_every_drop_is_counted_and_attributed(tmp_path: Path):
    """A scan that filtered everything and a scan that found nothing used to print
    exactly the same thing."""
    noise = [finding("/x/.env", v) for v in ("YOUR_TOKEN_HERE", "${SOME_VAR}", "xxxxxxxxxx")]
    real = finding("/x/.env", FAKE_STRIPE)
    kept, dropped = sv.partition(noise + [real])
    assert len(kept) == 1 and len(dropped) == 3
    rows = sv.suppression_summary(dropped)
    assert sum(r["count"] for r in rows) == 3
    assert all(r["reason"] and r["rule"] for r in rows), "a drop without a reason is invisible again"


def test_no_filter_reports_what_the_suppressors_would_drop(tmp_path: Path):
    sandbox(tmp_path)
    (tmp_path / ".env").write_text(f"K={FAKE_STRIPE}\n")
    kept, _ = sv.partition([finding("/x/.env", "YOUR_TOKEN_HERE")])
    assert not kept, "suppressed by default"
    saved = list(sv.SUPPRESSORS)
    sv.SUPPRESSORS.clear()
    try:
        kept, dropped = sv.partition([finding("/x/.env", "YOUR_TOKEN_HERE")])
        assert len(kept) == 1 and not dropped, "--no-filter must report everything"
    finally:
        sv.SUPPRESSORS[:] = saved


def test_the_ui_payload_carries_the_suppression_summary(tmp_path: Path):
    sandbox(tmp_path)
    dropped = [finding("/x/.env", "YOUR_TOKEN_HERE")]
    sv.partition(dropped)
    state = sv._scan_state([finding(str(tmp_path / "a.env"), FAKE_STRIPE)], [], dropped)
    assert state["suppressed"] and state["suppressed"][0]["count"] == 1


# ----------------------------------------------------- schema parsers


def test_terraform_state_secrets_are_found_where_patterns_cannot_see_them(tmp_path: Path):
    """State holds outputs and attributes in plaintext, frequently base64, which
    defeats entropy scoring. On a real state file gitleaks reported nothing."""
    tok = "ZXlKaGJHY2lPaUpJVXpJMU5" + "pSjkuZm9vYmFyYmF6cXV4"
    doc = {"resources": [{"instances": [{"attributes": {
        "token": tok * 4,
        "authentication_mode": "API_AND_CONFIG_MAP",
        "data": {"AB_JWT_SIGNATURE_SECRET": "c2lnbmluZ3Nl" + "Y3JldHZhbHVlaGVyZQ==",
                 "instance-admin-password": "Y29ycmVjdGhv" + "cnNlYmF0dGVyeQ=="},  # gitleaks:allow
        "region": "us-east-1", "bucket": "my-state-bucket"}}]}]}
    f = tmp_path / "terraform.tfstate"
    f.write_text(json.dumps(doc, indent=1))
    found = sv.parse_tfstate(f, f.read_text())
    names = {x.description.split(" in ")[0] for x in found}
    assert names == {"token", "AB_JWT_SIGNATURE_SECRET", "instance-admin-password"}, names
    assert "authentication_mode" not in names, "an enum constant is configuration, not a credential"


def test_terraform_state_is_reported_but_never_edited(tmp_path: Path):
    """A line-level replace leaves the JSON parseable and the state no longer
    describing reality, so the next apply destroys and recreates. Deleting the file
    is worse. Report it; the only honest action is rotation."""
    sandbox(tmp_path)
    state = tmp_path / "terraform.tfstate"
    state.write_text(json.dumps({"outputs": {"password": {"value": FAKE_STRIPE}}}))
    f = finding(str(state), FAKE_STRIPE)
    assert not f.editable and not f.removable
    assert f.suggested == "ignore"
    # and the grouped row the UI actually renders, which had its own default
    g = sv.group_findings([f])[0]
    assert not g.editable and g.suggested == "ignore", g.public()["suggested"]
    before = state.read_text()
    for action in ("remove", "redact"):
        out = act(action, f)
        assert not out["results"][0]["ok"]
        assert "rotate" in out["results"][0]["detail"]
    assert state.read_text() == before, "state must be untouched by either action"


def test_a_redaction_that_breaks_a_structured_file_is_rolled_back(tmp_path: Path):
    """Redaction is a line-level string replace. Inside a JSON document that can
    leave something that no longer parses, and a broken kubeconfig is a worse
    outcome than the redacted line was a good one."""
    sandbox(tmp_path)
    target = tmp_path / "app.json"
    # the value spans the quotes, so replacing it leaves an unterminated string
    target.write_text('{\n "k": "' + FAKE_STRIPE + '"\n}\n')
    original = target.read_text()
    f = finding(str(target), FAKE_STRIPE + '"', line=2)
    out = act("redact", f)
    assert target.read_text() == original, "the original must come back"
    assert not out["results"][0]["ok"]
    assert "broke the file" in out["results"][0]["detail"], out["results"][0]


def test_docker_registry_auth_is_decoded(tmp_path: Path):
    """auths[].auth is base64 of user:password, not encryption. gitleaks sees one
    opaque blob."""
    import base64 as b64
    blob = b64.b64encode(b"AWS:hunter2hunter2hunter2").decode()
    f = tmp_path / "config.json"
    f.write_text(json.dumps({"auths": {"registry.example.com": {"auth": blob}}}))
    found = sv.parse_docker_config(f, f.read_text())
    assert len(found) == 1
    assert found[0].secret == "hunter2hunter2hunter2"
    assert "registry.example.com" in found[0].description


def test_kubeconfig_credentials_are_parsed(tmp_path: Path):
    f = tmp_path / "config"
    f.write_text(
        "apiVersion: v1\nusers:\n- name: admin\n  user:\n"
        "    token: abcdefghijklmnopqrstuvwxyz012345\n"
        "- name: certuser\n  user:\n    client-key-data: LS0tLS1CRUdJTiBQUklWQVRF\n")
    found = sv.parse_kubeconfig(f, f.read_text())
    kinds = {x.description.split(" for ")[0] for x in found}
    assert kinds == {"token", "client-key-data"}, kinds
    assert all(x.detector == "schema" for x in found)


def test_container_definitions_with_literal_secrets_are_found(tmp_path: Path):
    d = tmp_path / "Dockerfile"
    d.write_text("FROM alpine\nENV API_TOKEN=s3cretvalue0123456789\nENV APP_PORT=8080\n")
    found = sv.parse_container_env(d, d.read_text())
    assert [x.description.split(" set ")[0] for x in found] == ["API_TOKEN"]


def test_credential_file_assignments_beat_the_keyword_list(tmp_path: Path):
    """gitleaks' generic rule keys off the variable name, so cs= (a client secret)
    and setup_token= are invisible. In a .env the file name has already said what
    the values are -- but a key that announces it is public stays out."""
    f = tmp_path / ".env"
    f.write_text(
        "cid=abcdef0123456789abcdef\n"
        "cs=sUp3rS3cr3t" + "Cl13ntV4lu3\n"
        "setup_" + "token=pnu_0123456789abcdefghij\n"  # gitleaks:allow
        "VITE_SUPABASE_URL=https://xyz.supabase.co\n"
        "VITE_SUPABASE_ANON_" + "KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\n"  # gitleaks:allow
        "VITE_TURNSTILE_SITE_KEY=0x4AAAAAAADnPIDROlWd9Tm\n"
        "APP_NAME=my-application-name\n"
        "# comment=shouldnotmatch0123456\n")
    names = {x.description.split(" in ")[0] for x in sv.parse_assignments(f, f.read_text())}
    assert {"cs", "setup_token"} <= names, f"missed a real credential: {names}"
    assert not names & {"VITE_SUPABASE_URL", "VITE_SUPABASE_ANON_KEY",
                        "VITE_TURNSTILE_SITE_KEY", "APP_NAME", "comment"}, names


def test_a_parser_that_raises_never_loses_the_scan(tmp_path: Path):
    """A bug in one parser must not cost the findings from every other file."""
    bad = tmp_path / "terraform.tfstate"
    bad.write_text("{ this is not json at all")
    assert sv.parse_file(bad) == []
    good = tmp_path / ".env"
    good.write_text(f"TOKEN={FAKE_STRIPE}\n")
    assert sv.parse_file(good), "the next file still parses"


# ----------------------------------------------------- what cannot be deleted


def test_an_environment_variable_is_traced_back_to_the_file_that_set_it(tmp_path: Path):
    """An exported variable has no file to delete, so the actionable thing is the
    file that exported it. The variable with no file behind it is the whole reason
    this report exists."""
    rc = tmp_path / ".zshrc"
    secret = "sbp_" + "0123456789abcdef0123456789abcdef"
    rc.write_text(f"export SUPABASE_ACCESS_TOKEN={secret}\n")
    rows = sv.env_report(
        environ={"SUPABASE_ACCESS_TOKEN": secret,
                 "ORPHAN_API_KEY": "qQ7wE2rT5yU8iO1pA4sD6fG9hJ0kL3zX",  # gitleaks:allow
                 "HOME": "/home/dev", "SSH_AUTH_SOCK": "/private/tmp/agent.sock",
                 "BUILD_ID": "9f1c2e3a-4b5d-6e7f-8a9b-0c1d2e3f4a5b"},
        roots=[str(rc)])
    by_name = {r["name"]: r for r in rows}
    assert set(by_name) == {"SUPABASE_ACCESS_TOKEN", "ORPHAN_API_KEY"}, sorted(by_name)
    assert by_name["SUPABASE_ACCESS_TOKEN"]["sources"] == [sv.display_path(str(rc))]
    assert not by_name["ORPHAN_API_KEY"]["sources"]
    assert "unset ORPHAN_API_KEY" in by_name["ORPHAN_API_KEY"]["advice"]
    assert all(secret not in json.dumps(r) for r in rows), "the report never carries a value"


def test_the_report_only_surfaces_never_print_a_value(tmp_path: Path):
    """These three exist to tell you something is there. None of them may copy it
    out: that is exactly what the malware this defends against does."""
    secret = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        sv.print_report(
            sv.env_report(environ={"GH_TOKEN": secret}, roots=[]),
            [{"container": "api", "image": "app:1", "names": ["DB_PASSWORD"]}],
            [{"service": "com.example.thing", "items": 3}])
    body = out.getvalue()
    assert secret not in body
    assert "DB_PASSWORD" in body and "com.example.thing" in body
    assert "nothing to remove" in body, "the keystore is where a secret belongs"


def test_docker_and_keystore_absence_is_a_skip_not_a_failure(tmp_path: Path):
    """No daemon, or a platform with no supported keystore, must be silence."""
    real = sv.shutil.which
    sv.shutil.which = lambda n: None if n in ("docker", "security", "cmdkey") else real(n)
    try:
        assert sv.docker_report() == []
        assert sv.keystore_report() == []
    finally:
        sv.shutil.which = real


def test_the_keystore_is_never_asked_for_a_value():
    """security dump-keychain with -d prints the secrets themselves and prompts per
    item. Nothing here may ever reach for that."""
    src = Path(sv.__file__).read_text()
    assert "dump-keychain" in src, "the inventory should still exist"
    # -d turns an attribute listing into a dump of the secrets themselves, and
    # prompts for every item.
    after = src.split("dump-keychain", 1)[1][:60]
    assert '"-d"' not in after and "'-d'" not in after
    assert "find-generic-password" not in src, "that reads a value back"


def test_both_detectors_skip_exactly_the_same_trees(tmp_path: Path):
    """The parsers keeping their own copy of the skip list is how a downloaded
    plugin marketplace got parsed but not pattern-scanned, and how 41 findings from
    somebody else's catalogue reached the table. One list, read from the config
    gitleaks is handed."""
    sandbox(tmp_path)
    vendored = [
        "node_modules/pkg/.env", ".venv/lib/site-packages/x/.env",
        ".cursor/extensions/vendor-1.0/.envrc",
        ".claude/plugins/marketplaces/official/.claude-plugin/catalog.json",
        ".claude/plugins/cache/thing/1.0/tests/config.json",
        "dist/bundle.env", ".terraform/modules/m/terraform.tfstate",
    ]
    for rel in vendored:
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(f"TOKEN={FAKE_STRIPE}\n")
        assert sv.is_skipped(str(f)), f"{rel} is vendored and must be skipped by the parsers too"
    mine = tmp_path / "project" / ".env"
    mine.parent.mkdir(parents=True)
    mine.write_text(f"TOKEN={FAKE_STRIPE}\n")
    assert not sv.is_skipped(str(mine))

    # and the walk agrees with the predicate
    found = {f.path for f in sv.parse_roots([tmp_path])}
    assert found == {str(mine)}, sorted(found)


def test_the_skip_list_covers_windows_separators(tmp_path: Path):
    assert sv.is_skipped(r"C:\Users\dev\project\node_modules\pkg\.env")
    assert not sv.is_skipped(r"C:\Users\dev\project\.env")


# --------------------------------------------------------------- runner


def main() -> int:
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = []
    for name, fn in tests:
        tmp_path = Path(tempfile.mkdtemp(prefix="sv-test-"))
        try:
            fn(tmp_path) if fn.__code__.co_argcount else fn()
            print(f"  ok    {name}")
        except Exception as e:  # noqa: BLE001
            failed.append(name)
            print(f"  FAIL  {name}\n        {type(e).__name__}: {e}")
        finally:
            sv.git_tracked.cache_clear()
            shutil.rmtree(tmp_path, ignore_errors=True)
    print(f"\n{len(tests) - len(failed)}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
