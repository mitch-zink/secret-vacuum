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
    sv.add_ignore(f.fingerprint)
    sv.add_ignore(f.fingerprint)  # idempotent
    body = sv.IGNORE_FILE.read_text()
    assert body.strip() == f.fingerprint
    assert FAKE_STRIPE not in body


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

    groups = json.loads(payload)
    assert len(groups) == 1 and groups[0]["copies"] == 2
    assert FAKE_STRIPE not in payload
    assert "key" in groups[0] and "paths" in groups[0]


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
        found = sv.scan([str(good), str(bad)])
        assert len(found) == 1, "the healthy root's findings survive"
        assert sv.SCAN_FAILURES and "bad" in sv.SCAN_FAILURES[0], "the failure is recorded"
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


# --------------------------------------------------------------- guarantee 4: no network


def test_the_tool_has_no_outbound_network_capability():
    source = Path(sv.__file__).read_text()
    for banned in ("import requests", "import urllib.request", "from urllib.request",
                   "import http.client", "import socket", "urlopen("):
        assert banned not in source, f"secret_vacuum.py must not reference {banned}"


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
    sv.add_ignore(found[0].fingerprint)
    assert sv.scan([str(root)]) == [], "gitleaks honours our fingerprint ignore file"


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
