#!/usr/bin/env python3
"""Tests for secret-vacuum. Plain asserts, no framework -- `python3 test_secret_vacuum.py`
or `pytest` both work.

Test secrets are assembled at runtime from split literals so this file does not itself
trip a secret scanner. Nothing here is a real credential.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
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
    # A restored batch is not replayed by the next undo.
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
        {"key": a.sha8, "action": "remove"},
        {"key": b.sha8, "action": "redact"},
    ])
    assert not target.exists()
    assert sum(r["ok"] for r in out["results"]) == 1


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
        assert raised, "a failing scan must raise, not return []"
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


def test_generated_trees_are_not_reported(tmp_path: Path):
    """A dependency cache full of other people's fixtures is not your leak."""
    sandbox(tmp_path)
    for rel in ("node_modules/pkg/fixture.env", "src/.venv/lib/site-packages/x/conf.env",
                "app/dist/bundle.env", "real/service.env"):
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(f"aws_access_key_id = {FAKE_AWS_ID}\n")
    paths = [Path(f.path).name for f in sv.scan([str(tmp_path)])]
    assert paths == ["service.env"], f"only the authored file should surface, got {paths}"


# --------------------------------------------------------------- guarantee 3: server is locked down


def request(url: str, headers: dict | None = None, method: str = "GET") -> tuple[int, str]:
    req = urllib.request.Request(url, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


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
