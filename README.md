# secret-vacuum

Finds plaintext secrets sitting on your Mac and deletes the ones you approve.

Two files, no dependencies. Detection is entirely [gitleaks](https://github.com/gitleaks/gitleaks)'
default ruleset, so this tool writes no regexes of its own. It is the scanner, a table with
checkboxes, and a trash can.

![secret-vacuum UI](docs/ui.png)

```
brew install gitleaks
git clone https://github.com/mitch-zink/secret-vacuum && cd secret-vacuum
python3 secret_vacuum.py            # preview, opens a local UI
python3 secret_vacuum.py --apply    # same UI, changes enabled
```

## What it does

```
python3 secret_vacuum.py scan       # masked table on stdout, no UI, read only
python3 secret_vacuum.py            # UI in your browser, read only
python3 secret_vacuum.py --apply    # UI with the actions enabled
python3 secret_vacuum.py undo       # put the last batch back
```

## One row per secret, not per hit

A scan of a real machine is dominated by the same credential appearing over and over: seven
worktrees of one repo, a value pasted into three config files, a token echoed through committed
logs. secret-vacuum groups findings by the value itself, so each row is one credential and the
`copies` column says how many places it lives. An action applies to every copy.

On the machine this was built against that is the difference between **2,029 rows and 118**. It is
the same data either way; one of them is a list you can actually work through.

Three actions per secret:

| Action | What happens on disk | For |
|---|---|---|
| **remove** | every file holding the value moves to `~/.secret-vacuum/trash/<batch>/`, paths preserved | `.env`, `*.pem`, `id_rsa`: files that are nothing but credential |
| **redact** | the file is copied to the trash, then the secret is replaced in place with `<removed by secret-vacuum>` | `.zshrc`, `settings.json`, `.mcp.json`: one bad line in a file you need |
| **ignore** | each copy's fingerprint is appended to `~/.secret-vacuum/.gitleaksignore` | false positives: presigned URLs, UUIDs, pagination cursors, content hashes |

`undo` restores the most recent batch. Trash is never emptied for you.

Generated and vendored trees (`node_modules`, `.venv`, `site-packages`, `dist`, `.terraform`,
lockfiles and friends) are skipped via `gitleaks.toml`, which is passed with `--config` so a
scanned repository's own `.gitleaks.toml` cannot allowlist away its leaks behind your back.

## Secrets already committed to a repo

A secret in a past commit is in every clone and in the history. Deleting the working-tree file
does not unleak it. The UI marks those **committed** and says so, then removes them anyway if you
approve, because you still want the plaintext copy off your disk. **Rotate them.**

secret-vacuum never rewrites git history and never force-pushes. That is not a thing a checkbox
should do.

## What gets scanned

`~/Documents/GitHub`, `~/.aws`, `~/.ssh`, `~/.dbt`, `~/.config/gcloud`, `~/.docker/config.json`,
`~/.kube`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`, `~/.zshrc`, `~/.zsh_history`, `~/.claude.json`,
`~/.cursor`.

`~/Documents`, `~/Downloads` and `~/Desktop` are deliberately off: heavy noise, and personal files
are not where an engineer's credentials live. Add any path with `--root`, repeatable:

```
python3 secret_vacuum.py --root ~/work --root ~/.config
```

Shell history files are shown and redactable but never removable as a whole file. Rewriting your
history wholesale is its own kind of damage.

## Guarantees

Each of these is a test in `test_secret_vacuum.py`.

1. **No secret value is ever written to disk by this tool.** The gitleaks report streams to stdout
   and stays in memory. Anything recorded on disk holds a path, a line number, a rule id and a
   SHA-256 prefix — never the value.
2. **Remove means move, not unlink.** Every removal lands in the trash and `undo` reverses it.
3. **The server is loopback-only.** It binds `127.0.0.1` on a random port, requires a 32-byte
   per-run token, rejects any request whose `Host` is not the literal loopback address (DNS
   rebinding), rejects a foreign `Origin`, and never emits a CORS header. Request logging is off
   because the URL carries the token.
4. **Nothing leaves the machine.** No network calls, no telemetry, no update check. A test asserts
   the source cannot even reach the network.

Writes are off unless you pass `--apply`.

## Tests

```
python3 test_secret_vacuum.py    # no framework needed
python3 -m pytest -q             # works too
```

The end-to-end tests shell out to the real gitleaks binary against fixture directories. Test
credentials are assembled from split string literals at runtime so this repo does not trip
secret scanners, including its own pre-commit hook.

## Requirements

Python 3.10+ and the `gitleaks` binary. Nothing else: no pip install, no npm, no build step.

## License

MIT
