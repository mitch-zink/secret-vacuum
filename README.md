# secret-vacuum

Finds plaintext secrets sitting on your Mac and deletes the ones you approve.

A script, a page and a config. No pip install, no npm, no build step. Detection is entirely
[gitleaks](https://github.com/gitleaks/gitleaks)' default ruleset, so this tool writes no regexes
of its own. It is the scanner, a table with checkboxes, and a trash can.

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

The first run walks your whole code directory and can take several minutes. Each root prints as it
finishes, and the browser opens when the scan is done.

## One row per secret, not per hit

A scan of a real machine is dominated by the same credential appearing over and over: seven
worktrees of one repo, a value pasted into three config files, a token echoed through committed
logs. secret-vacuum groups findings by the value itself, so each row is one credential and the
`copies` column says how many places it lives. An action applies to every copy.

On the machine this was built against that is the difference between **2,036 rows and 118**. It is
the same data either way; one of them is a list you can actually work through.

Three actions per secret:

| Action | What happens on disk | For |
|---|---|---|
| **remove** | every file holding the value moves to `~/.secret-vacuum/trash/<batch>/`, paths preserved | `.env`, `*.pem`, `id_rsa`: files that are nothing but credential |
| **redact** | the file is copied to the trash, then the secret is replaced in place with `<removed by secret-vacuum>` | `.zshrc`, `settings.json`, `.mcp.json`: one bad line in a file you need |
| **ignore** | each copy's fingerprint is appended to `~/.secret-vacuum/.gitleaksignore` | false positives: presigned URLs, UUIDs, pagination cursors, content hashes |

`undo` restores the most recent batch, moving files back rather than copying them, so a restored secret does not linger in the trash as a second plaintext copy. Batches you do not undo stay until you delete them yourself.

## What it ignores, and why

Two kinds of noise drown the real findings on a developer machine, and both are suppressed in
`gitleaks.toml`:

**Code you did not write.** `node_modules`, `.venv`, `site-packages`, `dist`, `.terraform`,
lockfiles, and editor extension directories (`~/.cursor/extensions`, `~/.vscode/extensions`),
downloaded plugin and skill content, and local application databases and their write-ahead logs.
On the machine this was built against, editor extensions alone accounted for 20 findings, several
of which were Win32 API function names.

**Documentation placeholders.** `YOUR_ACCESS_TOKEN`, `<your-token>`, `CHANGEME`, `${MY_TOKEN}`,
`1234567890abcdef` and friends. Downloaded plugin docs are full of example `curl` commands.

Together that took a real dotfile scan from 36 findings to 10, and all 10 were genuine.

The config is passed with `--config`, so a scanned repository's own `.gitleaks.toml` cannot
allowlist away its leaks behind your back. Anything the shipped list gets wrong for you goes in
`~/.secret-vacuum/.gitleaksignore` via the Ignore action.

A root that cannot be scanned is reported as a failure in the UI and on the command line, never
counted as clean. If no root can be scanned at all, the tool errors out.

## Secrets already committed to a repo

A secret in a past commit is in every clone and in the history. Deleting the working-tree file
does not unleak it. The UI marks those **committed** and says so, then removes them anyway if you
approve, because you still want the plaintext copy off your disk. **Rotate them.**

secret-vacuum never rewrites git history and never force-pushes. That is not a thing a checkbox
should do.

## What gets scanned

`~/Documents/GitHub`, `~/.aws`, `~/.ssh`, `~/.dbt`, `~/.config/gcloud`, `~/.docker/config.json`,
`~/.kube`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`, `~/.claude.json`, `~/.cursor`, every shell startup
file (`.zshrc`, `.zshenv`, `.zprofile`, `.zlogin`, `.bashrc`, `.bash_profile`, `.bash_login`,
`.profile`, fish's `config.fish`) and both shell histories.

### Exported environment variables

A token in `$MY_API_TOKEN` has no file to delete, so the tool does not read the process
environment. It scans the files that *set* those variables instead, which is where the removable
copy lives. All the shell startup files are covered for that reason: an export hides in whichever
one ran, not just in `.zshrc`.

Redacting the line does not unset the variable in shells that are already running. Start a new
shell, or `unset` it, once you have dealt with the file.

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
