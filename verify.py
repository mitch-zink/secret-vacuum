#!/usr/bin/env python3
"""Live credential verification, kept deliberately apart from secret_vacuum.py.

Asking a provider whether a credential still works is the difference between a
list and a queue. It is also an active use of that credential: the request lands
in the provider's audit log, it can trip impossible-travel or new-ASN alerts, it
consumes rate limit, and against a honeytoken it is the event that raises the
alarm you planted. Truffle Security reports that verification removes false
positives but publishes no controlled benchmark, so no number is claimed here.

None of that is a reason to withhold the feature, and all of it is a reason to
keep it out of the scanner. secret_vacuum.py never imports this module, so its
no-network guarantee is a property of the code rather than of a flag: the
scanner, the local server and the UI cannot make a request even if asked. This
file is the only place in the project that can, it is imported only when
--verify is passed with a live mode, and every destination is pinned below.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

MODES = ("never", "offline", "readonly", "all")

# rule id -> (host, url, header template). The host is pinned: a verifier may only
# ever talk to the service that issued the credential it is checking.
VERIFIERS: dict[str, tuple[str, str, dict]] = {
    "github-pat": ("api.github.com", "https://api.github.com/user",
                   {"Authorization": "Bearer {v}", "Accept": "application/vnd.github+json"}),
    "github-fine-grained-pat": ("api.github.com", "https://api.github.com/user",
                                {"Authorization": "Bearer {v}"}),
    "stripe-access-token": ("api.stripe.com", "https://api.stripe.com/v1/balance",
                            {"Authorization": "Bearer {v}"}),
    "slack-bot-token": ("slack.com", "https://slack.com/api/auth.test",
                        {"Authorization": "Bearer {v}"}),
    "openai-api-key": ("api.openai.com", "https://api.openai.com/v1/models",
                       {"Authorization": "Bearer {v}"}),
    "anthropic-api-key": ("api.anthropic.com", "https://api.anthropic.com/v1/models",
                          {"x-api-key": "{v}", "anthropic-version": "2023-06-01"}),
}

# Canaries exist so that any use raises an alarm, which makes verifying one the
# alarm -- and the alarm says this machine is compromised. A canary is designed to
# be indistinguishable from a real credential, so the value cannot be the signal.
# Two things that can: the path it was found under, and a registry the owner
# keeps. Anything unrecognised is treated as real, which is the safe default for
# deletion and the unsafe one for verification, so verification is opt-in.
CANARY_MARKERS = ("canarytoken", "canary.tools", "thinkst", "honeytoken", "canary")


def is_canary(value: str, context: str = "", registry: set[str] | None = None) -> bool:
    """registry holds SHA-256 prefixes the owner has marked as tripwires."""
    if registry and _sha8(value) in registry:
        return True
    return any(m in context.lower() for m in CANARY_MARKERS)


def _sha8(value: str) -> str:
    import hashlib
    return hashlib.sha256(value.encode()).hexdigest()[:8]


def load_registry(path) -> set[str]:
    try:
        return {ln.strip() for ln in open(path) if ln.strip() and not ln.startswith("#")}
    except OSError:
        return set()


def verifiable(rule: str) -> bool:
    return rule in VERIFIERS


def destinations(rules: list[str]) -> list[str]:
    """Every host a run would contact, so it can be shown before the first call."""
    return sorted({VERIFIERS[r][0] for r in rules if r in VERIFIERS})


def verify(rule: str, value: str, opener=None, timeout: int = 6) -> tuple[str, str]:
    """(state, detail). States: live, revoked, unknown.

    unknown is a first-class answer and never renders as safe: a timeout, a 429 or
    a proxy says nothing at all about the credential."""
    if rule not in VERIFIERS:
        return "unknown", "no verifier for this credential type"
    host, url, headers = VERIFIERS[rule]
    req = urllib.request.Request(url, headers={k: v.format(v=value) for k, v in headers.items()})
    send = opener or urllib.request.urlopen
    try:
        with send(req, timeout=timeout) as r:
            return ("live", f"{host} accepted it ({r.status})") if r.status < 300 \
                else ("unknown", f"{host} answered {r.status}")
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return "revoked", f"{host} rejected it ({e.code})"
        if e.code == 429:
            # Throttling is not a verdict. Reporting it as revoked would tell
            # someone a live key was dead.
            return "unknown", f"{host} rate-limited the check"
        return "unknown", f"{host} answered {e.code}"
    except Exception as e:  # noqa: BLE001 - DNS, TLS, proxy, offline: all inconclusive
        return "unknown", f"could not reach {host}: {type(e).__name__}"
