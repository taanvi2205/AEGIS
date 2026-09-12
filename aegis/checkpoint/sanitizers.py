"""Sanitizers / declassifiers (§2 item 3).

A sanitizer is a named, deterministic function that constrains a value to a
shape narrow enough that its origin stops mattering. If a recipient address must
be on a four-entry corporate allow-list, it makes no difference whether the model
read that address in a hostile web page - it cannot be an attacker's address.

Every sanitizer records what it checked and which rule it applied, so a cleared
taint is auditable after the fact (§2 item 3, §3 "everything is logged").

Fail-closed behaviour: a sanitizer that raises, times out on a pathological
input, or cannot parse its input returns `passed=False`. Taint is never cleared
by an error path, and a failed sanitizer leaves the value exactly as tainted as
it was before.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..core import SanitizationRecord, digest
from .. import text as T

_EMAIL = re.compile(r"^[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})$")
_URL = re.compile(r"^https?://([a-z0-9.-]+)(?::\d+)?(?:/|$)")


@dataclass
class SanitizerContext:
    """Session facts a context-aware sanitizer may consult.

    Only the declassifier needs this; the shape-checking sanitizers ignore it.
    It carries data, never a model or a policy decision, so the enforcement path
    stays deterministic (§3).
    """

    confidential_texts: tuple[str, ...] = ()
    public_texts: tuple[str, ...] = ()


@dataclass
class Sanitizer:
    """Base class. `rule` is the human-readable statement of the constraint that
    goes into the audit record.

    `declassifies` marks the sanitizers that satisfy INV-1. Shape checks such as
    an address allow-list constrain *where* data goes; they say nothing about
    whether the payload still contains confidential content, so they do not
    count as declassification. Only a sanitizer that inspects the outbound data
    itself sets this flag (see docs/decisions.md D-06).
    """

    name: str
    rule: str
    declassifies: bool = False

    def _check(self, value: str, context: "SanitizerContext | None") -> tuple[bool, str]:
        raise NotImplementedError

    def run(self, value: str, step: int = 0,
            context: "SanitizerContext | None" = None) -> SanitizationRecord:
        """Apply the sanitizer, never raising. Any exception becomes a failed
        check, because clearing taint on an error path would be a silent bypass."""
        try:
            passed, checked = self._check(value, context)
        except Exception as exc:                            # noqa: BLE001 - fail closed
            passed, checked = False, f"sanitizer raised {type(exc).__name__}; failing closed"
        return SanitizationRecord(self.name, digest(value), passed, checked, self.rule,
                                  step, self.declassifies)


@dataclass
class EmailAllowlist(Sanitizer):
    """Recipient must be a syntactically valid address on an allow-listed domain.

    Checks: RFC-ish shape, then domain membership. On failure: value stays
    tainted and the egress call is denied by the provenance layer.
    """

    domains: tuple[str, ...] = ()
    name: str = "email_allowlist"
    rule: str = ""

    def __post_init__(self) -> None:
        self.rule = f"address matches ^user@domain$ and domain ∈ {sorted(self.domains)}"

    def _check(self, value, context=None) -> tuple[bool, str]:
        v = T.normalize(value).replace(" ", "")
        m = _EMAIL.match(v)
        if not m:
            return False, f"{v!r} is not a single well-formed address"
        dom = m.group(1)
        if dom not in self.domains:
            return False, f"domain {dom!r} is not on the allow-list"
        return True, f"address shape valid and domain {dom!r} is allow-listed"


@dataclass
class SandboxPath(Sanitizer):
    """File path must resolve inside the approved sandbox root.

    Checks: resolution of symlinks and `..`, then containment. On failure: the
    value stays tainted, so any file tool that would touch it is denied.
    """

    root: str = "sandbox"
    name: str = "sandbox_path"
    rule: str = ""

    def __post_init__(self) -> None:
        self.rule = f"os.path.realpath(value) is inside {os.path.realpath(self.root)}"

    def _check(self, value, context=None) -> tuple[bool, str]:
        root = Path(self.root).resolve()
        target = (root / value).resolve() if not os.path.isabs(value) else Path(value).resolve()
        if root == target or root in target.parents:
            return True, f"resolves to {target}, inside the sandbox root"
        return False, f"resolves to {target}, outside {root}"


@dataclass
class UrlAllowlist(Sanitizer):
    """URL host must be on an allow-list.

    Checks: scheme is http(s) and the host matches exactly. On failure: value
    stays tainted and the network tool call is denied.
    """

    hosts: tuple[str, ...] = ()
    name: str = "url_allowlist"
    rule: str = ""

    def __post_init__(self) -> None:
        self.rule = f"scheme ∈ (http, https) and host ∈ {sorted(self.hosts)}"

    def _check(self, value, context=None) -> tuple[bool, str]:
        m = _URL.match(T.normalize(value))
        if not m:
            return False, f"{value!r} is not a plain http(s) URL"
        host = m.group(1)
        if host not in self.hosts:
            return False, f"host {host!r} is not on the allow-list"
        return True, f"host {host!r} is allow-listed"


@dataclass
class NumericRange(Sanitizer):
    """Value must parse as a number inside a closed range.

    Checks: parse, then bounds. On failure: value stays tainted, so a payment or
    quantity argument lifted from a document cannot be executed.
    """

    low: float = 0.0
    high: float = 0.0
    name: str = "numeric_range"
    rule: str = ""

    def __post_init__(self) -> None:
        self.rule = f"float(value) ∈ [{self.low}, {self.high}]"

    def _check(self, value, context=None) -> tuple[bool, str]:
        n = float(str(value).replace(",", "").strip().lstrip("$"))
        if self.low <= n <= self.high:
            return True, f"{n} is within [{self.low}, {self.high}]"
        return False, f"{n} is outside [{self.low}, {self.high}]"


@dataclass
class EnumValue(Sanitizer):
    """Value must be one of a fixed set of literals.

    Checks: normalized membership. On failure: value stays tainted.
    """

    allowed: tuple[str, ...] = ()
    name: str = "enum_value"
    rule: str = ""

    def __post_init__(self) -> None:
        self.rule = f"value ∈ {sorted(self.allowed)}"

    def _check(self, value, context=None) -> tuple[bool, str]:
        v = T.normalize(value)
        if v in {T.normalize(a) for a in self.allowed}:
            return True, f"{v!r} is in the permitted set"
        return False, f"{v!r} is not in the permitted set"


@dataclass
class NoConfidentialLeak(Sanitizer):
    """The declassifier: an outbound payload may not carry distinctive strings
    from confidential content read this session.

    What it checks: it collects the *distinctive* tokens of every confidential
    document ingested this session - long tokens, multi-digit numbers, email
    addresses - minus anything that also appears in non-confidential content,
    then verifies none of them survive in the outbound value. A summary that
    reports aggregates passes; a payload carrying individual rows does not.

    What happens on failure: the value is not declassified, so INV-1 continues to
    hold and the egress call is denied. This is the intended way to release data
    derived from confidential sources - the only way, by design.

    Fail-closed behaviour: with no context supplied it cannot prove the payload
    is clean, so it fails. An empty confidential set means nothing sensitive was
    read, and it passes trivially.
    """

    min_token_len: int = 5
    name: str = "no_confidential_leak"
    rule: str = ""
    declassifies: bool = True

    def __post_init__(self) -> None:
        self.rule = ("outbound payload shares no distinctive token with any "
                     "confidential content read this session")

    def _distinctive(self, context: "SanitizerContext") -> set[str]:
        public: set[str] = set()
        for t in context.public_texts:
            public |= set(T.tokenize(t))
        out: set[str] = set()
        for t in context.confidential_texts:
            for tok in T.tokenize(t):
                if tok in public:
                    continue
                if len(tok) >= self.min_token_len or sum(c.isdigit() for c in tok) >= 3:
                    out.add(tok)
        return out

    def _check(self, value, context=None) -> tuple[bool, str]:
        if context is None:
            return False, "no session context available; cannot prove the payload is clean"
        if not context.confidential_texts:
            return True, "no confidential content was read this session"
        distinctive = self._distinctive(context)
        present = sorted(set(T.tokenize(str(value))) & distinctive)
        if present:
            shown = ", ".join(present[:4]) + ("…" if len(present) > 4 else "")
            return False, (f"payload still carries {len(present)} distinctive token(s) from "
                           f"confidential content: {shown}")
        return True, (f"payload shares none of the {len(distinctive)} distinctive tokens "
                      f"from the confidential content read this session")


@dataclass
class SanitizerRegistry:
    """Name -> sanitizer, built once from policy and passed to the checkpoint.

    A tool argument may only be declassified by a sanitizer the tool's manifest
    names for that argument; there is no generic "sanitize anything" entry point
    (§4 Rule 5, least privilege).
    """

    sanitizers: dict[str, Sanitizer] = field(default_factory=dict)

    def add(self, s: Sanitizer) -> "SanitizerRegistry":
        self.sanitizers[s.name] = s
        return self

    def get(self, name: str) -> Sanitizer | None:
        return self.sanitizers.get(name)


def default_registry(sandbox_root: str = "sandbox") -> SanitizerRegistry:
    """The sanitizer set the shipped scenarios use. Allow-lists are deliberately
    tiny: a declassifier is only as good as how narrow it is."""
    return (SanitizerRegistry()
            .add(EmailAllowlist(domains=("corp.example", "team.corp.example")))
            .add(SandboxPath(root=sandbox_root))
            .add(UrlAllowlist(hosts=("api.corp.example", "docs.corp.example")))
            .add(NumericRange(low=0.0, high=500.0))
            .add(EnumValue(allowed=("summary", "report", "invoice")))
            .add(NoConfidentialLeak()))
