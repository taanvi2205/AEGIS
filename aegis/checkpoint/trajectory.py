"""Layer 3 - trajectory invariants (§2 item 2).

What this layer checks
----------------------
Properties of the *sequence* of tool calls in a session, not of any single call.
The attacks this catches are the ones where every individual call is legitimate
and only the order is hostile: read a confidential file (allowed), then send an
email (allowed) - an exfiltration chain assembled from two permitted actions.

Why it is separate from the per-call layers
-------------------------------------------
A manifest check and a provenance check both answer "may this call happen?" in
isolation. Neither can express "not after that other call." Prior action-level
systems (CaMeL arXiv:2503.18813, FIDES arXiv:2505.23643, Progent arXiv:2504.11703)
enforce per-call policy; sequence-level invariants are the mechanism this project
adds.

Fail-closed behaviour
---------------------
An invariant that raises is treated as violated, and the call is denied. Five
invariants ship and the list is deliberately capped - this is a demonstration
that the abstraction works, not a policy library (§2 item 2).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..core import Decision, Label, ProvenanceFinding, SanitizationRecord, ToolCall, Verdict

_DEST = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|https?://[^\s\"'>]+")
# Sentence punctuation clings to a URL at the end of a sentence ("...post to
# https://api.example/metrics."). Stripping it is what makes a destination the
# user really named compare equal to the one the agent emits.
_DEST_TRIM = ".,;:!?)]}'\""


def _destinations(text: str) -> set[str]:
    return {m.rstrip(_DEST_TRIM) for m in _DEST.findall(text.lower())}


@dataclass
class ExecutedCall:
    step: int
    tool: str
    args: dict
    egress: bool
    destructive: bool
    read_confidential: bool


@dataclass
class SessionState:
    """Everything the invariants are allowed to consult. Deterministic and
    append-only: no LLM is ever queried here (§3)."""

    executed: list[ExecutedCall] = field(default_factory=list)
    sanitizer_runs: list[tuple[int, SanitizationRecord]] = field(default_factory=list)
    confidential_reads: list[tuple[int, str]] = field(default_factory=list)
    untrusted_ingest_steps: list[int] = field(default_factory=list)
    blocked: list[Decision] = field(default_factory=list)
    blocked_shapes: dict[str, Decision] = field(default_factory=dict)
    trusted_destinations: set[str] = field(default_factory=set)
    egress_budget: int = 1

    @property
    def egress_count(self) -> int:
        return sum(1 for c in self.executed if c.egress)

    def last_confidential_read_step(self) -> int | None:
        return self.confidential_reads[-1][0] if self.confidential_reads else None

    def declassified_since(self, step: int) -> bool:
        """True if a *declassifying* sanitizer - one that inspects the outbound
        payload itself - has passed at or after `step`.

        A shape check such as an address allow-list does not count: constraining
        where data goes says nothing about whether the data is still confidential.
        """
        return any(s >= step and rec.passed and rec.declassifies
                   for s, rec in self.sanitizer_runs)

    def record_trusted_destinations(self, task_text: str) -> None:
        """Destinations the user themselves named in the original task. Extracted
        from TRUSTED content only - this set is never widened by anything the
        agent later reads."""
        self.trusted_destinations |= _destinations(task_text)


@dataclass
class Invariant:
    name: str
    describes: str

    def check(self, state: SessionState, call: ToolCall, tool, findings: list[ProvenanceFinding]) -> tuple[bool, str]:
        raise NotImplementedError

    def evaluate(self, state, call, tool, findings) -> tuple[bool, str]:
        """Run the invariant, never raising. An erroring invariant reports a
        violation, so a bug in a rule denies rather than permits."""
        try:
            return self.check(state, call, tool, findings)
        except Exception as exc:                            # noqa: BLE001 - fail closed
            return True, f"invariant {self.name} raised {type(exc).__name__}; failing closed"


class ConfidentialThenEgress(Invariant):
    """INV-1 (required by §2): once any call has read confidential data, no
    egress-capable call may execute until a sanitizer has passed in between.

    On violation: the egress call is denied. Declassify the outbound value with
    a named sanitizer to proceed - that is the intended, documented path, not a
    workaround.
    """

    def __init__(self) -> None:
        super().__init__("INV-1:confidential_then_egress",
                         "egress after a confidential read requires an intervening sanitizer")

    def check(self, state, call, tool, findings):
        if not tool.egress:
            return False, ""
        last = state.last_confidential_read_step()
        if last is None:
            return False, ""
        if state.declassified_since(last):
            return False, ""
        src = state.confidential_reads[-1][1]
        return True, (f"confidential data read at step {last} from {src}; no declassifier "
                      f"has cleared the outbound payload since, so egress via {call.tool} "
                      f"would be an undeclassified release")


class UntrustedThenDestructive(Invariant):
    """INV-2: after untrusted content enters the session, a destructive call may
    only run if every security-critical argument is TRUSTED or SANITIZED.

    On violation: the destructive call is denied. Unlike the provenance layer,
    this fires even when an argument is merely *unattributable*, because a
    destructive action taken on a value nobody can trace is not recoverable.
    """

    def __init__(self) -> None:
        super().__init__("INV-2:untrusted_then_destructive",
                         "destructive calls after untrusted ingest need fully attributed arguments")

    def check(self, state, call, tool, findings):
        if not tool.destructive or not state.untrusted_ingest_steps:
            return False, ""
        bad = [f for f in findings
               if f.arg_name in tool.critical_args and f.label is not Label.SANITIZED
               and not (f.label is Label.TRUSTED and f.origin_known)]
        if bad:
            names = ", ".join(sorted(f.arg_name for f in bad))
            return True, (f"destructive tool {call.tool} after untrusted ingest at step "
                          f"{state.untrusted_ingest_steps[0]}; argument(s) {names} are not "
                          f"provably trusted or sanitized")
        return False, ""


class EgressBudget(Invariant):
    """INV-3: a session may perform at most `egress_budget` egress calls.

    On violation: the call over budget is denied. Catches the pattern where the
    agent completes the user's real request and *then* performs a second,
    attacker-directed send - each call individually legitimate.
    """

    def __init__(self) -> None:
        super().__init__("INV-3:egress_budget",
                         "egress calls per session may not exceed the declared budget")

    def check(self, state, call, tool, findings):
        if not tool.egress:
            return False, ""
        if state.egress_count >= state.egress_budget:
            return True, (f"session egress budget of {state.egress_budget} already spent "
                          f"({state.egress_count} egress call(s) executed); {call.tool} would exceed it")
        return False, ""


class EgressDestinationScope(Invariant):
    """INV-4: after a confidential read, egress destinations must be ones the
    user named in the original (trusted) task.

    On violation: the call is denied. This is sequence-level rather than
    per-call: sending to a novel address is perfectly fine in a session that
    never touched confidential data, and forbidden in one that did.
    """

    def __init__(self) -> None:
        super().__init__("INV-4:egress_destination_scope",
                         "post-confidential-read egress may only target user-named destinations")

    def check(self, state, call, tool, findings):
        if not tool.egress or not state.confidential_reads:
            return False, ""
        dests: set[str] = set()
        for name, value in call.string_args():
            if name in tool.critical_args:
                dests |= _destinations(str(value))
        novel = dests - state.trusted_destinations
        if novel:
            return True, (f"destination(s) {sorted(novel)} were never named in the user's task "
                          f"(user named {sorted(state.trusted_destinations) or 'none'}), and "
                          f"confidential data was read at step {state.last_confidential_read_step()}")
        return False, ""


class BlockedCallRetry(Invariant):
    """INV-5: once a call has been denied, a cosmetically-altered retry of the
    same call is denied without re-evaluation.

    On violation: the retry is denied. Models routinely re-attempt a refused
    action with the payload lightly rewritten; without this, an attacker gets
    unlimited attempts against the probabilistic layer inside one session.
    """

    def __init__(self) -> None:
        super().__init__("INV-5:blocked_call_retry",
                         "a denied call may not be retried in the same session")

    @staticmethod
    def _shape(tool_name: str, call: ToolCall, tool) -> str:
        from .. import text as T
        crit = sorted((n, T.squeeze(str(v))) for n, v in call.string_args()
                      if n in tool.critical_args)
        return f"{tool_name}|{crit}"

    def check(self, state, call, tool, findings):
        prior = state.blocked_shapes.get(self._shape(call.tool, call, tool))
        if prior is not None:
            return True, (f"an equivalent call was already denied at step {prior.step} by "
                          f"{prior.layer.value}; retrying a denied action within the same "
                          f"session is not permitted")
        return False, ""


def default_invariants() -> list[Invariant]:
    """The shipped invariant set. Capped at five by §2 item 2."""
    return [ConfidentialThenEgress(), UntrustedThenDestructive(), EgressBudget(),
            EgressDestinationScope(), BlockedCallRetry()]
