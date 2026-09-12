"""The checkpoint - the mandatory interceptor between planning and execution (§3).

Every tool call the agent produces passes through `Checkpoint.evaluate` before it
can reach the mocked tool layer. There is no second path, no debug bypass and no
"trusted mode" flag; `aegis.agent.loop` calls the tool world only via a decision
object returned from here (tests/test_no_bypass.py asserts this).

Layer order and attribution
---------------------------
1. MANIFEST     - is this tool in scope, are its arguments declared? (deterministic)
2. PROVENANCE   - can each control-plane argument be attributed to trusted or
                  sanitized data? (deterministic)
3. TRAJECTORY   - does this call, in sequence, violate an invariant? (deterministic)

The Layer-1 input classifier does not appear in that list on purpose. An in-band
content filter acts at *ingestion*: content it flags is quarantined and never
enters the agent's context, which is how such filters actually deploy. So it is
applied in `Checkpoint.ingest`, and a block attributed to INPUT_CLASSIFIER always
means "the payload never reached the model", never "the policy engine consulted a
classifier". No LLM or learned component is consulted anywhere in `evaluate`
(§3, deterministic policy layer).

Fail-closed behaviour
---------------------
Any exception raised while evaluating a call is caught and converted into a BLOCK
attributed to the layer that was running. There is no code path in this file that
returns ALLOW as a consequence of an error.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..audit import AuditLog
from ..core import (Content, Decision, Label, Layer, ProvenanceFinding,
                    SanitizationRecord, ToolCall, Verdict)
from ..tools.manifests import TOOL_MANIFESTS, AgentManifest, DEFAULT_AGENT_MANIFEST
from .classifier import Guard, GuardResult
from .provenance import TaintStore
from .sanitizers import SanitizerContext, SanitizerRegistry, default_registry
from .trajectory import ExecutedCall, Invariant, SessionState, default_invariants


@dataclass(frozen=True)
class DefenseConfig:
    """Which layers are live. The evaluation runs the same scenarios under each
    of these and never averages across them (§7)."""

    name: str
    input_classifier: bool = False
    manifest: bool = False
    provenance: bool = False
    trajectory: bool = False


CONFIGS: dict[str, DefenseConfig] = {
    # No defense at all: the ungoverned agent, for measuring attack feasibility.
    "none": DefenseConfig("none"),
    # In-band only: the current-generation baseline (§2.1).
    "input_only": DefenseConfig("input_only", input_classifier=True),
    # Out-of-band only: this project's mechanism, with no classifier at all, so
    # its contribution can be read without the classifier confounding it.
    "out_of_band": DefenseConfig("out_of_band", manifest=True, provenance=True, trajectory=True),
    # Everything together.
    "full": DefenseConfig("full", input_classifier=True, manifest=True,
                          provenance=True, trajectory=True),
}


@dataclass
class Checkpoint:
    """One checkpoint per agent session."""

    config: DefenseConfig
    guard: Guard
    audit: AuditLog
    taint: TaintStore = field(default_factory=TaintStore)
    sanitizers: SanitizerRegistry = field(default_factory=default_registry)
    invariants: list[Invariant] = field(default_factory=default_invariants)
    agent_manifest: AgentManifest = field(
        default_factory=lambda: DEFAULT_AGENT_MANIFEST)
    state: SessionState = field(default_factory=SessionState)
    scenario_id: str = ""
    quarantined: list[str] = field(default_factory=list)
    quarantined_sources: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.state.egress_budget = self.agent_manifest.egress_budget

    # -- ingestion -------------------------------------------------------
    def ingest(self, content: Content, step: int = 0) -> tuple[bool, GuardResult | None]:
        """Admit content into the agent's context, or quarantine it.

        What it checks: untrusted content is screened by the Layer-1 guard when
        that layer is enabled. Trusted content (the user's own task) is not
        screened - filtering the user's own instruction is not what an injection
        filter is for.

        On failure: `guard.screen` never raises; an erroring guard returns
        flagged=True, so content is quarantined rather than admitted (fail closed).

        Returns (admitted, guard_result).
        """
        result: GuardResult | None = None
        if self.config.input_classifier and content.label is not Label.TRUSTED:
            result = self.guard.screen(content.text)
            self.audit.emit("classifier", content_id=content.content_id,
                            flagged=result.flagged, score=result.score,
                            matched=result.matched, backend=result.backend,
                            error=result.error, scenario_id=self.scenario_id,
                            defense_config=self.config.name)
            if result.flagged:
                self.quarantined.append(content.content_id)
                self.quarantined_sources.append(content.source_ref)
                self.audit.emit("decision", call_id="-", step=step, tool="<ingest>",
                                verdict=Verdict.BLOCK.value, layer=Layer.INPUT_CLASSIFIER.value,
                                reason=(f"content from {content.source_ref} quarantined by "
                                        f"{result.backend} (score {result.score}, "
                                        f"signals: {result.matched or 'n/a'})"),
                                scenario_id=self.scenario_id,
                                defense_config=self.config.name,
                                classifier_score=result.score)
                return False, result

        self.taint.ingest(content)
        if content.label is Label.TRUSTED:
            self.state.record_trusted_destinations(content.text)
        else:
            self.state.untrusted_ingest_steps.append(step)
        if content.confidential:
            self.state.confidential_reads.append((step, content.source_ref))
        self.audit.emit("ingest", scenario_id=self.scenario_id,
                        defense_config=self.config.name, **content.to_json())
        return True, result

    # -- evaluation ------------------------------------------------------
    def evaluate(self, call: ToolCall) -> Decision:
        """Decide whether one tool call may execute. Never raises."""
        self.audit.emit("tool_request", scenario_id=self.scenario_id,
                        defense_config=self.config.name, tool=call.tool,
                        args=call.args, step=call.step, call_id=call.call_id)
        try:
            decision = self._evaluate(call)
        except Exception as exc:                            # noqa: BLE001 - fail closed
            decision = self._decide(call, Verdict.BLOCK, Layer.MANIFEST,
                                    f"checkpoint raised {type(exc).__name__}: {exc}; failing closed")
        self.audit.emit("decision", scenario_id=self.scenario_id,
                        defense_config=self.config.name, **{
                            k: v for k, v in decision.to_json().items()
                            if k not in ("scenario_id", "defense_config")})
        if decision.verdict is Verdict.BLOCK:
            self.state.blocked.append(decision)
            tool = TOOL_MANIFESTS.get(call.tool)
            if tool is not None:
                from .trajectory import BlockedCallRetry
                self.state.blocked_shapes[BlockedCallRetry._shape(call.tool, call, tool)] = decision
        return decision

    def _decide(self, call: ToolCall, verdict: Verdict, layer: Layer, reason: str,
                findings: list[ProvenanceFinding] | None = None,
                invariant: str | None = None) -> Decision:
        return Decision(call_id=call.call_id, step=call.step, tool=call.tool,
                        verdict=verdict, layer=layer, reason=reason,
                        scenario_id=self.scenario_id, defense_config=self.config.name,
                        findings=findings or [], invariant=invariant)

    def _evaluate(self, call: ToolCall) -> Decision:
        # -- Layer: manifest ---------------------------------------------
        tool = TOOL_MANIFESTS.get(call.tool)
        if self.config.manifest:
            ok, why = self.agent_manifest.permits(call.tool)
            if not ok:
                return self._decide(call, Verdict.BLOCK, Layer.MANIFEST, why)
            ok, why = tool.validate(call.args)
            if not ok:
                return self._decide(call, Verdict.BLOCK, Layer.MANIFEST, why)
        elif tool is None:
            # Even with policy disabled, an undeclared tool cannot be dispatched.
            return self._decide(call, Verdict.BLOCK, Layer.MANIFEST,
                                f"tool {call.tool!r} is not a declared tool")

        findings: list[ProvenanceFinding] = []

        # -- Layer: provenance -------------------------------------------
        if self.config.provenance:
            findings = self._trace_arguments(call, tool)
            for f in findings:
                if f.arg_name not in tool.critical_args:
                    continue    # data-plane argument: traced and logged, not gated (D-05)
                if f.label is Label.SANITIZED:
                    continue
                if f.label is Label.TRUSTED and f.origin_known:
                    continue
                if f.origin_known:
                    reason = (f"control-plane argument {f.arg_name!r} traces to untrusted "
                              f"content from {f.matched_source} (matched by {f.tier} tier, "
                              f"score {f.score:.2f}) and no declared sanitizer cleared it")
                elif f.too_short:
                    reason = (f"control-plane argument {f.arg_name!r} is too short to attribute "
                              f"to any source and is not sanitized; denying rather than guessing")
                else:
                    reason = (f"control-plane argument {f.arg_name!r} cannot be attributed to the "
                              f"user's task or any sanitizer; it appears in no trusted content")
                return self._decide(call, Verdict.BLOCK, Layer.PROVENANCE, reason, findings)

        # -- Layer: trajectory -------------------------------------------
        if self.config.trajectory:
            for inv in self.invariants:
                violated, why = inv.evaluate(self.state, call, tool, findings)
                self.audit.emit("trajectory", scenario_id=self.scenario_id,
                                defense_config=self.config.name, invariant=inv.name,
                                violated=violated, step=call.step)
                if violated:
                    return self._decide(call, Verdict.BLOCK, Layer.TRAJECTORY, why,
                                        findings, invariant=inv.name)

        return self._decide(call, Verdict.ALLOW, Layer.NONE, "no layer objected", findings)

    def _sanitizer_context(self) -> SanitizerContext:
        """Session facts the declassifier consults: what confidential content has
        been read, and what non-confidential content it can be contrasted with."""
        return SanitizerContext(
            confidential_texts=tuple(c.text for c in self.taint.contents if c.confidential),
            public_texts=tuple(c.text for c in self.taint.contents if not c.confidential),
        )

    def _trace_arguments(self, call: ToolCall, tool) -> list[ProvenanceFinding]:
        """Run declared sanitizers, then attribute every argument value.

        A sanitizer only runs where the tool's manifest names one for that
        argument; there is no generic declassification path (§4 Rule 5). A
        sanitizer that passes clears taint for that exact value only.
        """
        for arg_name, value in call.string_args():
            san_name = tool.sanitizers.get(arg_name.split(".")[0].split("[")[0])
            if not san_name:
                continue
            san = self.sanitizers.get(san_name)
            if san is None:
                # A manifest naming a sanitizer that does not exist is a
                # configuration error; treat it as no declassification available.
                self.audit.emit("sanitizer", scenario_id=self.scenario_id,
                                defense_config=self.config.name, sanitizer=san_name,
                                passed=False, checked="sanitizer not registered; failing closed",
                                rule="n/a", step=call.step)
                continue
            rec: SanitizationRecord = san.run(value, call.step, self._sanitizer_context())
            self.state.sanitizer_runs.append((call.step, rec))
            self.taint.mark_sanitized(value, rec)
            self.audit.emit("sanitizer", scenario_id=self.scenario_id,
                            defense_config=self.config.name, **rec.to_json())

        findings = [self.taint.trace(n, v) for n, v in call.string_args()]
        for f in findings:
            self.audit.emit("provenance", scenario_id=self.scenario_id,
                            defense_config=self.config.name, arg_name=f.arg_name,
                            label=f.label.value, matched_source=f.matched_source,
                            tier=f.tier, score=f.score, origin_known=f.origin_known,
                            sanitizer=f.sanitizer, step=call.step)
        return findings

    # -- execution bookkeeping -------------------------------------------
    def record_execution(self, call: ToolCall, result: dict) -> None:
        """Record that an allowed call actually ran, so the trajectory layer sees
        the session's real history."""
        tool = TOOL_MANIFESTS[call.tool]
        read_conf = bool(result.get("confidential"))
        self.state.executed.append(ExecutedCall(call.step, call.tool, dict(call.args),
                                                tool.egress, tool.destructive, read_conf))
        self.audit.emit("tool_executed", scenario_id=self.scenario_id,
                        defense_config=self.config.name, tool=call.tool,
                        step=call.step, result={k: v for k, v in result.items() if k != "content"})
