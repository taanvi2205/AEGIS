"""The minimal agent loop (§3: custom loop, not a framework).

The loop is deliberately small enough to read in one sitting, because the whole
argument of the project rests on there being exactly one path from a planned tool
call to an executed one, and that path going through the checkpoint.

Sequence per step:
    plan step -> checkpoint.evaluate -> (allowed) world.invoke -> ingest any
    returned content as UNTRUSTED -> record execution

A blocked step does not abort the session: the agent continues with the rest of
its plan, which is what a real agent does after a refusal, and which is what
makes INV-5 (retry of a denied call) meaningful.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..audit import AuditLog
from ..checkpoint.checkpoint import Checkpoint
from ..core import Content, Label, ToolCall, Verdict, digest
from ..tools.mock import ToolWorld
from .backends import PlannedStep, ScriptedBackend


@dataclass
class StepOutcome:
    step: int
    tool: str
    verdict: str
    layer: str
    reason: str
    executed: bool
    attack_goal: bool
    required_for_task: bool
    skipped_reason: str = ""


@dataclass
class SessionResult:
    scenario_id: str
    defense_config: str
    outcomes: list[StepOutcome] = field(default_factory=list)
    attack_succeeded: bool = False
    task_completed: bool = False
    blocked_by: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "defense_config": self.defense_config,
            "attack_succeeded": self.attack_succeeded,
            "task_completed": self.task_completed,
            "blocked_by": self.blocked_by,
            "outcomes": [o.__dict__ for o in self.outcomes],
        }


@dataclass
class Agent:
    """Runs one scenario under one defense configuration."""

    checkpoint: Checkpoint
    world: ToolWorld
    audit: AuditLog
    backend: Any = field(default_factory=ScriptedBackend)

    def run(self, scenario_id: str, task: str, steps: list[dict]) -> SessionResult:
        self.audit.emit("session_start", scenario_id=scenario_id,
                        defense_config=self.checkpoint.config.name, task=task)
        result = SessionResult(scenario_id, self.checkpoint.config.name)

        # The user's own task is the trust anchor for the whole session.
        self.checkpoint.ingest(Content(
            content_id="task", origin="user_task", source_ref="user",
            text=task, label=Label.TRUSTED), step=0)

        plan: list[PlannedStep] = self.backend.plan(task, steps)
        for i, ps in enumerate(plan, start=1):
            # A step induced by a document that never reached the agent cannot
            # happen. This is how a quarantining input filter actually prevents
            # an action: the model never saw the instruction.
            quarantined = set(self.checkpoint.quarantined) | set(self.checkpoint.quarantined_sources)
            if ps.caused_by and ps.caused_by in quarantined:
                result.outcomes.append(StepOutcome(
                    i, ps.tool, "not_attempted", "input_classifier",
                    f"payload from {ps.caused_by} was quarantined before it reached the model",
                    False, ps.attack_goal, ps.required_for_task,
                    skipped_reason="payload quarantined"))
                continue

            # A step whose output depends on content the filter removed cannot be
            # performed correctly. Recording this is what makes the cost of
            # over-blocking visible in the task-completion metric rather than
            # hidden (§2 item 4).
            missing = [n for n in ps.needs if n in quarantined]
            if missing:
                result.outcomes.append(StepOutcome(
                    i, ps.tool, "not_attempted", "input_classifier",
                    f"depends on content from {missing[0]}, which was quarantined; "
                    f"the agent cannot produce this result",
                    False, ps.attack_goal, ps.required_for_task,
                    skipped_reason="required input quarantined"))
                continue

            call = ToolCall(tool=ps.tool, args=ps.args, step=i)
            decision = self.checkpoint.evaluate(call)
            executed = False
            if decision.verdict is Verdict.ALLOW:
                res = self.world.invoke(call.tool, call.args)
                executed = bool(res.get("ok", True))
                self.checkpoint.record_execution(call, res)
                if res.get("content"):
                    # Every tool output is untrusted, without exception (§2 item 1).
                    cid = f"out{i}-{digest(res['source_ref'])[:6]}"
                    admitted, _ = self.checkpoint.ingest(Content(
                        content_id=cid, origin="tool_output",
                        source_ref=res.get("source_ref", call.tool),
                        text=res["content"], label=Label.UNTRUSTED,
                        confidential=bool(res.get("confidential")), step=i), step=i)
                    if not admitted:
                        # Quarantined mid-session: any later step attributed to
                        # this content will be skipped by the check above.
                        pass
            else:
                result.blocked_by.append(decision.layer.value)

            result.outcomes.append(StepOutcome(
                i, ps.tool, decision.verdict.value, decision.layer.value,
                decision.reason, executed, ps.attack_goal, ps.required_for_task))

        result.attack_succeeded = any(o.executed and o.attack_goal for o in result.outcomes)
        required = [o for o in result.outcomes if o.required_for_task]
        result.task_completed = bool(required) and all(o.executed for o in required)
        self.audit.emit("session_end", scenario_id=scenario_id,
                        defense_config=self.checkpoint.config.name,
                        attack_succeeded=result.attack_succeeded,
                        task_completed=result.task_completed)
        return result
