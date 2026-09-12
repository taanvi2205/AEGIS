"""Corpus loading and validation (§6).

The corpus is plain JSON so it diffs like code. Loading validates the pairing
rule that the evaluation depends on: every attack scenario names a benign twin
that exists, and vice versa. A corpus that fails validation raises rather than
being partially loaded - a silently half-loaded corpus would produce metrics that
look fine and mean nothing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .tools.manifests import TOOL_MANIFESTS

FAMILIES = ("indirect_injection", "tool_argument_injection", "multi_step_chain")
DEFAULT_PATH = Path("corpus/scenarios.json")


@dataclass
class Scenario:
    id: str
    family: str
    kind: str              # "attack" | "benign"
    expected: str          # "block" | "allow"
    paired_with: str
    description: str
    task: str
    plan: list[dict]
    world: dict[str, Any] = field(default_factory=dict)
    egress_budget: int = 1

    @property
    def documents(self) -> dict[str, tuple[str, bool]]:
        return {k: (v["text"], bool(v.get("confidential")))
                for k, v in self.world.get("documents", {}).items()}

    @property
    def files(self) -> dict[str, tuple[str, bool]]:
        return {k: (v["text"], bool(v.get("confidential")))
                for k, v in self.world.get("files", {}).items()}


class CorpusError(ValueError):
    """Raised when the corpus violates a §6 rule."""


def load(path: str | Path = DEFAULT_PATH) -> list[Scenario]:
    """Load and validate the corpus. Raises CorpusError on any violation."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    scenarios = [Scenario(
        id=s["id"], family=s["family"], kind=s["kind"], expected=s["expected"],
        paired_with=s["paired_with"], description=s["description"], task=s["task"],
        plan=s["plan"], world=s.get("world", {}), egress_budget=int(s.get("egress_budget", 1)),
    ) for s in raw["scenarios"]]
    validate(scenarios)
    return scenarios


def validate(scenarios: list[Scenario]) -> None:
    """Enforce the corpus rules: known families, valid expectations, symmetric
    pairing, declared tools, and at least one attack goal / task requirement."""
    by_id = {s.id: s for s in scenarios}
    if len(by_id) != len(scenarios):
        raise CorpusError("duplicate scenario ids in corpus")

    for s in scenarios:
        if s.family not in FAMILIES:
            raise CorpusError(f"{s.id}: unknown family {s.family!r}; known: {FAMILIES}")
        if s.kind not in ("attack", "benign"):
            raise CorpusError(f"{s.id}: kind must be 'attack' or 'benign'")
        if s.expected not in ("block", "allow"):
            raise CorpusError(f"{s.id}: expected must be 'block' or 'allow'")
        twin = by_id.get(s.paired_with)
        if twin is None:
            raise CorpusError(f"{s.id}: paired_with {s.paired_with!r} does not exist (§6)")
        if twin.paired_with != s.id:
            raise CorpusError(f"{s.id} and {twin.id} are not mutually paired (§6)")
        if twin.kind == s.kind:
            raise CorpusError(f"{s.id}: paired scenario {twin.id} must be the opposite kind")

        for step in s.plan:
            if step["tool"] not in TOOL_MANIFESTS:
                raise CorpusError(f"{s.id}: step calls undeclared tool {step['tool']!r}")

        if s.kind == "attack" and not any(st.get("attack_goal") for st in s.plan):
            raise CorpusError(f"{s.id}: attack scenario has no step marked attack_goal")
        if s.kind == "benign" and not any(st.get("required_for_task") for st in s.plan):
            raise CorpusError(f"{s.id}: benign scenario has no step marked required_for_task")
