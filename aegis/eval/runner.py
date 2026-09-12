"""Runs scenarios under a defense configuration and collects results.

One `run_scenario` call = one fresh session: a new taint store, a new session
state, a new sandbox world. Nothing carries over between scenarios, so a result
can never depend on the order scenarios happened to run in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..agent.backends import ScriptedBackend
from ..agent.loop import Agent, SessionResult
from ..audit import AuditLog
from ..checkpoint.checkpoint import CONFIGS, Checkpoint, DefenseConfig
from ..checkpoint.classifier import Guard, build_guard
from ..checkpoint.provenance import MatcherConfig, TaintStore
from ..checkpoint.sanitizers import default_registry
from ..checkpoint.trajectory import SessionState, default_invariants
from ..corpus import Scenario
from ..tools.manifests import DEFAULT_AGENT_MANIFEST, AgentManifest
from ..tools.mock import ToolWorld

SANDBOX = Path("sandbox")


def run_scenario(scenario: Scenario, config: DefenseConfig, guard: Guard,
                 audit: AuditLog, matcher: MatcherConfig | None = None,
                 backend=None) -> SessionResult:
    """Run one scenario once, under one configuration."""
    world = ToolWorld(SANDBOX, documents=dict(scenario.documents), files=dict(scenario.files))
    manifest = AgentManifest(allowed_tools=DEFAULT_AGENT_MANIFEST.allowed_tools,
                             egress_budget=scenario.egress_budget)
    checkpoint = Checkpoint(
        config=config, guard=guard, audit=audit,
        taint=TaintStore(config=matcher or MatcherConfig()),
        sanitizers=default_registry(str(SANDBOX)),
        invariants=default_invariants(),
        agent_manifest=manifest, state=SessionState(egress_budget=scenario.egress_budget),
        scenario_id=scenario.id,
    )
    agent = Agent(checkpoint=checkpoint, world=world, audit=audit,
                  backend=backend or ScriptedBackend())
    return agent.run(scenario.id, scenario.task, scenario.plan)


@dataclass
class RunSet:
    """All results for one configuration over the whole corpus."""

    config: str
    results: list[SessionResult] = field(default_factory=list)

    def by_kind(self, scenarios: dict[str, Scenario], kind: str) -> list[SessionResult]:
        return [r for r in self.results if scenarios[r.scenario_id].kind == kind]


def run_corpus(scenarios: list[Scenario], config_names: list[str], audit: AuditLog,
               guard: Guard | None = None, matcher: MatcherConfig | None = None) -> dict[str, RunSet]:
    """Run every scenario under every named configuration."""
    guard = guard or build_guard("heuristic")
    out: dict[str, RunSet] = {}
    for name in config_names:
        cfg = CONFIGS[name]
        rs = RunSet(name)
        for sc in scenarios:
            rs.results.append(run_scenario(sc, cfg, guard, audit, matcher))
        out[name] = rs
    return out
