"""AEGIS command line.

    python -m aegis demo        four-beat live demo, one attack per layer
    python -m aegis eval        paired corpus under every defense configuration
    python -m aegis sweep       obfuscation sweep + plot
    python -m aegis redteam     adaptive red-team loop + plot
    python -m aegis report      everything, written to runs/ as JSON, SVG and Markdown
    python -m aegis policy      print the shipped manifests, sanitizers and invariants

The terminal output is the demo (§8): request, tag assignment, layer checks,
decision and reason, in that order, for every call.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import AuditLog
from .checkpoint.checkpoint import CONFIGS
from .checkpoint.classifier import GuardUnavailable, build_guard
from .checkpoint.sanitizers import default_registry
from .checkpoint.trajectory import default_invariants
from .corpus import load
from .eval.metrics import compute, render_table
from .eval.plots import degradation_curve, sweep_curve
from .eval.runner import run_corpus, run_scenario
from .eval.sweep import LEVEL_NAMES, TIER_SETS, render as render_sweep, run_sweep
from .redteam.loop import build_scenario, render as render_rt, run as run_redteam, save as save_rt
from .tools.manifests import TOOL_MANIFESTS

RUNS = Path("runs")
ALL_CONFIGS = ["none", "input_only", "out_of_band", "full"]


def _guard(name: str):
    """Build the Layer-1 backend, reporting clearly if it is unavailable rather
    than silently substituting a weaker one."""
    try:
        return build_guard(name)
    except GuardUnavailable as exc:
        print(f"guard backend {name!r} unavailable: {exc}", file=sys.stderr)
        raise SystemExit(2)


def cmd_demo(args) -> None:
    scenarios = {s.id: s for s in load(args.corpus)}
    guard = _guard(args.guard)
    beats = [
        ("1. Overt injection - the in-band classifier is enough",
         "atk-a1", ["input_only"]),
        ("2. Same attack, phrased as policy prose - the classifier misses it, "
         "provenance does not", "atk-a2", ["input_only", "full"]),
        ("3. Two individually legal calls forming an exfiltration chain - both "
         "per-call layers pass, the trajectory invariant does not",
         "atk-c1", ["out_of_band"]),
        ("4. The benign twin of beat 3, released through the declassifier - "
         "the same layers allow it", "ben-c1", ["out_of_band"]),
    ]
    def beat(title: str, description: str, scenario, configs: list[str]) -> None:
        if args.pause:
            try:
                input("\n            [enter] for the next beat ")
            except EOFError:
                pass
        print("\n" + "═" * 78)
        print(title)
        print(f"scenario {scenario.id}: {description}")
        print("═" * 78)
        for cname in configs:
            audit = AuditLog(echo=True, delay=args.delay)
            res = run_scenario(scenario, CONFIGS[cname], guard, audit)
            verdict = "ATTACK SUCCEEDED" if res.attack_succeeded else "attack blocked"
            if scenario.kind == "benign":
                verdict = "task completed" if res.task_completed else "TASK BLOCKED"
            print(f"   → [{cname}] {verdict}\n")

    for title, sid, configs in beats:
        beat(title, scenarios[sid].description, scenarios[sid], configs)

    # Beat 5 uses the payload the adaptive loop actually evolved, so the demo
    # shows a real evader rather than a hand-written "hard" example.
    rt = run_redteam(rounds=args.rounds, population=8, target="input_only",
                     configs=["input_only", "out_of_band"], guard=guard)
    evolved = rt.rounds[-1].best_payload
    beat(f"5. The payload the red-team loop evolved after {len(rt.rounds)} rounds - "
         f"the classifier no longer sees it, the out-of-band layers are unmoved",
         f"evolved by operators: {', '.join(rt.rounds[-1].best_ops)}",
         build_scenario(evolved, 0), ["input_only", "out_of_band"])
    print(f"   evolved payload: {evolved[:200]}")
    print(f"   guard block rate over the run: "
          f"{1 - rt.rounds[0].asr['input_only']:.0%} → {1 - rt.rounds[-1].asr['input_only']:.0%}")


def cmd_eval(args) -> None:
    scenarios = load(args.corpus)
    by_id = {s.id: s for s in scenarios}
    audit = AuditLog(RUNS / "eval.jsonl", echo=args.verbose)
    runs = run_corpus(scenarios, args.configs, audit, guard=_guard(args.guard))
    rows = [compute(n, rs.results, by_id) for n, rs in runs.items()]
    print(render_table(rows))
    out = {
        "metrics": [m.to_json() for m in rows],
        "per_scenario": {n: [r.to_json() for r in rs.results] for n, rs in runs.items()},
    }
    (RUNS / "eval.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\nwrote {RUNS / 'eval.json'} and {RUNS / 'eval.jsonl'}")
    audit.close()


def cmd_sweep(args) -> None:
    cells = run_sweep()
    print(render_sweep(cells))
    (RUNS / "sweep.json").write_text(
        json.dumps([c.to_json() for c in cells], indent=2), encoding="utf-8")
    p = sweep_curve(cells, list(TIER_SETS), LEVEL_NAMES, RUNS / "provenance_sweep.svg")
    print(f"\nwrote {RUNS / 'sweep.json'} and {p}")


def cmd_redteam(args) -> None:
    res = run_redteam(rounds=args.rounds, population=args.population, seed=args.seed,
                      target=args.target, configs=args.configs, guard=_guard(args.guard))
    print(render_rt(res))
    save_rt(res, RUNS / f"redteam_{args.target}.json")
    p = degradation_curve(res, RUNS / f"redteam_{args.target}.svg")
    print(f"\nwrote {RUNS / f'redteam_{args.target}.json'} and {p}")


def cmd_try(args) -> None:
    from .interactive import run
    try:
        run(defense=args.defense, guard_name=args.guard)
    except KeyboardInterrupt:
        print("\n")


def cmd_policy(args) -> None:
    print("Tool manifests (least privilege, §4 Rule 5)")
    print("-" * 78)
    for m in TOOL_MANIFESTS.values():
        flags = ",".join(f for f, on in (("egress", m.egress), ("destructive", m.destructive),
                                         ("reads", m.reads_resources)) if on) or "-"
        print(f"  {m.name:<14} args={list(m.args)}")
        print(f"  {'':<14} control-plane={list(m.critical_args)}  flags={flags}")
        print(f"  {'':<14} sanitizers={m.sanitizers}")
    print("\nSanitizers (§2 item 3)")
    print("-" * 78)
    for s in default_registry().sanitizers.values():
        kind = "declassifier" if s.declassifies else "shape check"
        print(f"  {s.name:<22} [{kind}] {s.rule}")
    print("\nTrajectory invariants (§2 item 2)")
    print("-" * 78)
    for i in default_invariants():
        print(f"  {i.name:<38} {i.describes}")


def cmd_report(args) -> None:
    from .report import write_report
    path = write_report(args)
    print(f"\nwrote {path}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="aegis", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--guard", default="heuristic",
                   help="Layer-1 backend: heuristic (shipped) or hf (needs transformers)")
    p.add_argument("--corpus", default="corpus/scenarios.json")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("demo", help="five-beat live demo")
    d.add_argument("--rounds", type=int, default=10,
                   help="red-team rounds used to evolve the beat-5 payload")
    d.add_argument("--pause", action="store_true",
                   help="wait for enter between beats (use when presenting)")
    d.add_argument("--delay", type=float, default=0.0,
                   help="seconds between trace lines, e.g. 0.12 (presentation pacing)")
    d.set_defaults(fn=cmd_demo)

    e = sub.add_parser("eval", help="paired corpus under every configuration")
    e.add_argument("--configs", nargs="+", default=ALL_CONFIGS, choices=list(CONFIGS))
    e.add_argument("-v", "--verbose", action="store_true", help="echo the full decision trace")
    e.set_defaults(fn=cmd_eval)

    sub.add_parser("sweep", help="obfuscation sweep").set_defaults(fn=cmd_sweep)

    r = sub.add_parser("redteam", help="adaptive red-team loop")
    r.add_argument("--rounds", type=int, default=15)
    r.add_argument("--population", type=int, default=8)
    r.add_argument("--seed", type=int, default=20260910)
    r.add_argument("--target", default="input_only", choices=list(CONFIGS))
    r.add_argument("--configs", nargs="+", default=ALL_CONFIGS, choices=list(CONFIGS))
    r.set_defaults(fn=cmd_redteam)

    t = sub.add_parser("try", help="interactive: type your own attack and watch it decide")
    t.add_argument("--defense", default="full", choices=list(CONFIGS))
    t.set_defaults(fn=cmd_try)

    sub.add_parser("policy", help="print manifests, sanitizers and invariants").set_defaults(fn=cmd_policy)

    rep = sub.add_parser("report", help="run everything and write runs/report.md")
    rep.add_argument("--rounds", type=int, default=15)
    rep.add_argument("--population", type=int, default=8)
    rep.add_argument("--seed", type=int, default=20260910)
    rep.set_defaults(fn=cmd_report)

    args = p.parse_args(argv)
    RUNS.mkdir(exist_ok=True)
    args.fn(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
