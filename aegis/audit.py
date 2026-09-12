"""Structured audit log.

Every tagged value, sanitizer invocation, invariant check and allow/block
decision lands here (§3 "everything is logged"). The JSONL stream is the
evaluation's only data source, and the rendered stream is the demo (§8), so both
are produced from the same event records - the terminal view can never drift
from what was actually recorded.
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


DIM, RED, GREEN, YELLOW, CYAN, BOLD = "2", "31", "32", "33", "36", "1"


@dataclass
class Event:
    kind: str
    data: dict[str, Any]
    ts: float = field(default_factory=time.time)

    def to_json(self) -> dict[str, Any]:
        return {"ts": self.ts, "kind": self.kind, **self.data}


class AuditLog:
    """Append-only event log for one process run.

    Failure behaviour: if the log file cannot be opened the run aborts rather
    than continuing unlogged - an enforcement decision that cannot be
    reconstructed afterwards is not an auditable decision (§3).
    """

    def __init__(self, path: str | Path | None = None, echo: bool = False,
                 delay: float = 0.0) -> None:
        """`delay` paces echoed lines for live presentation. It affects only the
        rendered stream - the recorded events and every decision are identical
        with or without it."""
        self.events: list[Event] = []
        self.echo = echo
        self.delay = delay
        self._fh = None
        if path is not None:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self._fh = p.open("a", encoding="utf-8")

    def emit(self, kind: str, **data: Any) -> Event:
        ev = Event(kind, data)
        self.events.append(ev)
        if self._fh is not None:
            self._fh.write(json.dumps(ev.to_json(), default=str) + "\n")
            self._fh.flush()
        if self.echo:
            line = self.render(ev)
            if line:
                print(line, flush=True)
                if self.delay:
                    time.sleep(self.delay)
        return ev

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def of_kind(self, kind: str) -> Iterator[Event]:
        return (e for e in self.events if e.kind == kind)

    # -- rendering -------------------------------------------------------
    @staticmethod
    def render(ev: Event) -> str:
        """One line per event: request -> tag -> check -> decision -> reason."""
        d = ev.data
        k = ev.kind
        if k == "session_start":
            return (_c(BOLD, f"\n┏━ session {d['scenario_id']} ")
                    + _c(DIM, f"[defense={d['defense_config']}]")
                    + f"\n┃  task: {_c(CYAN, str(d.get('task', ''))[:96])}")
        if k == "ingest":
            tag = d["label"]
            colour = GREEN if tag == "trusted" else YELLOW
            conf = _c(RED, " CONFIDENTIAL") if d.get("confidential") else ""
            return (f"┃  {_c(DIM, 'ingest')} {d['source_ref'][:40]:<40} "
                    f"→ {_c(colour, tag.upper())}{conf} "
                    + _c(DIM, f"({d['text_len']}b {d['content_id']})"))
        if k == "tool_request":
            args = ", ".join(f"{k2}={str(v)[:32]!r}" for k2, v in d["args"].items())
            return f"┃  {_c(BOLD, '⟶ call')} {d['tool']}({args[:110]})"
        if k == "classifier":
            v = "FLAG" if d["flagged"] else "pass"
            return (f"┃    {_c(DIM, 'L1 classifier')} {v} "
                    + _c(DIM, f"score={d['score']:.2f} {d.get('matched', '')}"))
        if k == "provenance":
            lab = d["label"]
            colour = {"trusted": GREEN, "untrusted": RED, "sanitized": CYAN}.get(lab, DIM)
            src = f" ← {d['matched_source']}" if d.get("matched_source") else ""
            tier = f" via {d['tier']}@{d['score']:.2f}" if d.get("tier") else ""
            return f"┃    {_c(DIM, 'L2 provenance')} {d['arg_name']}: {_c(colour, lab)}{src}{tier}"
        if k == "sanitizer":
            v = _c(GREEN, "PASS") if d["passed"] else _c(RED, "FAIL")
            return f"┃    {_c(DIM, 'sanitizer')} {d['sanitizer']} {v} — {d['checked']}"
        if k == "trajectory":
            v = _c(RED, "VIOLATED") if d["violated"] else _c(DIM, "ok")
            return f"┃    {_c(DIM, 'L3 invariant')} {d['invariant']} {v}"
        if k == "decision":
            allow = d["verdict"] == "allow"
            head = _c(GREEN, "✔ ALLOW") if allow else _c(RED, "✖ BLOCK")
            layer = "" if allow else _c(BOLD, f" [{d['layer']}]")
            return f"┃  {head}{layer} {d['tool']} — {d['reason']}"
        if k == "tool_executed":
            return f"┃    {_c(DIM, 'executed')} {d['tool']} → {str(d['result'])[:80]}"
        if k == "session_end":
            return (_c(DIM, f"┗━ {d['scenario_id']}: ")
                    + f"attack_succeeded={d['attack_succeeded']} "
                    f"task_completed={d['task_completed']}")
        return ""
