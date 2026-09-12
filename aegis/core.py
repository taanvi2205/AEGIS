"""Core value types for AEGIS.

Everything in this module is a plain, immutable-ish data record. No policy logic
lives here; policy lives in `aegis.checkpoint`. Keeping the vocabulary in one
place is what makes §6's "small, fixed tag vocabulary" rule enforceable.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Label(str, Enum):
    """The complete provenance tag vocabulary (§6). Do not extend casually.

    TRUSTED    - originated inside the trust boundary: the system prompt or the
                 user's own original task statement.
    UNTRUSTED  - originated outside it: retrieved documents, web content, file
                 contents, email bodies, and *any* tool output.
    SANITIZED  - was UNTRUSTED, then passed a named sanitizer (§2.3) that
                 constrained it to a checkable shape. Taint is cleared only for
                 the exact value the sanitizer inspected.
    """

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    SANITIZED = "sanitized"


class Verdict(str, Enum):
    """Outcome of a checkpoint decision. There is no third 'warn' state: the
    checkpoint either lets a call execute or it does not (§3 fail-closed)."""

    ALLOW = "allow"
    BLOCK = "block"


class Layer(str, Enum):
    """Which enforcement layer produced a decision. Every block must attribute
    itself to exactly one layer so the evaluation can never average across
    layers in a way that hides which one did the work (§7)."""

    INPUT_CLASSIFIER = "input_classifier"   # probabilistic, in-band
    PROVENANCE = "provenance"               # deterministic, out-of-band
    TRAJECTORY = "trajectory"               # deterministic, sequence-level
    MANIFEST = "manifest"                   # deterministic, per-call least privilege
    NONE = "none"                           # allowed; no layer objected


def digest(text: str) -> str:
    """Stable short hash used to reference a value in logs without copying the
    whole payload into every record."""
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


@dataclass
class Content:
    """A unit of content that entered the agent's context.

    `label` is assigned at ingestion time and never inferred later. `confidential`
    is an orthogonal axis (an integrity tag and a confidentiality tag, as in
    FIDES, arXiv:2505.23643): a value can be TRUSTED and confidential at once.
    """

    content_id: str
    origin: str                 # "user_task" | "tool_output" | "document"
    source_ref: str             # tool name, url, or file path this came from
    text: str
    label: Label
    confidential: bool = False
    step: int = 0               # agent step at which it entered context

    def to_json(self) -> dict[str, Any]:
        d = asdict(self)
        d["label"] = self.label.value
        d["text_digest"] = digest(self.text)
        d["text_len"] = len(self.text)
        del d["text"]           # logs reference content by digest, not by copy
        return d


@dataclass
class ToolCall:
    """A tool invocation the agent wants to make. Constructed by the agent loop
    and handed to the checkpoint; never executed directly (§3 interceptor)."""

    tool: str
    args: dict[str, Any]
    step: int = 0
    call_id: str = ""

    def __post_init__(self) -> None:
        if not self.call_id:
            self.call_id = digest(f"{self.step}:{self.tool}:{sorted(self.args.items())}")[:10]

    def string_args(self) -> list[tuple[str, str]]:
        """Argument values flattened to (name, text) pairs for taint tracing.

        Nested lists/dicts are flattened with dotted names so no argument value
        can hide from provenance tracing inside a container (§4 Rule 4).
        """
        out: list[tuple[str, str]] = []

        def walk(name: str, value: Any) -> None:
            if isinstance(value, str):
                out.append((name, value))
            elif isinstance(value, (int, float, bool)) or value is None:
                out.append((name, str(value)))
            elif isinstance(value, dict):
                for k, v in value.items():
                    walk(f"{name}.{k}", v)
            elif isinstance(value, (list, tuple)):
                for i, v in enumerate(value):
                    walk(f"{name}[{i}]", v)
            else:
                out.append((name, str(value)))

        for k, v in self.args.items():
            walk(k, v)
        return out


@dataclass
class ProvenanceFinding:
    """Result of tracing one argument value back to ingested content."""

    arg_name: str
    value_digest: str
    label: Label
    matched_content_id: str | None = None
    matched_source: str | None = None
    tier: str | None = None          # which matcher tier fired
    score: float = 0.0
    sanitizer: str | None = None     # sanitizer that cleared it, if any
    origin_known: bool = False       # True only if positively matched to a source
    too_short: bool = False          # value below the attributable-length floor


@dataclass
class Decision:
    """The audit record for one checkpoint evaluation. This is the schema the
    entire evaluation reads from - treat changes to it as breaking."""

    call_id: str
    step: int
    tool: str
    verdict: Verdict
    layer: Layer
    reason: str
    scenario_id: str = ""
    defense_config: str = ""
    findings: list[ProvenanceFinding] = field(default_factory=list)
    classifier_score: float | None = None
    invariant: str | None = None
    ts: float = field(default_factory=time.time)

    def to_json(self) -> dict[str, Any]:
        return {
            "ts": self.ts,
            "scenario_id": self.scenario_id,
            "defense_config": self.defense_config,
            "call_id": self.call_id,
            "step": self.step,
            "tool": self.tool,
            "verdict": self.verdict.value,
            "layer": self.layer.value,
            "reason": self.reason,
            "classifier_score": self.classifier_score,
            "invariant": self.invariant,
            "findings": [
                {**asdict(f), "label": f.label.value} for f in self.findings
            ],
        }


@dataclass
class SanitizationRecord:
    """Auditable evidence that a sanitizer ran (§2 item 3): what was checked,
    against what rule, and why the value passed or failed."""

    sanitizer: str
    value_digest: str
    passed: bool
    checked: str        # human-readable statement of what was verified
    rule: str           # the concrete rule/allow-list applied
    step: int = 0
    declassifies: bool = False   # True only for sanitizers that inspect payload data

    def to_json(self) -> dict[str, Any]:
        return asdict(self)
