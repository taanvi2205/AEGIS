"""Layer 1 - the in-band input classifier (§2.1 baseline).

This is the only probabilistic component in AEGIS, and it is deliberately kept
outside the deterministic enforcement path (§3): it can flag content, and its
verdict is recorded, but the provenance and trajectory layers never consult it.

Two backends implement one interface:

* `HeuristicGuard`  - a pattern-and-lexicon detector, shipped, zero-dependency,
  deterministic. It stands in for an off-the-shelf guard model. It is a genuine
  detector, not a strawman, but it is a *lexical* one, and the report must say so
  wherever Layer-1 numbers appear (see docs/decisions.md D-02).
* `HFGuard`         - adapter for a real off-the-shelf classifier via
  transformers. Activates only if that package and a local model are present.

Fail-closed behaviour: `Guard.screen` never raises. If a backend errors, times
out or returns something unparseable, the result is `flagged=True` with
`error` set - an unavailable guard denies, it does not wave content through
(§3 "any code that falls back to allow on error is a security bug").
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .. import text as T


@dataclass
class GuardResult:
    flagged: bool
    score: float
    matched: str = ""
    backend: str = ""
    error: str | None = None


class Guard:
    """Interface every Layer-1 backend implements."""

    name = "guard"

    def classify(self, content: str) -> GuardResult:
        raise NotImplementedError

    def screen(self, content: str) -> GuardResult:
        """Classify without ever raising. Errors become a flagged result."""
        try:
            return self.classify(content)
        except Exception as exc:                            # noqa: BLE001 - fail closed
            return GuardResult(True, 1.0, "", self.name,
                               f"{type(exc).__name__}: {exc} (failing closed)")


# Weighted signals. Each is (name, regex, weight, passes). `passes` names which
# scoring passes the signal is meaningful in: "text" (normalized), "decoded"
# (base64/hex/rot13 payloads) and "squeezed" (all non-alphanumerics stripped).
# Signals that detect *formatting* - long encoded blobs, character-separator
# spacing - are excluded from the squeezed pass, where whitespace no longer
# exists and they would fire on ordinary prose. Weights were set by hand so a
# single strong override phrase clears the threshold while weak signals must
# co-occur, which is the behaviour of a typical deployed injection filter.
ALL_PASSES = ("text", "decoded", "squeezed")
SIGNALS: tuple[tuple[str, str, float, tuple[str, ...]], ...] = (
    ("instruction_override", r"\b(ignore|disregard|forget|override|bypass)\b[^.]{0,30}\b"
                             r"(previous|prior|above|earlier|all)\b[^.]{0,20}"
                             r"\b(instruction|prompt|rule|direction|message)s?\b", 0.62, ALL_PASSES),
    ("new_instructions", r"\b(new|updated|revised|actual|real)\s+(instruction|directive|task|system\s+prompt)s?\b", 0.42, ALL_PASSES),
    ("role_hijack", r"\b(you\s+are\s+now|from\s+now\s+on|act\s+as|pretend\s+to\s+be|"
                    r"switch\s+to)\b[^.]{0,40}\b(admin|developer|dan|unrestricted|jailbroken|assistant)\b", 0.50, ALL_PASSES),
    ("fake_system_turn", r"(</?(system|instruction)s?>|\[/?INST\]|\bsystem\s*:|###\s*(system|instruction))", 0.45, ("text", "decoded")),
    ("exfiltration_verb", r"\b(send|forward|email|upload|post|transmit|exfiltrate|leak|share)\b"
                          r"[^.]{0,40}(to\s+)?[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", 0.55, ALL_PASSES),
    ("exfiltration_url", r"\b(send|forward|upload|post|transmit|exfiltrate)\b[^.]{0,40}https?://", 0.50, ALL_PASSES),
    ("credential_target", r"\b(api[_\s-]?key|password|secret|token|credential|ssn|private\s+key)s?\b", 0.28, ALL_PASSES),
    ("urgency_authority", r"\b(urgent(ly)?|immediately|right\s+now|do\s+not\s+tell|without\s+asking|"
                          r"do\s+not\s+mention|silently|secretly)\b", 0.24, ALL_PASSES),
    ("confidentiality_break", r"\b(confidential|internal\s+only|do\s+not\s+share|classified)\b"
                              r"[^.]{0,40}\b(send|share|forward|publish|post)\b", 0.35, ALL_PASSES),
    ("encoded_blob", r"[A-Za-z0-9+/]{40,}={0,2}", 0.20, ("text",)),
    ("obfuscation_spacing", r"(?:\b[a-z]\s+){6,}[a-z]\b|(?:[a-z]\.){5,}[a-z]", 0.22, ("text",)),
)


@dataclass
class HeuristicGuard(Guard):
    """Lexical injection/jailbreak detector used as the Layer-1 baseline.

    What it checks: weighted regular-expression signals for instruction override,
    role hijacking, forged system turns, exfiltration phrasing, credential
    targeting and common obfuscation, scored over the normalized text and over
    any decodable base64/hex/rot13 payload inside it.

    On failure: `screen` reports flagged=True (fail closed).

    Known limit, stated because it is the experimental result rather than an
    excuse: every signal is surface-form. Rewording that preserves intent while
    avoiding these lexical shapes evades it, which is precisely what the adaptive
    red-team loop measures.
    """

    threshold: float = 0.50
    name: str = "heuristic-lexical-v1"
    _compiled: dict = field(default_factory=dict, repr=False)

    @staticmethod
    def _relax(pattern: str) -> str:
        """Whitespace-free variant of a pattern, for the squeezed pass.

        Squeezing deletes spaces and punctuation, so word boundaries and literal
        whitespace can never match. Dropping them lets the same signal catch
        character-separator obfuscation ("i g n o r e   a l l   p r e v i o u s").
        """
        out = re.sub(r"\\s[+*]?", r"\\s*", pattern)   # any whitespace run becomes optional
        return out.replace(r"\b", "")                # word boundaries cannot exist

    def __post_init__(self) -> None:
        flags = re.I | re.S
        self._compiled = {
            "text": [(n, re.compile(p, flags), w) for n, p, w, ps in SIGNALS if "text" in ps],
            "decoded": [(n, re.compile(p, flags), w) for n, p, w, ps in SIGNALS if "decoded" in ps],
            "squeezed": [(n, re.compile(self._relax(p), flags), w)
                         for n, p, w, ps in SIGNALS if "squeezed" in ps],
        }

    def _score_one(self, text: str, which: str) -> tuple[float, list[str]]:
        hits, total = [], 0.0
        for name, pat, weight in self._compiled[which]:
            if pat.search(text):
                hits.append(name)
                total += weight
        return total, hits

    def classify(self, content: str) -> GuardResult:
        norm = T.normalize(content)
        score, hits = self._score_one(norm, "text")

        # A real guard decodes obvious encodings before scoring; a payload that
        # only survives as base64 still counts, at a discount for uncertainty.
        for cand in T.decode_candidates(content):
            sub, subhits = self._score_one(T.normalize(cand), "decoded")
            if sub > 0:
                score += 0.8 * sub
                hits.extend(f"decoded:{h}" for h in subhits)

        # Squeezed pass catches character-separator obfuscation ('i g n o r e').
        sq_score, sq_hits = self._score_one(T.squeeze(content), "squeezed")
        if sq_score > score:
            score, hits = sq_score, [f"squeezed:{h}" for h in sq_hits]

        score = min(score, 1.0)
        return GuardResult(score >= self.threshold, round(score, 3),
                           ",".join(dict.fromkeys(hits)), self.name)


@dataclass
class HFGuard(Guard):
    """Adapter for an off-the-shelf transformers classifier (§2.1).

    What it checks: whatever the loaded model was trained to detect; the label
    named by `positive_label` is treated as "injection".

    On failure: construction raises `GuardUnavailable` so the caller must choose
    a backend explicitly; at classify time any error is converted by `screen`
    into flagged=True. There is no path where an unavailable model allows content.

    No model is downloaded by this repo and no model name is hardcoded as a
    default beyond the documented candidate - set AEGIS_GUARD_MODEL to choose.
    """

    model_id: str = "protectai/deberta-v3-base-prompt-injection-v2"
    positive_label: str = "INJECTION"
    threshold: float = 0.5
    name: str = "hf-guard"
    _pipe: object = field(default=None, repr=False)

    def __post_init__(self) -> None:
        try:
            from transformers import pipeline           # type: ignore[import-not-found]
        except ImportError as exc:
            raise GuardUnavailable(
                "transformers is not installed; install it in a virtualenv to use "
                "a real off-the-shelf guard model, or run with the heuristic backend"
            ) from exc
        self._pipe = pipeline("text-classification", model=self.model_id, truncation=True)
        self.name = f"hf:{self.model_id}"

    def classify(self, content: str) -> GuardResult:
        out = self._pipe(content[:4000])                    # type: ignore[operator]
        if not out:
            raise ValueError("guard model returned no label")
        top = out[0]
        score = float(top["score"])
        is_pos = str(top["label"]).upper() == self.positive_label.upper()
        p = score if is_pos else 1.0 - score
        return GuardResult(p >= self.threshold, round(p, 3), str(top["label"]), self.name)


class GuardUnavailable(RuntimeError):
    """Raised when a requested guard backend cannot be constructed."""


def build_guard(kind: str = "heuristic", **kw) -> Guard:
    """Construct a Layer-1 backend by name. Unknown names raise rather than
    silently degrading to a weaker detector."""
    if kind == "heuristic":
        return HeuristicGuard(**kw)
    if kind == "hf":
        return HFGuard(**kw)
    raise GuardUnavailable(f"unknown guard backend {kind!r}; known: heuristic, hf")
