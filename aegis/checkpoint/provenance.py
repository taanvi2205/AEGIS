"""Layer 2 - argument provenance (§2 item 1).

What this layer checks
----------------------
For every value that reaches a tool-call argument: did this value originate in
content the agent ingested from outside the trust boundary?

Why it is approximate
---------------------
Taint cannot be propagated through the LLM, because the model regenerates text
rather than passing objects through. So origin is *reconstructed* after the
fact: an argument value is compared against everything ingested this session,
through a ladder of matchers from exact substring to lexical similarity. This is
an approximation with a known failure mode - a true paraphrase transfers meaning
without transferring surface form - and measuring exactly where it fails is the
point of `aegis.eval.sweep`, not something to hide.

Fail-closed behaviour
---------------------
An argument that matches nothing at all is labelled UNTRUSTED with
`origin_known=False`, never TRUSTED. The checkpoint then decides what that means
per argument role: security-critical arguments must be *positively* attributable
to trusted or sanitized data, so an unattributable value is denied. Any error
inside a matcher is caught and treated as "no match", which under this default
means the value stays UNTRUSTED - errors can never open the gate.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field

from ..core import Content, Label, ProvenanceFinding, SanitizationRecord, digest
from .. import text as T

# Tiers, strongest evidence first.
#   literal   - raw substring, no normalisation at all
#   exact     - substring after NFKC, zero-width stripping, homoglyph folding, casefolding
#   squeezed  - substring after also removing every non-alphanumeric character
#   decoded   - substring of a base64/hex/rot13/percent decoding of the content
#   ngram     - character n-gram containment above a threshold
#   lexical   - IDF-weighted token cosine above a threshold
# `literal` exists so the obfuscation sweep can measure what normalisation buys.
# Without it the weakest rung of the ladder would silently already include it.
TIER_ORDER = ("literal", "exact", "squeezed", "decoded", "ngram", "lexical")

# Only these tiers are used when matching against *trusted* content. Fuzzy
# matching against the user's own task would let an attacker launder a payload
# by making it merely resemble something the user said (§4 Rule 1: no permissive
# behaviour that wasn't specified).
TRUSTED_TIERS = ("literal", "exact", "squeezed")


@dataclass
class MatcherConfig:
    """Which matcher tiers are live, and at what thresholds.

    Exposed as configuration because the obfuscation sweep varies exactly this:
    the headline curve is detection rate against obfuscation level, per tier set.
    """

    tiers: tuple[str, ...] = TIER_ORDER
    ngram_n: int = 4
    ngram_threshold: float = 0.72
    lexical_threshold: float = 0.62
    min_fuzzy_len: int = 8      # below this, fuzzy tiers are too collision-prone
    min_traceable_len: int = 4  # below this, a value cannot be attributed at all

    def enabled(self, tier: str) -> bool:
        return tier in self.tiers


@dataclass
class TaintStore:
    """Per-session record of everything ingested, plus cleared-taint values.

    One store per agent session. Nothing is ever removed: a value that became
    untrusted at step 2 is still untrusted at step 9 unless a sanitizer cleared
    that exact value.
    """

    config: MatcherConfig = field(default_factory=MatcherConfig)
    contents: list[Content] = field(default_factory=list)
    sanitized: dict[str, SanitizationRecord] = field(default_factory=dict)
    _idf: dict[str, float] | None = field(default=None, repr=False)

    def ingest(self, content: Content) -> Content:
        """Record content entering the agent's context with the label assigned
        at its point of entry. Labels are never revised later."""
        self.contents.append(content)
        self._idf = None
        return content

    def mark_sanitized(self, value: str, record: SanitizationRecord) -> None:
        """Clear taint for one exact value, on the evidence of one sanitizer run.

        Only the precise value the sanitizer inspected is cleared - not the
        document it came from, and not any other value derived from it.
        """
        if record.passed:
            self.sanitized[digest(T.normalize(value))] = record

    def idf(self) -> dict[str, float]:
        """IDF weights over ingested content, so that boilerplate shared by every
        document does not carry similarity on its own."""
        if self._idf is None:
            n = max(len(self.contents), 1)
            df: Counter = Counter()
            for c in self.contents:
                df.update(set(T.tokenize(c.text)))
            self._idf = {t: math.log((n + 1) / (d + 1)) + 1.0 for t, d in df.items()}
        return self._idf

    # -- tracing ---------------------------------------------------------
    def _match(self, value: str, content: Content, tiers: tuple[str, ...]) -> tuple[str, float] | None:
        """Best evidence that `value` came from `content`, or None.

        Returns the strongest tier that fires with its score. Any exception from
        a matcher is swallowed and reported as no-match, which is the
        conservative direction under this layer's UNTRUSTED default.
        """
        cfg = self.config
        try:
            if cfg.enabled("literal") and "literal" in tiers and value and value in content.text:
                return "literal", 1.0

            nv, nc = T.normalize(value), T.normalize(content.text)
            if cfg.enabled("exact") and "exact" in tiers and nv and nv in nc:
                return "exact", 1.0

            sv, sc = T.squeeze(value), T.squeeze(content.text)
            if cfg.enabled("squeezed") and "squeezed" in tiers and sv and sv in sc:
                return "squeezed", 1.0

            if cfg.enabled("decoded") and "decoded" in tiers and sv:
                for cand in T.decode_candidates(content.text):
                    if sv in T.squeeze(cand):
                        return "decoded", 1.0

            if len(sv) < cfg.min_fuzzy_len:
                return None

            wins = T.windows(content.text, len(value))
            if cfg.enabled("ngram") and "ngram" in tiers:
                needle = T.char_ngrams(value, cfg.ngram_n)
                best = max((T.containment(needle, T.char_ngrams(w, cfg.ngram_n))
                            for w in wins), default=0.0)
                if best >= cfg.ngram_threshold:
                    return "ngram", best

            if cfg.enabled("lexical") and "lexical" in tiers:
                idf = self.idf()
                best = max((T.tfidf_cosine(value, w, idf) for w in wins), default=0.0)
                if best >= cfg.lexical_threshold:
                    return "lexical", best
        except Exception:                                  # noqa: BLE001 - fail closed
            return None
        return None

    def trace(self, arg_name: str, value: str) -> ProvenanceFinding:
        """Attribute one argument value to a source.

        Resolution order: cleared taint, then trusted content, then untrusted
        content. On failure to attribute anything, returns UNTRUSTED with
        `origin_known=False` - the fail-closed default (§4 Rule 4).
        """
        key = digest(T.normalize(value))
        vd = digest(value)

        if key in self.sanitized:
            rec = self.sanitized[key]
            return ProvenanceFinding(arg_name, vd, Label.SANITIZED,
                                     tier="sanitizer", score=1.0, sanitizer=rec.sanitizer)

        if len(T.squeeze(value)) < self.config.min_traceable_len:
            # Too short to attribute to anything: a 2-character value collides
            # with every document. Reported explicitly rather than guessed at;
            # see docs/decisions.md D-04 and the limitations section.
            return ProvenanceFinding(arg_name, vd, Label.UNTRUSTED, tier=None,
                                     score=0.0, origin_known=False, too_short=True)

        for c in self.contents:
            if c.label is Label.TRUSTED:
                hit = self._match(value, c, TRUSTED_TIERS)
                if hit:
                    return ProvenanceFinding(arg_name, vd, Label.TRUSTED, c.content_id,
                                             c.source_ref, hit[0], hit[1],
                                             origin_known=True)

        best: tuple[float, ProvenanceFinding] | None = None
        for c in self.contents:
            if c.label is Label.TRUSTED:
                continue
            hit = self._match(value, c, TIER_ORDER)
            if hit:
                f = ProvenanceFinding(arg_name, vd, Label.UNTRUSTED, c.content_id,
                                      c.source_ref, hit[0], hit[1], origin_known=True)
                rank = (len(TIER_ORDER) - TIER_ORDER.index(hit[0])) + hit[1]
                if best is None or rank > best[0]:
                    best = (rank, f)
        if best:
            return best[1]

        return ProvenanceFinding(arg_name, vd, Label.UNTRUSTED, tier=None,
                                 score=0.0, origin_known=False)

    def confidential_seen(self) -> list[Content]:
        return [c for c in self.contents if c.confidential]
