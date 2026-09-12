"""Text normalisation, de-obfuscation and similarity primitives.

These are the mechanics the provenance matcher is built out of. They are kept
separate from policy so the obfuscation sweep (`aegis.eval.sweep`) can measure
each tier in isolation. Pure standard library and fully deterministic - no model
is consulted anywhere in this file, which is what lets the enforcement path stay
deterministic (§3).
"""

from __future__ import annotations

import base64
import binascii
import codecs
import math
import re
import unicodedata
from collections import Counter
from urllib.parse import unquote

# Characters attackers insert to break literal matching without changing how the
# string renders to a human or is re-emitted by a model.
ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)

# Confusable characters folded to their ASCII lookalike. Deliberately small and
# explicit rather than pulling in a full confusables table (§4 Rule 7).
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "ɡ": "g", "ⅼ": "l", "ᴏ": "o",
    "к": "k", "м": "m", "н": "h", "т": "t", "ь": "b", "г": "r", "ѵ": "v",
    "ο": "o", "α": "a", "ε": "e", "ρ": "p", "ι": "i", "ν": "v", "τ": "t",
    "ϲ": "c", "ѡ": "w", "ĸ": "k", "ı": "i", "ǀ": "l",
    "𝐚": "a", "𝐞": "e", "𝐨": "o", "０": "0", "１": "1", "＠": "@", "．": ".",
    "‐": "-", "–": "-", "—": "-", "’": "'", "“": '"', "”": '"',
}

_WS = re.compile(r"\s+")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")
_TOKEN = re.compile(r"[a-z0-9][a-z0-9._%+@-]*")
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}[\s:]?){8,}")


def fold_homoglyphs(text: str) -> str:
    """Map known confusable characters onto their ASCII lookalikes."""
    return "".join(HOMOGLYPHS.get(ch, ch) for ch in text)


def normalize(text: str) -> str:
    """Canonical form used by the `normalized` matcher tier.

    Applies NFKC, strips zero-width characters, folds homoglyphs, lowercases and
    collapses whitespace. Reversible information is intentionally discarded: the
    point is to make cosmetically-obfuscated copies of a value collide with the
    original.
    """
    t = unicodedata.normalize("NFKC", text)
    t = t.translate(ZERO_WIDTH)
    # Case-fold *before* folding homoglyphs so the confusable table only needs
    # lowercase entries (Cyrillic 'А' casefolds to 'а', which is in the table).
    t = fold_homoglyphs(t.casefold())
    return _WS.sub(" ", t).strip()


def squeeze(text: str) -> str:
    """Aggressive form: normalized, then every non-alphanumeric character
    removed. Defeats punctuation and separator injection ('a.t.t.a.c.k.e.r')."""
    return _NON_ALNUM.sub("", normalize(text))


def decode_candidates(text: str, max_candidates: int = 24) -> list[str]:
    """Return plausible decodings hidden inside `text`.

    Handles base64, hex, percent-encoding and rot13 - the encodings the red-team
    mutation operators actually use. Returns only decodings that look like text,
    to avoid flooding the matcher with binary noise. Never raises: a decoding
    failure yields no candidate rather than an error, because this runs inside
    the enforcement path and must not be a denial-of-service surface.
    """
    out: list[str] = []

    def keep(s: str) -> None:
        if len(out) >= max_candidates:
            return
        if len(s) < 4:
            return
        printable = sum(ch.isprintable() for ch in s)
        if printable / max(len(s), 1) > 0.9:
            out.append(s)

    for m in _B64.findall(text):
        pad = m + "=" * (-len(m) % 4)
        try:
            keep(base64.b64decode(pad, validate=True).decode("utf-8", "strict"))
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass

    for m in _HEX.findall(text):
        cleaned = re.sub(r"[\s:]", "", m)
        if len(cleaned) % 2:
            cleaned = cleaned[:-1]
        try:
            keep(bytes.fromhex(cleaned).decode("utf-8", "strict"))
        except (ValueError, UnicodeDecodeError):
            pass

    if "%" in text:
        try:
            unq = unquote(text, errors="strict")
            if unq != text:
                keep(unq)
        except (UnicodeDecodeError, ValueError):
            pass

    try:
        rot = codecs.decode(text, "rot_13")
        if rot != text:
            keep(rot)
    except (UnicodeDecodeError, LookupError, TypeError):
        pass

    return out


def char_ngrams(text: str, n: int = 4) -> Counter:
    """Character n-grams over the squeezed form, used for near-duplicate scoring."""
    s = squeeze(text)
    if len(s) < n:
        return Counter([s]) if s else Counter()
    return Counter(s[i:i + n] for i in range(len(s) - n + 1))


def containment(needle: Counter, haystack: Counter) -> float:
    """Asymmetric overlap: what fraction of the needle's n-grams appear in the
    haystack. Asymmetric on purpose - an argument value is short and the
    document it was lifted from is long, so symmetric Jaccard would score near
    zero for a true match.
    """
    total = sum(needle.values())
    if total == 0:
        return 0.0
    shared = sum(min(c, haystack.get(g, 0)) for g, c in needle.items())
    return shared / total


def tokenize(text: str) -> list[str]:
    """Word-level tokens over the normalized form, keeping email/path shapes intact."""
    return _TOKEN.findall(normalize(text))


def tfidf_cosine(a: str, b: str, idf: dict[str, float] | None = None) -> float:
    """Cosine similarity between two token bags, optionally IDF-weighted.

    This is the `semantic` tier's engine. It is lexical, not embedding-based:
    it catches word-reordering and partial rewrites, and - by construction - it
    cannot catch a true paraphrase that shares no tokens. That limit is the
    finding the obfuscation sweep is designed to measure, not a bug to paper
    over.
    """
    ta, tb = Counter(tokenize(a)), Counter(tokenize(b))
    if not ta or not tb:
        return 0.0
    w = idf or {}

    def vec(c: Counter) -> dict[str, float]:
        return {t: (1 + math.log(n)) * w.get(t, 1.0) for t, n in c.items()}

    va, vb = vec(ta), vec(tb)
    shared = set(va) & set(vb)
    if not shared:
        return 0.0
    dot = sum(va[t] * vb[t] for t in shared)
    na = math.sqrt(sum(v * v for v in va.values()))
    nb = math.sqrt(sum(v * v for v in vb.values()))
    return dot / (na * nb) if na and nb else 0.0


def windows(text: str, target_len: int, stride_ratio: float = 0.5) -> list[str]:
    """Split a document into overlapping windows sized around the value being
    traced, plus its natural lines. Comparing a short value against a whole
    document dilutes every similarity score toward zero; windowing preserves
    locality.
    """
    parts = [ln.strip() for ln in re.split(r"[\n\r]+|(?<=[.!?])\s+", text) if ln.strip()]
    span = max(target_len * 3, 48)
    stride = max(int(span * stride_ratio), 16)
    flat = _WS.sub(" ", text)
    parts.extend(flat[i:i + span] for i in range(0, max(len(flat) - span, 0) + 1, stride))
    return parts
