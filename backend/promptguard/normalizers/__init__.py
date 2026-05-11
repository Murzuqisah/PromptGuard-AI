"""Input normalization pipeline.

Runs before pattern matching to defeat obfuscation techniques:
- Zero-width character removal
- Unicode normalization (NFKC)
- Homoglyph substitution
- Base64 decoding (when detected)
- Whitespace collapse
"""

from __future__ import annotations

import base64
import re
import unicodedata

# Zero-width and invisible unicode characters
_INVISIBLE_RE = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f"
    r"\u2060\u2061\u2062\u2063\u2064"
    r"\ufeff\u00ad\u034f\u061c"
    r"\u115f\u1160\u17b4\u17b5"
    r"\u180e\u2000-\u200a\u202a-\u202e"
    r"\u2066-\u2069\ufff9-\ufffb]"
)

# Common homoglyph mappings (Cyrillic/Greek/special → Latin)
_HOMOGLYPHS: dict[str, str] = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0458": "j", "\u04bb": "h", "\u0501": "d",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H",
    "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N",
    "\u039f": "O", "\u03a1": "P", "\u03a4": "T", "\u03a7": "X",
    "\u03b1": "a", "\u03bf": "o",
    "\uff41": "a", "\uff42": "b", "\uff43": "c", "\uff44": "d",
    "\uff45": "e", "\uff46": "f", "\uff47": "g", "\uff48": "h",
    "\uff49": "i", "\uff4a": "j", "\uff4b": "k", "\uff4c": "l",
    "\uff4d": "m", "\uff4e": "n", "\uff4f": "o", "\uff50": "p",
    "\uff51": "q", "\uff52": "r", "\uff53": "s", "\uff54": "t",
    "\uff55": "u", "\uff56": "v", "\uff57": "w", "\uff58": "x",
    "\uff59": "y", "\uff5a": "z",
}

# Base64 pattern (at least 20 chars, valid base64 alphabet)
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

# Spaced-out character bypass (e.g., "i g n o r e")
_SPACED_CHARS_RE = re.compile(r"(?<=[a-zA-Z])\s(?=[a-zA-Z])")


def normalize(content: str) -> str:
    """Run the full normalization pipeline on input content."""
    text = content
    text = _remove_invisible(text)
    text = _normalize_unicode(text)
    text = _replace_homoglyphs(text)
    text = _collapse_spacing(text)
    text = _decode_base64_segments(text)
    return text


def _remove_invisible(text: str) -> str:
    return _INVISIBLE_RE.sub("", text)


def _normalize_unicode(text: str) -> str:
    return unicodedata.normalize("NFKC", text)


def _replace_homoglyphs(text: str) -> str:
    return "".join(_HOMOGLYPHS.get(c, c) for c in text)


def _collapse_spacing(text: str) -> str:
    """Collapse single spaces between single characters (e.g., 'i g n o r e' → 'ignore')."""
    # Only collapse if we detect a pattern of alternating char-space-char 4+ times
    if re.search(r"(?:[a-zA-Z] ){4,}[a-zA-Z]", text):
        text = _SPACED_CHARS_RE.sub("", text)
    return text


def _decode_base64_segments(text: str) -> str:
    """Attempt to decode base64 segments and append decoded content for scanning."""
    decoded_parts: list[str] = []
    for match in _BASE64_RE.finditer(text):
        segment = match.group(0)
        try:
            decoded = base64.b64decode(segment).decode("utf-8", errors="ignore")
            if decoded.isprintable() and len(decoded) > 4:
                decoded_parts.append(decoded)
        except Exception:
            continue

    if decoded_parts:
        return text + "\n[DECODED_BASE64]: " + " | ".join(decoded_parts)
    return text
