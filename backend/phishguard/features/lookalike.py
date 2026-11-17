"""Lookalike domains: homoglyphs (аpple.com) and typosquats (paypa1.com).

These attacks are rare in public training data, so a model cannot learn them.
They are also unambiguous when detected, so they are handled by explicit
checks here and turned into strong rules in rules.py.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from .brands import BRANDS, host_in
from .parsing import ParsedURL

# Non-Latin letters that render (almost) identically to Latin ones. This is a
# hand-picked subset of Unicode's confusables.txt (UTS #39) covering the
# letters attackers actually use; the full table has thousands of entries.
CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ԁ": "d", "һ": "h", "ӏ": "l", "ѕ": "s", "ԛ": "q",
    "ԝ": "w", "ь": "b", "п": "n", "т": "t", "к": "k", "м": "m", "в": "b",
    # Greek
    "α": "a", "ο": "o", "ν": "v", "ρ": "p", "τ": "t", "ι": "i", "κ": "k",
    "χ": "x", "ε": "e", "υ": "u", "ω": "w",
    # Latin look-alikes outside basic ASCII
    "ı": "i", "ł": "l", "ɑ": "a", "ɡ": "g", "ɩ": "i",
}

# Digit swaps and letter pairs that read as one letter: paypa1, g00gle, rnicrosoft.
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})
_PAIRS = (("rn", "m"), ("vv", "w"))
# Single ASCII characters that are easy to misread for each other.
_VISUAL_SWAPS = {frozenset(p) for p in ("li", "l1", "i1", "o0", "mn", "uv", "gq", "ce")}
_TOKEN = re.compile(r"[a-z0-9$]+")


@dataclass(frozen=True)
class LookalikeMatch:
    kind: str          # "homoglyph" or "typosquat"
    brand: str         # keyword from BRANDS, e.g. "paypal"
    legit_domain: str  # the domain being imitated, e.g. "paypal.com"
    evidence: str      # the part of the host that does the imitating


def skeleton(text: str) -> str:
    """Map look-alike characters to plain ASCII ("раураl" -> "paypal").

    Accents are stripped too (NFKD splits "é" into "e" + a combining mark).
    """
    out = []
    for ch in text:
        if ch in CONFUSABLES:
            out.append(CONFUSABLES[ch])
            continue
        decomposed = unicodedata.normalize("NFKD", ch)
        out.append("".join(c for c in decomposed if not unicodedata.combining(c)))
    return "".join(out)


def is_mixed_script(unicode_host: str) -> bool:
    """True when one label mixes Latin, Cyrillic or Greek letters.

    Real words almost never mix alphabets inside one label; homoglyph attacks
    do it all the time. (Chrome uses a similar test to decide when to show
    punycode instead of Unicode in the address bar.)
    """
    for label in unicode_host.split("."):
        scripts = {unicodedata.name(ch, "UNKNOWN").split(" ")[0] for ch in label if ch.isalpha()}
        if len(scripts & {"LATIN", "CYRILLIC", "GREEK"}) >= 2:
            return True
    return False


def is_typo_of(token: str, brand: str) -> bool:
    """True when `token` is `brand` with one *plausible* typo.

    WHY not plain edit distance: "cloud" is one edit from "icloud" and
    "finance" one edit from "binance", which would flag thousands of honest
    sites. Only the mistakes a victim would not notice count:
      * one visually confusable swap      paypai  (l -> i)
      * two neighbouring letters swapped  paypla
      * a doubled or un-doubled letter    gooogle, gogle
    """
    if token == brand:
        return False
    if len(token) == len(brand):
        diffs = [i for i, (a, b) in enumerate(zip(token, brand)) if a != b]
        if len(diffs) == 1:
            i = diffs[0]
            return frozenset((token[i], brand[i])) in _VISUAL_SWAPS
        if len(diffs) == 2:
            i, j = diffs
            return j == i + 1 and token[i] == brand[j] and token[j] == brand[i]
        return False
    longer, shorter = (token, brand) if len(token) > len(brand) else (brand, token)
    if len(longer) - len(shorter) != 1:
        return False
    for i in range(len(longer)):
        if longer[:i] + longer[i + 1:] == shorter:
            # The extra letter must repeat its neighbour (a doubled letter).
            return (i > 0 and longer[i - 1] == longer[i]) or (
                i + 1 < len(longer) and longer[i + 1] == longer[i])
    return False


def _deleet(token: str) -> str:
    token = token.translate(_LEET)
    for fake, real in _PAIRS:
        token = token.replace(fake, real)
    return token


def _brand_for_token(token: str) -> str | None:
    """Return the brand a single host token imitates, if any."""
    if token in BRANDS:
        return None  # the real word is brand impersonation, handled in lexical.py
    fixed = _deleet(token)
    if fixed != token and fixed in BRANDS:
        return fixed
    for brand in BRANDS:
        if len(brand) >= 5 and is_typo_of(token, brand):
            return brand
    return None


def find_lookalike(parsed: ParsedURL) -> LookalikeMatch | None:
    """Detect a host that imitates a known brand domain without being it."""
    if parsed.is_ip:
        return None

    # 1) Homoglyphs: the Unicode form changes when mapped to its ASCII skeleton.
    if not parsed.unicode_host.isascii():
        skel = skeleton(parsed.unicode_host)
        if skel != parsed.unicode_host:
            for brand, domains in BRANDS.items():
                if host_in(skel, domains) or brand in _TOKEN.findall(skel):
                    if host_in(parsed.host, domains):
                        return None  # it really is the brand
                    return LookalikeMatch("homoglyph", brand, domains[0], parsed.unicode_host)

    # 2) Typosquats in any label left of the public suffix.
    left_of_suffix = ".".join(p for p in (parsed.subdomain, parsed.domain) if p)
    for token in _TOKEN.findall(left_of_suffix):
        if len(token) < 4:
            continue
        brand = _brand_for_token(token)
        if brand and not host_in(parsed.host, BRANDS[brand]):
            return LookalikeMatch("typosquat", brand, BRANDS[brand][0], token)
    return None
