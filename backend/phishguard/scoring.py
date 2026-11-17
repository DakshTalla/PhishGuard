"""Combine the model's probability and the rules into one 0-100 score.

Noisy-OR: treat every signal as an independent chance of being right.

    risk = 1 - (1 - p_model) * (1 - w_rule1) * (1 - w_rule2) * ...

Why this formula:
  * one strong signal is enough (a homoglyph of paypal.com alone gives 85+);
  * more evidence can only raise the risk, and it never exceeds 100;
  * each weight still means something on its own ("this rule alone = 60%").
Its known weakness is double counting when two signals are really the same
evidence (a model feature and a rule about the same thing). We limit that by
keeping strong rules for things the model rarely saw in training.

Well-known domains are capped at a low score: a long Google Docs link is not
phishing. Platforms where anyone can publish (sites.google.com, *.github.io,
...) never get this cap, because their pages are written by strangers.
"""
from __future__ import annotations

from .features.brands import KNOWN_GOOD_DOMAINS, USER_CONTENT_HOSTS, host_in, matching_suffix
from .features.lexical import LexicalResult
from .rules import Reason

SUSPICIOUS_AT = 40   # score >= 40: "suspicious"
PHISHING_AT = 70     # score >= 70: "phishing"; the extension warns from here by default
KNOWN_GOOD_CAP = 0.10


def verdict_for(score: int) -> str:
    if score >= PHISHING_AT:
        return "phishing"
    if score >= SUSPICIOUS_AT:
        return "suspicious"
    return "safe"


def is_known_good(lex: LexicalResult) -> bool:
    host = lex.parsed.host
    return host_in(host, KNOWN_GOOD_DOMAINS) and matching_suffix(host, USER_CONTENT_HOSTS) is None


def rules_keep(reasons: list[Reason]) -> float:
    """Product of (1 - weight) over the rules: the chance that all of them are wrong."""
    keep = 1.0
    for reason in reasons:
        if reason.source == "rule":
            keep *= 1.0 - reason.weight
    return keep


def combine_keep(p_model: float, keep: float, known_good: bool) -> float:
    """Risk in [0, 1] from the model probability and a rules_keep() value."""
    risk = 1.0 - (1.0 - p_model) * keep
    return min(risk, KNOWN_GOOD_CAP) if known_good else risk


def combine(p_model: float, reasons: list[Reason], known_good: bool) -> float:
    """Risk in [0, 1]. (train.py uses the two halves separately for speed.)"""
    return combine_keep(p_model, rules_keep(reasons), known_good)


def score_of(risk: float) -> int:
    return int(round(risk * 100))
