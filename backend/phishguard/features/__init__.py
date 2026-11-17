"""Feature extraction: URL string -> numbers and facts.

lexical.py  string-only features (fast, used by the model)
host.py     DNS, TLS certificate, domain age (network, used by rules)
page.py     fetched HTML: forms, password fields, brand claims (network, rules)
"""
from .lexical import FEATURE_NAMES, LexicalResult, extract_lexical
from .parsing import InvalidURL, ParsedURL, parse_url

__all__ = ["FEATURE_NAMES", "LexicalResult", "extract_lexical", "InvalidURL", "ParsedURL", "parse_url"]
