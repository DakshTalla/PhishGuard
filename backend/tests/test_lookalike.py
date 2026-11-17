import pytest

from phishguard.features.lexical import extract_lexical
from phishguard.features.lookalike import is_mixed_script, is_typo_of, skeleton


def lookalike(url):
    return extract_lexical(url).lookalike


@pytest.mark.parametrize("url,brand", [
    ("https://аpple.com/", "apple"),             # Cyrillic а
    ("https://xn--pple-43d.com/login", "apple"),
    ("https://раураl.com/", "paypal"),           # all-Cyrillic lookalike
])
def test_homoglyphs(url, brand):
    match = lookalike(url)
    assert match and match.kind == "homoglyph" and match.brand == brand


@pytest.mark.parametrize("url,brand", [
    ("http://paypa1.com/", "paypal"),         # digit swap
    ("http://rnicrosoft.com/", "microsoft"),  # rn -> m
    ("http://g00gle-login.com/", "google"),
    ("http://paypai.com/", "paypal"),         # l -> i
    ("http://gooogle.com/", "google"),        # doubled letter
    ("http://netfilx.com/", "netflix"),       # swapped neighbours
])
def test_typosquats(url, brand):
    match = lookalike(url)
    assert match and match.kind == "typosquat" and match.brand == brand


@pytest.mark.parametrize("url", [
    "https://cloud.google.com/",       # "cloud" is one edit from "icloud"
    "https://finance.yahoo.com/",      # "finance" is one edit from "binance"
    "https://apply.example.com/",      # "apply" vs "apple"
    "https://www.paypal.com/",
    "https://github.com/",
])
def test_no_false_alarms_on_ordinary_words(url):
    assert lookalike(url) is None


def test_is_typo_of_rules():
    assert is_typo_of("paypla", "paypal")
    assert not is_typo_of("cloud", "icloud")
    assert not is_typo_of("finance", "binance")
    assert not is_typo_of("paypal", "paypal")


def test_skeleton_and_mixed_script():
    assert skeleton("раураl") == "paypal"
    assert skeleton("café") == "cafe"
    assert is_mixed_script("аpple.com")
    assert not is_mixed_script("example.com")
    assert not is_mixed_script("пример.рф")  # all Cyrillic is a real word, not mixed
