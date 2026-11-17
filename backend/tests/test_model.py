import json
import math

import pytest

from phishguard.features.lexical import FEATURE_NAMES, extract_lexical
from phishguard.model.explain import breakdown, model_reasons
from phishguard.model.predictor import MODEL_DIR, Predictor


def test_contributions_add_up_to_the_prediction(predictor):
    pred = predictor.predict(extract_lexical("http://secure-login.verify-paypal.example.top/account.php"))
    logit = sum(pred.contributions.values()) + pred.bias
    assert pred.probability == pytest.approx(1 / (1 + math.exp(-logit)), rel=1e-5)
    assert set(pred.contributions) == set(FEATURE_NAMES)


def test_model_separates_obvious_cases(predictor):
    bad = predictor.predict(extract_lexical("http://paypal-login-verify.com/account/update.php")).probability
    good = predictor.predict(extract_lexical("https://example.com/")).probability
    assert bad > 0.9 and good < 0.2


def test_feature_list_mismatch_is_refused(predictor):
    with pytest.raises(ValueError):
        Predictor(predictor.booster, FEATURE_NAMES[:-1])


def test_breakdown_is_sorted_and_reasons_are_plausible(predictor):
    lex = extract_lexical("http://paypal-login-verify.com/account/update.php")
    pred = predictor.predict(lex)
    rows = breakdown(lex, pred)
    assert len(rows) == len(FEATURE_NAMES)
    assert abs(rows[0]["contribution"]) >= abs(rows[-1]["contribution"])
    reasons = model_reasons(lex, pred)
    assert reasons and all(r.source == "model" and r.weight == 0 for r in reasons)


def test_metrics_file_matches_code():
    metrics = json.loads((MODEL_DIR / "metrics.json").read_text(encoding="utf-8"))
    assert metrics["feature_names"] == FEATURE_NAMES
    assert metrics["test"]["model"]["roc_auc"] > 0.85
