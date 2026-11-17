"""Train the URL model and write models/model.json + models/metrics.json.

Run from backend/ after scripts/download_datasets.py:

    ..\\.venv\\Scripts\\python.exe -m phishguard.model.train

What it does, in order:
  1. Mendeley dataset -> lexical features (the same code the API uses).
  2. Split 80/20 BY REGISTRABLE DOMAIN: every URL of a site lands on the same
     side. A random split would put paypal-x.netlify.app/a in train and
     /b in test, and the model would be graded on sites it has already seen.
  3. 5-fold grouped cross-validation on the training part (stability check).
  4. Fit XGBoost (served) and logistic regression (baseline for comparison).
  5. Test-set metrics for the model alone and for model + lexical rules.
  6. External test on PhiUSIIL (different researchers, different year).
  7. Leakage experiment: what happens if you train on PhiUSIIL instead.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

import numpy as np
import xgboost as xgb
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix,
                             f1_score, precision_recall_curve, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit, StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from ..features.lexical import FEATURE_NAMES, extract_lexical
from ..rules import lexical_rules
from ..scoring import PHISHING_AT, SUSPICIOUS_AT, combine_keep, is_known_good, rules_keep
from .dataset import MENDELEY_CSV, PHIUSIIL_CSV, load_mendeley, load_phiusiil
from .explain import LABELS
from .predictor import MODEL_DIR

SEED = 42
# Shallow trees and a small learning rate: the data set has ~11k rows, so we
# prefer many small corrections over a few deep trees that memorise it.
# max_depth was picked by grouped CV on the training part only: depth 4 and 6
# scored the same within noise (F1 0.890 vs 0.888), so the simpler one wins.
XGB_PARAMS = dict(n_estimators=400, max_depth=4, learning_rate=0.05, subsample=0.9,
                  colsample_bytree=0.9, eval_metric="logloss", random_state=SEED, n_jobs=4)


def featurize(rows):
    """Lexical features plus the two inputs scoring needs from the rules."""
    n = len(rows)
    X = np.zeros((n, len(FEATURE_NAMES)), dtype=np.float32)
    y = np.zeros(n, dtype=np.int8)
    groups, keep, known = [], np.ones(n), np.zeros(n, dtype=bool)
    for i, (url, label) in enumerate(rows):
        lex = extract_lexical(url)
        X[i], y[i] = lex.vector(), label
        groups.append(lex.parsed.registrable_domain)
        keep[i] = rules_keep(lexical_rules(lex))
        known[i] = is_known_good(lex)
    return X, y, np.array(groups), keep, known


def metrics_at(y, prob, threshold: float = 0.5) -> dict:
    pred = (prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    out = {
        "n": int(len(y)), "threshold": threshold,
        "accuracy": accuracy_score(y, pred),
        "precision": precision_score(y, pred, zero_division=0),
        "recall": recall_score(y, pred, zero_division=0),
        "f1": f1_score(y, pred, zero_division=0),
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }
    if len(set(y.tolist())) == 2:
        out["roc_auc"] = roc_auc_score(y, prob)
        out["pr_auc"] = average_precision_score(y, prob)
    return {k: round(v, 4) if isinstance(v, float) else v for k, v in out.items()}


def system_risk(prob, keep, known):
    """Vectorised scoring.combine_keep for a whole test set."""
    return np.array([combine_keep(p, k, g) for p, k, g in zip(prob, keep, known)])


def pr_curve_points(y, prob, n_points: int = 40) -> list[dict]:
    precision, recall, thresholds = precision_recall_curve(y, prob)
    idx = np.linspace(0, len(thresholds) - 1, n_points).astype(int)
    return [{"threshold": round(float(thresholds[i]), 4), "precision": round(float(precision[i]), 4),
             "recall": round(float(recall[i]), 4)} for i in idx]


def cross_validate(X, y, groups) -> dict:
    cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)
    f1s, aucs = [], []
    for train_idx, val_idx in cv.split(X, y, groups):
        model = XGBClassifier(**XGB_PARAMS).fit(X[train_idx], y[train_idx])
        prob = model.predict_proba(X[val_idx])[:, 1]
        f1s.append(f1_score(y[val_idx], prob >= 0.5))
        aucs.append(roc_auc_score(y[val_idx], prob))
    return {"folds": 5, "f1_mean": round(float(np.mean(f1s)), 4), "f1_std": round(float(np.std(f1s)), 4),
            "roc_auc_mean": round(float(np.mean(aucs)), 4), "roc_auc_std": round(float(np.std(aucs)), 4)}


def group_split(X, y, groups, test_size=0.2):
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=SEED)
    return next(splitter.split(X, y, groups))


def main() -> None:
    started = time.perf_counter()
    if not MENDELEY_CSV.exists():
        raise SystemExit("Dataset missing. Run: ..\\.venv\\Scripts\\python.exe scripts\\download_datasets.py")

    print("Loading Mendeley dataset ...")
    rows = load_mendeley()
    X, y, groups, keep, known = featurize(rows)
    train_idx, test_idx = group_split(X, y, groups)
    assert not set(groups[train_idx]) & set(groups[test_idx]), "a domain leaked across the split"
    print(f"  {len(rows)} URLs ({int(y.sum())} phishing), {len(set(groups))} domains; "
          f"train {len(train_idx)} / test {len(test_idx)}")

    print("5-fold grouped cross-validation ...")
    cv = cross_validate(X[train_idx], y[train_idx], groups[train_idx])
    print(f"  F1 {cv['f1_mean']:.3f} +/- {cv['f1_std']:.3f}, ROC-AUC {cv['roc_auc_mean']:.3f}")

    print("Training XGBoost and the logistic-regression baseline ...")
    model = XGBClassifier(**XGB_PARAMS).fit(X[train_idx], y[train_idx])
    baseline = make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000)).fit(X[train_idx], y[train_idx])

    y_test = y[test_idx]
    prob = model.predict_proba(X[test_idx])[:, 1]
    risk = system_risk(prob, keep[test_idx], known[test_idx])
    test = {
        "model": metrics_at(y_test, prob),
        "baseline_logreg": metrics_at(y_test, baseline.predict_proba(X[test_idx])[:, 1]),
        "system_suspicious": metrics_at(y_test, risk, SUSPICIOUS_AT / 100),
        "system_phishing": metrics_at(y_test, risk, PHISHING_AT / 100),
        "thresholds": [metrics_at(y_test, risk, t / 100) for t in range(10, 100, 10)],
        "pr_curve": pr_curve_points(y_test, prob),
        "score_histogram": {
            "legit": np.histogram(risk[y_test == 0] * 100, bins=10, range=(0, 100))[0].tolist(),
            "phishing": np.histogram(risk[y_test == 1] * 100, bins=10, range=(0, 100))[0].tolist(),
        },
    }
    m = test["model"]
    print(f"  model:    acc {m['accuracy']:.3f}  precision {m['precision']:.3f}  recall {m['recall']:.3f}  "
          f"ROC-AUC {m['roc_auc']:.3f}")
    b = test["baseline_logreg"]
    print(f"  baseline: acc {b['accuracy']:.3f}  precision {b['precision']:.3f}  recall {b['recall']:.3f}")
    for key in ("system_suspicious", "system_phishing"):
        s = test[key]
        print(f"  {key} (score >= {s['threshold'] * 100:.0f}): precision {s['precision']:.3f} "
              f"recall {s['recall']:.3f} FPR {s['false_positive_rate']:.3f}")

    # Mean |contribution| on the test set = how much each feature moves predictions.
    contribs = model.get_booster().predict(
        xgb.DMatrix(X[test_idx], feature_names=FEATURE_NAMES), pred_contribs=True)[:, :-1]
    importance = sorted(
        ({"feature": f, "label": LABELS[f], "importance": round(float(v), 4)}
         for f, v in zip(FEATURE_NAMES, np.abs(contribs).mean(axis=0))),
        key=lambda r: r["importance"], reverse=True)

    external, leakage = None, None
    if PHIUSIIL_CSV.exists():
        print("External test on PhiUSIIL (this takes about a minute) ...")
        p_rows = load_phiusiil()
        pX, py, pgroups, pkeep, pknown = featurize(p_rows)
        p_prob = model.predict_proba(pX)[:, 1]
        p_risk = system_risk(p_prob, pkeep, pknown)
        path_col = FEATURE_NAMES.index("path_length")
        query_col = FEATURE_NAMES.index("query_length")
        bare = (pX[:, path_col] <= 1) & (pX[:, query_col] == 0)
        phish = py == 1
        external = {
            "rows": int(len(py)), "phishing": int(phish.sum()),
            "model": metrics_at(py, p_prob),
            "system_phishing": metrics_at(py, p_risk, PHISHING_AT / 100),
            "system_suspicious": metrics_at(py, p_risk, SUSPICIOUS_AT / 100),
            "phishing_with_path": {"n": int((phish & ~bare).sum()),
                                   "recall_suspicious": round(float((p_risk[phish & ~bare] >= SUSPICIOUS_AT / 100).mean()), 4)},
            "phishing_bare_domain": {"n": int((phish & bare).sum()),
                                     "recall_suspicious": round(float((p_risk[phish & bare] >= SUSPICIOUS_AT / 100).mean()), 4)},
        }
        e = external
        print(f"  model acc {e['model']['accuracy']:.3f}  precision {e['model']['precision']:.3f}  "
              f"recall {e['model']['recall']:.3f}  ROC-AUC {e['model'].get('roc_auc', 0):.3f}")
        print(f"  recall (score >= {SUSPICIOUS_AT}) with path {e['phishing_with_path']['recall_suspicious']:.3f}, "
              f"bare domain {e['phishing_bare_domain']['recall_suspicious']:.3f}")

        print("Leakage experiment: train on PhiUSIIL, test on Mendeley ...")
        tr, te = group_split(pX, py, pgroups)
        naive = XGBClassifier(**XGB_PARAMS).fit(pX[tr], py[tr])
        gain = naive.get_booster().get_score(importance_type="gain")
        leakage = {
            "description": f"XGBoost on the same {len(FEATURE_NAMES)} features, trained on PhiUSIIL, where every legitimate "
                           "URL is a bare https://www. homepage.",
            "in_distribution": metrics_at(py[te], naive.predict_proba(pX[te])[:, 1]),
            "on_mendeley": metrics_at(y, naive.predict_proba(X)[:, 1]),
            # Trained on a bare numpy array, so XGBoost names columns f0, f1, ...
            "top_features": [LABELS[FEATURE_NAMES[int(f[1:])]]
                             for f, _ in sorted(gain.items(), key=lambda kv: -kv[1])[:5]],
        }
        print(f"  in-distribution acc {leakage['in_distribution']['accuracy']:.4f} -> "
              f"on Mendeley acc {leakage['on_mendeley']['accuracy']:.3f}, "
              f"FPR {leakage['on_mendeley']['false_positive_rate']:.3f}")
    else:
        print("PhiUSIIL not downloaded: skipping the external test and leakage experiment.")

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    model.get_booster().save_model(str(MODEL_DIR / "model.json"))
    metrics = {
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model": "XGBoost (gradient-boosted trees)",
        "params": XGB_PARAMS,
        "feature_names": FEATURE_NAMES,
        "dataset": {
            "name": "Hannousse & Yahiouche, Web page phishing detection (Mendeley Data V3, 2020)",
            "rows": int(len(y)), "phishing": int(y.sum()), "legitimate": int(len(y) - y.sum()),
            "domains": int(len(set(groups))), "train_rows": int(len(train_idx)), "test_rows": int(len(test_idx)),
            "split": "80/20 grouped by registrable domain (no site in both train and test), seed 42",
        },
        "score_bands": {"suspicious_at": SUSPICIOUS_AT, "phishing_at": PHISHING_AT},
        "cv": cv,
        "test": test,
        "feature_importance": importance,
        "external": {"phiusiil": external} if external else {},
        "leakage_experiment": leakage,
        "training_seconds": round(time.perf_counter() - started, 1),
    }
    (MODEL_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"Saved {MODEL_DIR / 'model.json'} and metrics.json in {metrics['training_seconds']} s")


if __name__ == "__main__":
    main()
