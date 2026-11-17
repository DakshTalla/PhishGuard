"""Load the trained XGBoost model and explain each prediction.

WHY XGBoost's JSON format instead of pickle/joblib: loading a pickle can run
arbitrary code, so a model file swapped by an attacker would be code
execution. The JSON format is plain data.

WHY pred_contribs: XGBoost can split every prediction into one additive
contribution per feature (TreeSHAP). Positive numbers pushed the URL towards
"phishing", negative towards "legitimate", and they sum (with a bias term) to
the model's log-odds. That is what powers the per-feature breakdown in the UI.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import xgboost as xgb

from ..features.lexical import FEATURE_NAMES, LexicalResult

MODEL_DIR = Path(__file__).resolve().parents[2] / "models"


@dataclass
class Prediction:
    probability: float                # P(phishing) from the model alone
    contributions: dict[str, float]   # feature -> log-odds contribution
    bias: float                       # log-odds before looking at any feature


class Predictor:
    def __init__(self, booster: xgb.Booster, feature_names: list[str]):
        if feature_names != FEATURE_NAMES:
            # The model was trained on a different feature list: refuse to
            # run rather than feed it columns in the wrong order.
            raise ValueError("model feature list does not match the code; retrain the model")
        self.booster = booster
        self.feature_names = feature_names

    @classmethod
    def load(cls, model_dir: Path = MODEL_DIR) -> "Predictor":
        booster = xgb.Booster()
        booster.load_model(str(model_dir / "model.json"))
        meta = json.loads((model_dir / "metrics.json").read_text(encoding="utf-8"))
        return cls(booster, meta["feature_names"])

    def _dmatrix(self, rows) -> xgb.DMatrix:
        return xgb.DMatrix(np.asarray(rows, dtype=np.float32), feature_names=self.feature_names)

    def predict(self, lex: LexicalResult) -> Prediction:
        dm = self._dmatrix([lex.vector()])
        contribs = self.booster.predict(dm, pred_contribs=True)[0]
        logit = float(contribs.sum())
        return Prediction(
            probability=1.0 / (1.0 + math.exp(-logit)),
            contributions={n: float(c) for n, c in zip(self.feature_names, contribs[:-1])},
            bias=float(contribs[-1]),
        )

    def predict_many(self, rows) -> np.ndarray:
        """Batch probabilities for evaluation (rows = list of feature vectors)."""
        return self.booster.predict(self._dmatrix(rows))
