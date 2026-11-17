"""Load the downloaded datasets as (url, label) pairs with label 1 = phishing."""
from __future__ import annotations

import csv
from pathlib import Path

from ..features.parsing import InvalidURL, parse_url

RAW_DIR = Path(__file__).resolve().parents[2] / "data" / "raw"
MENDELEY_CSV = RAW_DIR / "mendeley" / "dataset_B_05_2020.csv"
PHIUSIIL_CSV = RAW_DIR / "phiusiil" / "PhiUSIIL_Phishing_URL_Dataset.csv"


def _dedupe(rows: list[tuple[str, int]]) -> list[tuple[str, int]]:
    """Normalise URLs, drop exact duplicates and URLs labelled both ways.

    Duplicates would let the same URL sit in train and test (inflated
    scores); conflicting labels are noise we cannot resolve.
    """
    labels: dict[str, set[int]] = {}
    for url, label in rows:
        try:
            key = parse_url(url).url
        except InvalidURL:
            continue
        labels.setdefault(key, set()).add(label)
    return [(url, next(iter(ls))) for url, ls in labels.items() if len(ls) == 1]


def load_mendeley(path: Path = MENDELEY_CSV) -> list[tuple[str, int]]:
    """Columns `url` and `status` ("phishing" / "legitimate")."""
    with path.open(encoding="utf-8-sig", errors="replace", newline="") as fh:
        rows = [(r["url"], int(r["status"] == "phishing")) for r in csv.DictReader(fh)]
    return _dedupe(rows)


def load_phiusiil(path: Path = PHIUSIIL_CSV) -> list[tuple[str, int]]:
    """Columns `URL` and `label`.

    GOTCHA: in PhiUSIIL label 1 means LEGITIMATE and 0 means phishing, the
    opposite of the usual convention, so it is flipped here.
    """
    with path.open(encoding="utf-8-sig", errors="replace", newline="") as fh:
        rows = [(r["URL"], 1 - int(r["label"])) for r in csv.DictReader(fh)]
    return _dedupe(rows)
