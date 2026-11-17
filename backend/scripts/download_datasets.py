"""Download the two public phishing datasets used for training and evaluation.

Run from the backend folder:

    ..\\.venv\\Scripts\\python.exe scripts\\download_datasets.py

Files land in backend/data/raw/ (git-ignored). Each download is checked
against a pinned SHA-256 so a changed or tampered file fails loudly instead
of silently changing the model.

Datasets (both CC BY 4.0):
  * mendeley  Hannousse & Yahiouche, "Web page phishing detection",
              Mendeley Data V3, doi:10.17632/c2gw7fy2j4.3 (11,430 URLs, May 2020).
              TRAINING set: both classes are full, realistic URLs.
  * phiusiil  Prasad & Chandra, "PhiUSIIL Phishing URL Dataset", UCI Machine
              Learning Repository, 2024 (235,795 URLs).
              EXTERNAL TEST set only: every legitimate URL in it is a bare
              https://www. homepage, so a model trained on it learns URL shape
              instead of phishing (see docs/STUDY_GUIDE.md, "Dataset leakage").

Only the CSV files are used. The Mendeley page also offers .pickle files; we
never load those, because unpickling untrusted data can execute code.
"""
from __future__ import annotations

import hashlib
import sys
import urllib.request
import zipfile
from pathlib import Path

RAW_DIR = Path(__file__).resolve().parents[1] / "data" / "raw"

DATASETS = {
    "mendeley": {
        "url": "https://data.mendeley.com/public-files/datasets/c2gw7fy2j4/files/"
               "575316f4-ee1d-453e-a04f-7b950915b61b/file_downloaded",
        "file": "dataset_B_05_2020.csv",
        "sha256": "21093e2902e5441c86a6daf95e86e7c332046e477fdf109a579d7bd81e586d6c",
    },
    "phiusiil": {
        "url": "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip",
        "file": "phiusiil.zip",
        "sha256": "0a639fd03aea6308c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59a",
        "extract": "PhiUSIIL_Phishing_URL_Dataset.csv",
    },
}


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def download(url: str, dest: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "PhishGuard-dataset-downloader/1.0"})
    with urllib.request.urlopen(request, timeout=60) as resp, dest.open("wb") as out:
        total = int(resp.headers.get("Content-Length") or 0)
        done = 0
        while chunk := resp.read(1 << 16):
            out.write(chunk)
            done += len(chunk)
            if total:
                print(f"\r  {done / 1e6:6.1f} / {total / 1e6:.1f} MB", end="", flush=True)
    print()


def fetch(name: str, spec: dict) -> None:
    target_dir = RAW_DIR / name
    target_dir.mkdir(parents=True, exist_ok=True)
    dest = target_dir / spec["file"]
    if dest.exists() and sha256_of(dest) == spec["sha256"]:
        print(f"[{name}] already downloaded")
    else:
        print(f"[{name}] downloading {spec['url']}")
        download(spec["url"], dest)
        actual = sha256_of(dest)
        if actual != spec["sha256"]:
            dest.unlink()
            sys.exit(f"[{name}] checksum mismatch: expected {spec['sha256']}, got {actual}")
        print(f"[{name}] checksum OK")

    member = spec.get("extract")
    if member and not (target_dir / member).exists():
        # Extract only the one file we expect, by its exact name. Never
        # extractall() on downloaded archives: a crafted entry such as
        # "../../x" could write outside the folder ("zip slip").
        with zipfile.ZipFile(dest) as archive:
            with archive.open(member) as src, (target_dir / member).open("wb") as out:
                while block := src.read(1 << 20):
                    out.write(block)
        print(f"[{name}] extracted {member}")


def main() -> None:
    for name, spec in DATASETS.items():
        fetch(name, spec)
    print(f"\nDone. Files are in {RAW_DIR}")
    print("Next: ..\\.venv\\Scripts\\python.exe -m phishguard.model.train")


if __name__ == "__main__":
    main()
