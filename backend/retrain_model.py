"""
Manual retraining pipeline (minimal v1 — no scheduler).

Merges original Kaggle-style CSVs in data/ with buffered rows in data/new_samples.csv,
deduplicates, retrains the RF+GB ensemble, evaluates with stratified CV, and saves
updated artifacts so LIME explanations stay aligned with train_features.npy.

Run:
  cd backend && python retrain_model.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from model import train_and_save


def main() -> None:
    print("[retrain] Merging base datasets + new_samples.csv ...")
    train_and_save(include_new_samples=True, record_retrain=True)
    print("[retrain] Done. Restart the API or POST /learning/retrain to reload in memory.")


if __name__ == "__main__":
    main()
