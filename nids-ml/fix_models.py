"""
fix_models.py — ShadowGuard-D Model Compatibility Fixer
=========================================================
Fixes: _pickle.UnpicklingError: STACK_GLOBAL requires str

Root cause: The .pkl files were saved with a NEWER Python/sklearn than the
venv currently running them. This script loads them with every known fallback
strategy, then re-saves them using the CURRENT environment so detect_stream.py
can load them normally.

Usage (run inside the nids-ml venv):
    python fix_models.py

Or to diagnose only (no re-saving):
    python fix_models.py --diagnose
"""

import argparse
import os
import pickle
import sys
import shutil
from datetime import datetime

# ── Try joblib import (ships with sklearn) ────────────────────────────────────
try:
    import joblib
    HAS_JOBLIB = True
except ImportError:
    HAS_JOBLIB = False

# ── Files to fix ──────────────────────────────────────────────────────────────
PICKLE_FILES = [
    "rf_model.pkl",
    "scaler.pkl",
    "scaler_real.pkl",
    "ae_threshold.pkl",
    "ae_threshold_real1.pkl",
    "feature_order.pkl",
]

# ── Keras models (separate handling) ─────────────────────────────────────────
KERAS_FILES = [
    "autoencoder_model.h5",
    "autoencoder_real.keras",
    "autoencoder_real_fixed.h5",
]


def print_env():
    import platform
    print(f"\n{'='*60}")
    print(f"  Python  : {sys.version}")
    print(f"  Platform: {platform.platform()}")
    try:
        import sklearn
        print(f"  sklearn : {sklearn.__version__}")
    except ImportError:
        print(f"  sklearn : NOT INSTALLED")
    try:
        import tensorflow as tf
        print(f"  TF      : {tf.__version__}")
    except ImportError:
        print(f"  TensorFlow: NOT INSTALLED")
    print(f"  joblib  : {'available' if HAS_JOBLIB else 'NOT INSTALLED'}")
    print(f"{'='*60}\n")


def try_load(path: str):
    """Try every known strategy to load a pickle. Returns (obj, strategy) or (None, None)."""
    if not os.path.exists(path):
        return None, "file_not_found"

    # 1. Standard pickle
    try:
        with open(path, "rb") as f:
            obj = pickle.load(f)
        return obj, "pickle_standard"
    except Exception as e:
        last_err = e

    # 2. joblib
    if HAS_JOBLIB:
        try:
            obj = joblib.load(path)
            return obj, "joblib"
        except Exception as e:
            last_err = e

    # 3. pickle with latin-1 encoding (Python 2 objects)
    try:
        with open(path, "rb") as f:
            obj = pickle.load(f, encoding="latin-1")
        return obj, "pickle_latin1"
    except Exception as e:
        last_err = e

    # 4. pickle with bytes encoding
    try:
        with open(path, "rb") as f:
            obj = pickle.load(f, encoding="bytes")
        return obj, "pickle_bytes"
    except Exception as e:
        last_err = e

    print(f"    ✗ All strategies failed. Last error: {last_err}")
    return None, None


def backup(path: str):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{path}.bak_{ts}"
    shutil.copy2(path, backup_path)
    return backup_path


def resave(path: str, obj, strategy: str, dry_run: bool = False):
    """Re-save object using standard pickle with current Python version."""
    if dry_run:
        print(f"    [DRY RUN] Would re-save {path} (loaded via {strategy})")
        return True
    bak = backup(path)
    print(f"    Backup → {bak}")
    try:
        with open(path, "wb") as f:
            pickle.dump(obj, f, protocol=pickle.HIGHEST_PROTOCOL)
        print(f"    ✓ Re-saved {path} with pickle protocol {pickle.HIGHEST_PROTOCOL}")
        return True
    except Exception as e:
        print(f"    ✗ Re-save failed: {e}")
        shutil.copy2(bak, path)   # restore backup
        return False


def fix_pickles(dry_run: bool):
    print("── Pickle files ─────────────────────────────────────────────")
    any_fixed = False
    for fname in PICKLE_FILES:
        if not os.path.exists(fname):
            print(f"  SKIP  {fname}  (not found)")
            continue

        print(f"\n  Checking {fname} ...")

        # First try standard load — if it works, nothing to fix
        try:
            with open(fname, "rb") as f:
                pickle.load(f)
            print(f"    ✓ Already loads fine with standard pickle — no action needed.")
            continue
        except Exception as e:
            print(f"    Standard load failed: {e}")

        # Try fallback strategies
        obj, strategy = try_load(fname)
        if obj is None:
            print(f"    ✗ CANNOT LOAD {fname} with any strategy.")
            print(f"      → You need to retrain this model.")
            print(f"        RF:     python train_models.py --dataset /path/to/CIC-IDS2017/")
            print(f"        Scaler/AE: python retrain_autoencoder.py")
            continue

        print(f"    Loaded successfully via: {strategy}")
        if resave(fname, obj, strategy, dry_run):
            any_fixed = True

    return any_fixed


def fix_keras(dry_run: bool):
    print("\n── Keras / TF models ────────────────────────────────────────")
    try:
        os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
        import tensorflow as tf
        tf.get_logger().setLevel("ERROR")
    except ImportError:
        print("  TensorFlow not installed — skipping Keras checks.")
        return

    for fname in KERAS_FILES:
        if not os.path.exists(fname):
            print(f"  SKIP  {fname}  (not found)")
            continue

        print(f"\n  Checking {fname} ...")
        try:
            model = tf.keras.models.load_model(fname, compile=False)
            print(f"    ✓ Loads fine.")

            # Re-save in current TF format to future-proof it
            if not dry_run:
                bak = backup(fname)
                print(f"    Backup → {bak}")
                # Save as .keras (new format) alongside .h5 for compatibility
                new_path = fname.replace(".h5", "_fixed.keras") if fname.endswith(".h5") else fname
                model.save(fname)
                print(f"    ✓ Re-saved {fname} in current TF format.")
        except Exception as e:
            print(f"    ✗ Load failed: {e}")
            print(f"      → Keras model may need retraining:")
            print(f"        python retrain_autoencoder.py")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--diagnose", action="store_true",
                        help="Print diagnostics only, do not modify files")
    args = parser.parse_args()

    print_env()

    if args.diagnose:
        print("DIAGNOSE MODE — no files will be modified.\n")

    fix_pickles(dry_run=args.diagnose)
    fix_keras(dry_run=args.diagnose)

    print("\n── Done ─────────────────────────────────────────────────────")
    if not args.diagnose:
        print("  Re-saved files use the current Python/sklearn version.")
        print("  Restart the ShadowGuard-D agent to pick up the fixed models.")
    else:
        print("  Run without --diagnose to apply fixes.")


if __name__ == "__main__":
    main()
