"""
detect_stream.py — ShadowGuard-D ML Inference Engine
======================================================
Reads CSV feature vectors from stdin (one line per flow),
outputs a classification line per input to stdout.

Output format:
  <label>,rf=<rf_label>,ae=<ae_score>,conf=<rf_conf>
  where label = 0 (benign) or 1 (malicious)

Writes READY to stdout when models are loaded and ready.
"""

import sys
import os
import pickle
import numpy as np

# ── Suppress TF/Keras noise ──────────────────────────────────────────────────
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"

import warnings
warnings.filterwarnings("ignore")

import tensorflow as tf
tf.get_logger().setLevel("ERROR")

# ── Constants ────────────────────────────────────────────────────────────────

FEATURE_DIM       = 17
RF_MODEL_PATH     = "rf_model.pkl"
AE_MODEL_PATH     = "autoencoder_real_fixed.h5"
SCALER_PATH       = "scaler_real.pkl"
THRESHOLD_PATH    = "ae_threshold_real1.pkl"
FEAT_ORDER_PATH   = "feature_order.pkl"

# Fallback paths if real-data models not found
AE_FALLBACK_PATH  = "autoencoder_model.h5"
SCALER_FALLBACK   = "scaler.pkl"
THRESH_FALLBACK   = "ae_threshold.pkl"

# Feature names (must match Go's feature vector order)
FEATURE_NAMES = [
    "server_port", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
    "min_len", "max_len", "mean_len", "std_len", "duration",
    "mean_iat", "std_iat", "syn", "ack", "fin", "rst", "psh"
]

# ── Helpers ──────────────────────────────────────────────────────────────────

def _try_load_one(path: str):
    """
    Try every known deserialization strategy for a single path.
    Returns the object on success, raises on hard failure, returns None if
    file not found.
    """
    if not os.path.exists(path):
        return None

    # 1. Standard pickle
    try:
        with open(path, "rb") as f:
            return pickle.load(f)
    except pickle.UnpicklingError as e:
        print(f"[ML] pickle failed for {path}: {e}", file=sys.stderr)
    except Exception as e:
        print(f"[ML] pickle error for {path}: {e}", file=sys.stderr)

    # 2. joblib (sklearn saves with joblib internally in newer versions)
    try:
        import joblib
        return joblib.load(path)
    except ImportError:
        pass
    except Exception as e:
        print(f"[ML] joblib failed for {path}: {e}", file=sys.stderr)

    # 3. pickle with encoding fallbacks (Python 2 → 3 cross-version)
    for encoding in ("latin-1", "bytes", "ASCII"):
        try:
            with open(path, "rb") as f:
                return pickle.load(f, encoding=encoding)
        except Exception:
            pass

    print(f"[ML ERROR] All load strategies failed for {path}.", file=sys.stderr)
    print(f"[ML ERROR] This usually means the model was saved with a different",
          file=sys.stderr)
    print(f"[ML ERROR] Python/sklearn version. Fix: run  python fix_models.py",
          file=sys.stderr)
    return None


def _load_pickle(path, fallback=None):
    obj = _try_load_one(path)
    if obj is not None:
        return obj
    if fallback:
        obj = _try_load_one(fallback)
        if obj is not None:
            print(f"[ML] Used fallback: {fallback}", file=sys.stderr)
            return obj
    return None


def _load_keras(path, fallback=None):
    for p in ([path] + ([fallback] if fallback else [])):
        if not p or not os.path.exists(p):
            continue
        # Try .keras / SavedModel / legacy .h5
        for kwargs in [
            {"compile": False},
            {"compile": False, "safe_mode": False},
        ]:
            try:
                return tf.keras.models.load_model(p, **kwargs)
            except TypeError:
                # safe_mode not supported in older TF
                try:
                    return tf.keras.models.load_model(p, compile=False)
                except Exception:
                    pass
            except Exception as e:
                print(f"[ML] Keras load failed ({p}): {e}", file=sys.stderr)
                break
    return None


def reorder_features(raw: np.ndarray, feat_order) -> np.ndarray:
    """Reorder Go feature vector to match training feature order if available."""
    if feat_order is None:
        return raw
    try:
        indices = [FEATURE_NAMES.index(f) for f in feat_order if f in FEATURE_NAMES]
        if len(indices) == raw.shape[1]:
            return raw[:, indices]
    except Exception:
        pass
    return raw


# ── Model Loading ────────────────────────────────────────────────────────────

def load_models():
    print("[ML] Loading Random Forest...", file=sys.stderr)
    rf = _load_pickle(RF_MODEL_PATH)
    if rf is None:
        print("[ML WARNING] rf_model.pkl not found — RF path will always return benign.", file=sys.stderr)

    print("[ML] Loading Autoencoder...", file=sys.stderr)
    ae = _load_keras(AE_MODEL_PATH, AE_FALLBACK_PATH)
    if ae is None:
        print("[ML WARNING] Autoencoder model not found — AE path disabled.", file=sys.stderr)

    print("[ML] Loading scaler...", file=sys.stderr)
    scaler = _load_pickle(SCALER_PATH, SCALER_FALLBACK)
    if scaler is None:
        print("[ML WARNING] Scaler not found — features will be unscaled.", file=sys.stderr)

    print("[ML] Loading AE threshold...", file=sys.stderr)
    ae_threshold = _load_pickle(THRESHOLD_PATH, THRESH_FALLBACK)
    if ae_threshold is None:
        ae_threshold = 0.05  # conservative default
        print(f"[ML WARNING] AE threshold not found — using default {ae_threshold}.", file=sys.stderr)
    else:
        print(f"[ML] AE reconstruction-error threshold: {ae_threshold:.6f}", file=sys.stderr)

    feat_order = _load_pickle(FEAT_ORDER_PATH)
    if feat_order is not None:
        print(f"[ML] Feature order loaded ({len(feat_order)} features).", file=sys.stderr)

    return rf, ae, scaler, ae_threshold, feat_order


# ── Inference ────────────────────────────────────────────────────────────────

def predict(raw_vector: list, rf, ae, scaler, ae_threshold, feat_order) -> str:
    """
    Returns a result string:
      <final_label>,rf=<rf_label>,ae=<ae_score:.4f>,conf=<rf_conf:.2f>
    """
    try:
        x = np.array(raw_vector, dtype=np.float32).reshape(1, -1)
        x = reorder_features(x, feat_order)

        # Clip obvious infinities/NaNs before scaling
        x = np.nan_to_num(x, nan=0.0, posinf=1e9, neginf=0.0)

        x_scaled = scaler.transform(x) if scaler is not None else x

        # ── Random Forest path ─────────────────────────────────────────────
        rf_label = 0
        rf_conf  = 1.0
        if rf is not None:
            rf_label = int(rf.predict(x_scaled)[0])
            proba    = rf.predict_proba(x_scaled)[0]
            rf_conf  = float(np.max(proba))

        # ── Autoencoder path ───────────────────────────────────────────────
        ae_score = 0.0
        ae_label = 0
        if ae is not None:
            x_reconstructed = ae.predict(x_scaled, verbose=0)
            ae_score = float(np.mean(np.square(x_scaled - x_reconstructed)))
            ae_label = 1 if ae_score > ae_threshold else 0

        # ── Fusion: flag if EITHER path raises alarm ───────────────────────
        # High-confidence RF benign can suppress a low-margin AE anomaly,
        # but a definitive RF attack overrides everything.
        final_label = 0
        if rf_label == 1 and rf_conf > 0.6:
            final_label = 1
        elif ae_label == 1 and ae_score > ae_threshold * 1.5:
            # Only trigger AE zero-day if score is meaningfully above threshold
            final_label = 1

        return f"{final_label},rf={rf_label},ae={ae_score:.4f},conf={rf_conf:.2f}"

    except Exception as e:
        # Never let an exception crash the loop — return safe benign
        print(f"[ML ERROR] Inference failed: {e}", file=sys.stderr)
        return "0,rf=0,ae=0.0000,conf=0.00"


# ── Streaming main loop ──────────────────────────────────────────────────────

def main():
    rf, ae, scaler, ae_threshold, feat_order = load_models()

    # Signal readiness to the Go orchestrator
    print("READY", flush=True)
    print("[ML] ✅ Inference engine live — reading from stdin.", file=sys.stderr)

    stdin = sys.stdin
    stdout = sys.stdout

    for line in stdin:
        line = line.strip()
        if not line:
            continue

        try:
            parts = line.split(",")
            if len(parts) != FEATURE_DIM:
                print(f"[ML WARNING] Expected {FEATURE_DIM} features, got {len(parts)}. Skipping.", file=sys.stderr)
                print("0,rf=0,ae=0.0000,conf=0.00", flush=True)
                continue

            vector = [float(v) for v in parts]
            result = predict(vector, rf, ae, scaler, ae_threshold, feat_order)
            print(result, flush=True)

        except ValueError as e:
            print(f"[ML WARNING] Parse error: {e}", file=sys.stderr)
            print("0,rf=0,ae=0.0000,conf=0.00", flush=True)


if __name__ == "__main__":
    main()
