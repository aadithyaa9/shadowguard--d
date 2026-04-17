"""
retrain_autoencoder.py — ShadowGuard-D Domain Adaptation
==========================================================
Retrains the Autoencoder on a local safe-traffic baseline captured
by the Go agent's calibration mode, achieving true domain adaptation
and eliminating the "Kaggle Gap" false-positive problem.

Usage:
    python retrain_autoencoder.py [--calib calib_baseline.csv]
                                  [--epochs 30]
                                  [--threshold-percentile 99]
"""

import argparse
import os
import sys
import pickle
import numpy as np
import pandas as pd

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
import warnings
warnings.filterwarnings("ignore")

import tensorflow as tf
tf.get_logger().setLevel("ERROR")

from sklearn.preprocessing import StandardScaler

# ── Constants ────────────────────────────────────────────────────────────────

DEFAULT_CALIB_CSV   = "calib_baseline.csv"
AE_OUT_PATH         = "autoencoder_real_fixed.h5"
SCALER_OUT_PATH     = "scaler_real.pkl"
THRESHOLD_OUT_PATH  = "ae_threshold_real1.pkl"
FEAT_ORDER_OUT      = "feature_order.pkl"

FEATURE_NAMES = [
    "server_port", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
    "min_len", "max_len", "mean_len", "std_len", "duration",
    "mean_iat", "std_iat", "syn", "ack", "fin", "rst", "psh"
]

# ── Architecture ─────────────────────────────────────────────────────────────

def build_autoencoder(input_dim: int) -> tf.keras.Model:
    """
    Symmetric Autoencoder matching the paper's deep-learning feature extractor.
    Bottleneck forces the model to learn a compressed, meaningful representation
    of normal traffic — anomalies produce high reconstruction error.
    """
    inp = tf.keras.Input(shape=(input_dim,))

    # Encoder
    x = tf.keras.layers.Dense(64, activation="relu")(inp)
    x = tf.keras.layers.BatchNormalization()(x)
    x = tf.keras.layers.Dropout(0.2)(x)
    x = tf.keras.layers.Dense(32, activation="relu")(x)
    x = tf.keras.layers.BatchNormalization()(x)
    encoded = tf.keras.layers.Dense(16, activation="relu", name="bottleneck")(x)

    # Decoder
    x = tf.keras.layers.Dense(32, activation="relu")(encoded)
    x = tf.keras.layers.BatchNormalization()(x)
    x = tf.keras.layers.Dense(64, activation="relu")(x)
    decoded = tf.keras.layers.Dense(input_dim, activation="linear")(x)

    model = tf.keras.Model(inputs=inp, outputs=decoded, name="shadowguard_ae")
    model.compile(optimizer=tf.keras.optimizers.Adam(1e-3), loss="mse")
    return model


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ShadowGuard-D Autoencoder Domain Adaptation")
    parser.add_argument("--calib", default=DEFAULT_CALIB_CSV, help="Calibration CSV path")
    parser.add_argument("--epochs", type=int, default=30, help="Training epochs")
    parser.add_argument("--batch", type=int, default=64, help="Batch size")
    parser.add_argument("--threshold-percentile", type=float, default=99.0,
                        help="Percentile of reconstruction errors to use as detection threshold")
    parser.add_argument("--val-split", type=float, default=0.1, help="Validation split fraction")
    args = parser.parse_args()

    # ── Load calibration data
    if not os.path.exists(args.calib):
        print(f"[ERROR] Calibration file not found: {args.calib}")
        print("        Run the Go agent with --calibrate first.")
        sys.exit(1)

    print(f"[CALIB] Loading calibration data from {args.calib}...")
    df = pd.read_csv(args.calib)

    # Drop any columns not in our feature set
    available = [f for f in FEATURE_NAMES if f in df.columns]
    df = df[available]

    print(f"[CALIB] Loaded {len(df)} samples × {len(available)} features")

    if len(df) < 50:
        print("[WARNING] Very few calibration samples — consider capturing more.")

    X = df.values.astype(np.float32)

    # Replace NaN / Inf that can appear from idle flows
    X = np.nan_to_num(X, nan=0.0, posinf=1e9, neginf=0.0)

    # ── Fit scaler on local data
    print("[CALIB] Fitting StandardScaler on local traffic...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # ── Train autoencoder
    print(f"[CALIB] Training Autoencoder ({args.epochs} epochs, batch={args.batch})...")
    ae = build_autoencoder(X_scaled.shape[1])
    ae.summary()

    callbacks = [
        tf.keras.callbacks.EarlyStopping(patience=5, restore_best_weights=True, verbose=1),
        tf.keras.callbacks.ReduceLROnPlateau(patience=3, factor=0.5, verbose=1),
    ]

    history = ae.fit(
        X_scaled, X_scaled,
        epochs=args.epochs,
        batch_size=args.batch,
        validation_split=args.val_split,
        callbacks=callbacks,
        verbose=1,
    )

    final_loss = history.history["val_loss"][-1]
    print(f"[CALIB] Training complete. Final val_loss = {final_loss:.6f}")

    # ── Compute reconstruction errors on training data → set threshold
    X_reconstructed = ae.predict(X_scaled, verbose=0)
    errors = np.mean(np.square(X_scaled - X_reconstructed), axis=1)

    threshold = float(np.percentile(errors, args.threshold_percentile))
    print(f"[CALIB] Reconstruction error at p{args.threshold_percentile:.0f} = {threshold:.6f}")
    print(f"[CALIB] This is your new detection threshold.")

    # ── Save everything
    print(f"[CALIB] Saving adapted Autoencoder → {AE_OUT_PATH}")
    ae.save(AE_OUT_PATH)

    print(f"[CALIB] Saving adapted Scaler → {SCALER_OUT_PATH}")
    with open(SCALER_OUT_PATH, "wb") as f:
        pickle.dump(scaler, f)

    print(f"[CALIB] Saving AE threshold → {THRESHOLD_OUT_PATH}")
    with open(THRESHOLD_OUT_PATH, "wb") as f:
        pickle.dump(threshold, f)

    print(f"[CALIB] Saving feature order → {FEAT_ORDER_OUT}")
    with open(FEAT_ORDER_OUT, "wb") as f:
        pickle.dump(available, f)

    print("\n[CALIB] ✅ Domain adaptation complete!")
    print(f"         AE threshold: {threshold:.6f}")
    print(f"         Restart the Go agent (without --calibrate) to deploy.")


if __name__ == "__main__":
    main()
