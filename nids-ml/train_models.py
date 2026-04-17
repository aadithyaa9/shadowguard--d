"""
train_models.py — ShadowGuard-D Model Training Pipeline
=========================================================
Trains the Random Forest and initial Autoencoder on CIC-IDS2017.

Usage:
    python train_models.py --dataset /path/to/CIC-IDS2017/
                           [--sample 200000]
                           [--ae-epochs 50]

Outputs:
    rf_model.pkl
    autoencoder_model.h5
    scaler.pkl
    ae_threshold.pkl
    feature_order.pkl
"""

import argparse
import glob
import os
import pickle
import sys

import numpy as np
import pandas as pd

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
import warnings
warnings.filterwarnings("ignore")

import tensorflow as tf
tf.get_logger().setLevel("ERROR")

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix

# ── 17 features extracted by the Go edge sensor ──────────────────────────────
FEATURE_NAMES = [
    "Destination Port",
    "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std",
    "Flow Duration",
    "Flow IAT Mean", "Flow IAT Std",
    "SYN Flag Count", "ACK Flag Count", "FIN Flag Count",
    "RST Flag Count", "PSH Flag Count",
]

# Canonical output names used by detect_stream.py / retrain_autoencoder.py
CANONICAL_NAMES = [
    "server_port", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
    "min_len", "max_len", "mean_len", "std_len", "duration",
    "mean_iat", "std_iat", "syn", "ack", "fin", "rst", "psh"
]

LABEL_COL = "Label"

# ── CIC-IDS2017 column name normalization ────────────────────────────────────

def _norm(col: str) -> str:
    return col.strip().lower().replace(" ", "_").replace("/", "_")

CIC_MAP = {
    "destination_port":                  "Destination Port",
    "total_fwd_packets":                 "Total Fwd Packets",
    "total_backward_packets":            "Total Backward Packets",
    "total_length_of_fwd_packets":       "Total Length of Fwd Packets",
    "total_length_of_bwd_packets":       "Total Length of Bwd Packets",
    "min_packet_length":                 "Min Packet Length",
    "max_packet_length":                 "Max Packet Length",
    "packet_length_mean":                "Packet Length Mean",
    "packet_length_std":                 "Packet Length Std",
    "flow_duration":                     "Flow Duration",
    "flow_iat_mean":                     "Flow IAT Mean",
    "flow_iat_std":                      "Flow IAT Std",
    "syn_flag_count":                    "SYN Flag Count",
    "ack_flag_count":                    "ACK Flag Count",
    "fin_flag_count":                    "FIN Flag Count",
    "rst_flag_count":                    "RST Flag Count",
    "psh_flag_count":                    "PSH Flag Count",
    "label":                             "Label",
}


def load_cicids2017(dataset_dir: str, sample: int = None) -> pd.DataFrame:
    csvs = glob.glob(os.path.join(dataset_dir, "**/*.csv"), recursive=True)
    if not csvs:
        csvs = glob.glob(os.path.join(dataset_dir, "*.csv"))
    if not csvs:
        print(f"[ERROR] No CSV files found in {dataset_dir}")
        sys.exit(1)

    print(f"[DATA] Found {len(csvs)} CSV file(s)")
    frames = []
    for path in csvs:
        try:
            df = pd.read_csv(path, encoding="latin-1", low_memory=False)
            # Normalize column names
            df.columns = [CIC_MAP.get(_norm(c), c) for c in df.columns]
            frames.append(df)
            print(f"       Loaded {len(df):,} rows from {os.path.basename(path)}")
        except Exception as e:
            print(f"[WARN] Could not read {path}: {e}")

    combined = pd.concat(frames, ignore_index=True)
    print(f"[DATA] Combined: {len(combined):,} total rows")

    if sample and sample < len(combined):
        combined = combined.sample(n=sample, random_state=42)
        print(f"[DATA] Sampled down to {len(combined):,} rows")

    return combined


def build_autoencoder(input_dim: int) -> tf.keras.Model:
    inp = tf.keras.Input(shape=(input_dim,))
    x = tf.keras.layers.Dense(64, activation="relu")(inp)
    x = tf.keras.layers.BatchNormalization()(x)
    x = tf.keras.layers.Dropout(0.2)(x)
    x = tf.keras.layers.Dense(32, activation="relu")(x)
    x = tf.keras.layers.BatchNormalization()(x)
    encoded = tf.keras.layers.Dense(16, activation="relu", name="bottleneck")(x)
    x = tf.keras.layers.Dense(32, activation="relu")(encoded)
    x = tf.keras.layers.BatchNormalization()(x)
    x = tf.keras.layers.Dense(64, activation="relu")(x)
    decoded = tf.keras.layers.Dense(input_dim, activation="linear")(x)
    model = tf.keras.Model(inputs=inp, outputs=decoded, name="shadowguard_ae_cic")
    model.compile(optimizer=tf.keras.optimizers.Adam(1e-3), loss="mse")
    return model


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", required=True, help="Path to CIC-IDS2017 CSV directory")
    parser.add_argument("--sample", type=int, default=200000)
    parser.add_argument("--ae-epochs", type=int, default=50)
    parser.add_argument("--rf-estimators", type=int, default=100)
    parser.add_argument("--threshold-percentile", type=float, default=99.0)
    args = parser.parse_args()

    # ── Load data
    df = load_cicids2017(args.dataset, args.sample)

    # ── Select features
    available = [f for f in FEATURE_NAMES if f in df.columns]
    missing = set(FEATURE_NAMES) - set(available)
    if missing:
        print(f"[WARN] Missing features: {missing}")

    if LABEL_COL not in df.columns:
        print(f"[ERROR] Label column '{LABEL_COL}' not found.")
        sys.exit(1)

    X_df = df[available].copy()
    y_raw = df[LABEL_COL].str.strip()

    # Binary encode: BENIGN=0, everything else=1
    y = (y_raw.str.upper() != "BENIGN").astype(int).values

    X = X_df.values.astype(np.float64)
    X = np.nan_to_num(X, nan=0.0, posinf=1e9, neginf=0.0)

    print(f"[DATA] Class distribution: benign={np.sum(y==0):,}, attack={np.sum(y==1):,}")

    # ── Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # ── Scale
    print("[TRAIN] Fitting StandardScaler...")
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    # ── Random Forest
    print(f"[TRAIN] Training Random Forest ({args.rf_estimators} trees)...")
    rf = RandomForestClassifier(
        n_estimators=args.rf_estimators,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced",
        max_depth=20,
        min_samples_leaf=2,
    )
    rf.fit(X_train_s, y_train)
    rf_preds = rf.predict(X_test_s)
    print("\n[RF] Classification Report:")
    print(classification_report(y_test, rf_preds, target_names=["BENIGN", "ATTACK"]))

    print("[TRAIN] Saving rf_model.pkl...")
    with open("rf_model.pkl", "wb") as f:
        pickle.dump(rf, f)

    # ── Autoencoder (train on benign only)
    benign_mask = y_train == 0
    X_benign = X_train_s[benign_mask]
    print(f"[TRAIN] Training Autoencoder on {len(X_benign):,} benign samples...")

    ae = build_autoencoder(X_train_s.shape[1])
    ae.summary()

    callbacks = [
        tf.keras.callbacks.EarlyStopping(patience=5, restore_best_weights=True, verbose=1),
        tf.keras.callbacks.ReduceLROnPlateau(patience=3, factor=0.5, verbose=1),
        tf.keras.callbacks.ModelCheckpoint("autoencoder_model.h5", save_best_only=True, verbose=0),
    ]

    ae.fit(
        X_benign, X_benign,
        epochs=args.ae_epochs,
        batch_size=128,
        validation_split=0.1,
        callbacks=callbacks,
        verbose=1,
    )

    # Compute threshold from benign reconstruction errors
    X_benign_rec = ae.predict(X_benign, verbose=0)
    errors = np.mean(np.square(X_benign - X_benign_rec), axis=1)
    threshold = float(np.percentile(errors, args.threshold_percentile))
    print(f"\n[AE] Reconstruction error threshold (p{args.threshold_percentile:.0f}): {threshold:.6f}")

    # Evaluate AE on test set
    X_test_rec = ae.predict(X_test_s, verbose=0)
    test_errors = np.mean(np.square(X_test_s - X_test_rec), axis=1)
    ae_preds = (test_errors > threshold).astype(int)
    print("[AE] Classification Report:")
    print(classification_report(y_test, ae_preds, target_names=["BENIGN", "ATTACK"]))

    print("[TRAIN] Saving autoencoder_model.h5...")
    ae.save("autoencoder_model.h5")

    print("[TRAIN] Saving scaler.pkl...")
    with open("scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)

    print("[TRAIN] Saving ae_threshold.pkl...")
    with open("ae_threshold.pkl", "wb") as f:
        pickle.dump(threshold, f)

    # Save canonical feature order
    canon_order = CANONICAL_NAMES[:len(available)]
    with open("feature_order.pkl", "wb") as f:
        pickle.dump(canon_order, f)

    print("\n[TRAIN] ✅ All models saved.")
    print("         Run the Go agent to start live detection.")


if __name__ == "__main__":
    main()
