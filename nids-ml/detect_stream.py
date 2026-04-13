import os
import sys
import warnings

import joblib
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras import layers, models

warnings.filterwarnings("ignore", message="X does not have valid feature names")
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"

# -------------------------------------------------
# Resolve absolute path (critical for Go execution)
# -------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# -------------------------------------------------
# Load models & artifacts (Happens exactly ONCE)
# -------------------------------------------------
rf_model = joblib.load(os.path.join(BASE_DIR, "rf_model.pkl"))
scaler = joblib.load(os.path.join(BASE_DIR, "scaler_real.pkl"))
threshold = joblib.load(os.path.join(BASE_DIR, "ae_threshold_real1.pkl"))
feature_order = joblib.load(os.path.join(BASE_DIR, "feature_order.pkl"))

# -------------------------------------------------
# FIX: Manually rebuild architecture to bypass Keras version mismatch
# -------------------------------------------------
input_dim = len(feature_order)

autoencoder = models.Sequential([
    layers.Dense(8, activation='relu', input_shape=(input_dim,)),
    layers.Dense(4, activation='relu'),
    layers.Dense(8, activation='relu'),
    layers.Dense(input_dim, activation='linear')
])

# Load weights only from the .h5 file
autoencoder.load_weights(os.path.join(BASE_DIR, "autoencoder_real_fixed.h5"))

# -------------------------------------------------
# Hybrid Prediction Logic
# -------------------------------------------------
def predict_flow(flow_row):
    # Ensure correct feature order and numeric dtype
    feature_vector = np.array(flow_row[feature_order], dtype=np.float32).reshape(1, -1)

    # ---- Random Forest Path ----
    rf_pred = rf_model.predict(feature_vector)[0]
    rf_prob = rf_model.predict_proba(feature_vector)[0][1]

    if rf_pred == 1:
        return 1, float(rf_prob), 0.0

    # ---- Autoencoder Path ----
    scaled_vector = scaler.transform(feature_vector)

    reconstructed = autoencoder.predict(scaled_vector, verbose=0)

    error = float(np.mean(np.square(scaled_vector - reconstructed)))

    if error > threshold:
        return 1, float(rf_prob), error
    else:
        return 0, float(rf_prob), error

# -------------------------------------------------
# Continuous Stream Listener (Modified for Go IPC)
# -------------------------------------------------
def main():
    # 1. Signal to the Go agent that models are loaded and we are ready
    print("READY", flush=True)

    # 2. Enter an infinite loop waiting for data from Go via standard input
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        # Skip the header row if Go accidentally sends it
        if "Destination Port" in line:
            continue

        try:
            # Parse the incoming CSV string from Go into floats
            values = list(map(float, line.split(",")))

            # Reconstruct it into a format the predict_flow function expects
            row_dict = dict(zip(feature_order, values))
            row_df = pd.Series(row_dict)

            # Run inference
            label, confidence, anomaly_score = predict_flow(row_df)

            # Print the result and FLUSH the buffer immediately back to Go
            print(f"{label},{confidence:.6f},{anomaly_score:.6f}", flush=True)

        except Exception as e:
            # If a row fails, send a structured error back so Go doesn't hang
            print(f"ERROR,{str(e)},0.0", flush=True)

if __name__ == "__main__":
    main()