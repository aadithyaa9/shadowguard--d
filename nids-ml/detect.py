import sys
import joblib
import numpy as np
import pandas as pd
import tensorflow as tf

# ----------------------------
# Load models and artifacts
# ----------------------------
rf_model = joblib.load("rf_model.pkl")

feature_order = joblib.load("feature_order.pkl")
scaler = joblib.load("scaler_real.pkl")
threshold = joblib.load("ae_threshold_real.pkl")
import tensorflow as tf
from tensorflow.keras import layers, models

# Rebuild architecture manually
input_dim = len(feature_order)

autoencoder = models.Sequential([
    layers.Dense(8, activation='relu', input_shape=(input_dim,)),
    layers.Dense(4, activation='relu'),
    layers.Dense(8, activation='relu'),
    layers.Dense(input_dim, activation='linear')
])

# Load weights only
autoencoder.load_weights("autoencoder_real_fixed.h5")

# ----------------------------
# Hybrid prediction function
# ----------------------------
def predict_flow(flow_df_row):
    feature_vector = pd.DataFrame(
    [flow_df_row[feature_order]],
    columns=feature_order
)

    # Random Forest prediction
    rf_pred = rf_model.predict(feature_vector)[0]
    rf_prob = rf_model.predict_proba(feature_vector)[0][1]

    if rf_pred == 1:
        return 1, rf_prob, 0.0

    # Autoencoder path
    scaled_vector = scaler.transform(feature_vector)
    reconstructed = autoencoder.predict(scaled_vector, verbose=0)
    error = np.mean(np.square(scaled_vector - reconstructed))

    if error > threshold:
        return 1, rf_prob, error
    else:
        return 0, rf_prob, error

# ----------------------------
# Main CLI Logic
# ----------------------------
def main():
    if len(sys.argv) != 2:
        print("Usage: python detect.py input.csv")
        sys.exit(1)

    input_file = sys.argv[1]
    df = pd.read_csv(input_file)

    print("\n===== Detection Results =====\n")

    for idx, row in df.iterrows():
        label, confidence, anomaly_score = predict_flow(row)

        label_str = "Malicious" if label == 1 else "Benign"

        print(f"Flow {idx+1}:")
        print(f"  Label: {label_str}")
        print(f"  RF Confidence: {confidence:.4f}")
        print(f"  Anomaly Score: {anomaly_score:.6f}")
        print("")

if __name__ == "__main__":
    main()