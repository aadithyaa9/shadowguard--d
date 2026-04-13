import pandas as pd
import numpy as np
import joblib
import tensorflow as tf
from sklearn.preprocessing import StandardScaler

# -----------------------
# Load dataset
# -----------------------
df = pd.read_csv("Final_week1.csv")

feature_order = joblib.load("feature_order.pkl")
X = df[feature_order].values

# -----------------------
# Scale
# -----------------------
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

joblib.dump(scaler, "scaler.pkl")

# -----------------------
# Build Autoencoder
# -----------------------
input_dim = X_scaled.shape[1]

model = tf.keras.Sequential([
    tf.keras.layers.Input(shape=(input_dim,)),
    tf.keras.layers.Dense(32, activation='relu'),
    tf.keras.layers.Dense(16, activation='relu'),
    tf.keras.layers.Dense(32, activation='relu'),
    tf.keras.layers.Dense(input_dim, activation='linear')
])

model.compile(optimizer='adam', loss='mse')

model.fit(
    X_scaled,
    X_scaled,
    epochs=20,
    batch_size=64,
    validation_split=0.1,
    verbose=1
)

# -----------------------
# Compute threshold
# -----------------------
reconstructed = model.predict(X_scaled)
mse = np.mean(np.square(X_scaled - reconstructed), axis=1)
threshold = np.percentile(mse, 95)

joblib.dump(threshold, "ae_threshold.pkl")

# -----------------------
# Save model (CRITICAL)
# -----------------------
model.save("autoencoder_model.h5")

print("Autoencoder retrained and saved successfully.")