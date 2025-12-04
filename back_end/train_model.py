# train_model.py (updated for realistic dataset)
import pandas as pd
import numpy as np
import os
import pickle
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

DATA_PATH = "dataset/iot_data_realistic.csv"
df = pd.read_csv(DATA_PATH)
print("Loaded dataset:", df.shape)

# Quick cleanup: drop exact duplicates and rows with NaN
df = df.drop_duplicates().dropna().reset_index(drop=True)

# Keep a copy for analysis (attack_type distribution)
print("Attack type distribution:\n", df['attack_type'].value_counts())

# Categorical encoders
proto_encoder = LabelEncoder()
df['protocol_enc'] = proto_encoder.fit_transform(df['protocol'].astype(str).str.lower())

device_encoder = LabelEncoder()
df['device_type_enc'] = device_encoder.fit_transform(df['device_type'].astype(str))

# Choose features for training (numeric + encoded categorical)
# We intentionally drop raw strings and IPs & timestamp
feature_cols = [
    "packet_rate", "byte_rate", "packet_size", "connection_duration",
    "protocol_enc", "device_type_enc", "source_port", "destination_port"
]

X = df[feature_cols]
y = df['label'].map({'Normal': 0, 'Attack': 1})

# Save feature names for runtime
os.makedirs("model", exist_ok=True)
pickle.dump(feature_cols, open("model/feature_names.pkl", "wb"))

# Scale numeric features (we'll fit scaler on full X)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)

# RandomForest classifier
clf = RandomForestClassifier(
    n_estimators=150,
    max_depth=12,
    random_state=42,
    class_weight="balanced_subsample",
    n_jobs=-1
)
clf.fit(X_train, y_train)

# Evaluate
y_pred = clf.predict(X_test)
print("\nClassification report:\n", classification_report(y_test, y_pred))
print("Confusion matrix:\n", confusion_matrix(y_test, y_pred))
print("Accuracy:", round(accuracy_score(y_test, y_pred)*100,2), "%")

# Train IsolationForest on training set (for anomaly detection)
iso = IsolationForest(n_estimators=100, contamination=0.08, random_state=42)
iso.fit(X_train)

# Save artifacts
pickle.dump(clf, open("model/iot_model.pkl", "wb"))
pickle.dump(scaler, open("model/scaler.pkl", "wb"))
pickle.dump(proto_encoder, open("model/encoder_protocol.pkl", "wb"))
pickle.dump(device_encoder, open("model/encoder_device.pkl", "wb"))
pickle.dump(iso, open("model/isoforest.pkl", "wb"))

# Also save mapping for convenience
meta = {
    "feature_cols": feature_cols,
    "protocol_classes": list(proto_encoder.classes_),
    "device_classes": list(device_encoder.classes_)
}
pickle.dump(meta, open("model/meta.pkl", "wb"))

print("\nSaved model artifacts in /model. Done.")
