import pandas as pd
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import silhouette_score
import numpy as np


def extract_features(packets_data):
    df = pd.DataFrame(packets_data)
    feature_cols = ['Protocol', 'Packet Size']
    df_features = df[feature_cols].copy()
    df_features['Packet Size'] = df_features['Packet Size'].fillna(0)
    categorical_features = ['Protocol']
    numerical_features = ['Packet Size']
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), numerical_features),
            ('cat', OneHotEncoder(), categorical_features)
        ]
    )
    X = preprocessor.fit_transform(df_features)
    return X


def detect_anomalies_kmeans(X, k_range=(2, 10)):
    best_k = 2
    best_score = -1
    best_kmeans = None

    for k in range(k_range[0], k_range[1] + 1):
        kmeans = KMeans(n_clusters=k, random_state=42)
        labels = kmeans.fit_predict(X)
        score = silhouette_score(X, labels)
        if score > best_score:
            best_score = score
            best_k = k
            best_kmeans = kmeans

    distances = best_kmeans.transform(X)
    min_distances = distances.min(axis=1)
    threshold = min_distances.mean() + min_distances.std()
    anomalies = min_distances > threshold

    print(f"K-Means: Optimal k={best_k} with Silhouette Score={best_score:.2f}")
    print(f"K-Means: Detected {np.sum(anomalies)} anomalies out of {len(anomalies)} packets.")

    return anomalies


def detect_anomalies_isolation_forest(X, contamination=0.05, n_estimators=200, max_samples=256, max_features=1.0,
                                      bootstrap=True):
    model = IsolationForest(contamination=contamination, n_estimators=n_estimators,
                            max_samples=max_samples, max_features=max_features, bootstrap=bootstrap, random_state=42)
    model.fit(X)
    preds = model.predict(X)
    anomalies = preds == -1

    print(f"Isolation Forest: Detected {np.sum(anomalies)} anomalies out of {len(anomalies)} packets.")

    return anomalies


def detect_anomalies_one_class_svm(X, contamination=0.05, kernel='rbf', gamma='scale'):
    model = OneClassSVM(kernel=kernel, gamma=gamma, nu=contamination)
    model.fit(X)
    preds = model.predict(X)
    anomalies = preds == -1

    print(f"One-Class SVM: Detected {np.sum(anomalies)} anomalies out of {len(anomalies)} packets.")

    return anomalies


def generate_alerts(kmeans_anomalies, iforest_anomalies, svm_anomalies):
    alerts = []
    total_anomalies = 0
    for idx, (k, i, s) in enumerate(zip(kmeans_anomalies, iforest_anomalies, svm_anomalies), start=1):
        if k or i or s:
            alert = {
                "Index": idx,
                "Methods": []
            }
            if k:
                alert["Methods"].append("K-Means")
            if i:
                alert["Methods"].append("Isolation Forest")
            if s:
                alert["Methods"].append("One-Class SVM")

            alert["Methods"] = ", ".join(alert["Methods"])

            alerts.append(alert)
            total_anomalies += 1

    print(f"Total anomalies detected: {total_anomalies}")
    return alerts
