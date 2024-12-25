import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE, RandomOverSampler
import joblib
import os
import logging
from collections import Counter
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
import psutil

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def log_memory_usage():
    process = psutil.Process(os.getpid())
    mem = process.memory_info().rss / (1024 ** 2)
    logging.info(f"Memory usage: {mem:.2f} MB")

def load_data(training_set_path, testing_set_path):
    logging.info("Loading training dataset...")
    train_data = pd.read_csv(training_set_path)
    logging.info("Loading testing dataset...")
    test_data = pd.read_csv(testing_set_path)
    return train_data, test_data

def explore_data(data):
    logging.info("Exploring data...")
    print("Data Information:")
    print(data.info())
    print("\nStatistical Metrics:")
    print(data.describe())
    print("\nMissing Values:")
    print(data.isnull().sum())

def reduce_cardinality(df, column, threshold=0.01):
    freq = df[column].value_counts(normalize=True)
    categories_to_keep = freq[freq >= threshold].index
    df[column] = df[column].apply(lambda x: x if x in categories_to_keep else 'Other')
    return df

def preprocess_data(train_data, test_data):
    logging.info("Preprocessing data...")
    numeric_features = train_data.select_dtypes(include=[np.number]).columns.tolist()
    categorical_features = train_data.select_dtypes(include=['object']).columns.tolist()

    if 'label' in categorical_features:
        categorical_features.remove('label')
    if 'label' in numeric_features:
        numeric_features.remove('label')

    logging.info("Reducing cardinality of categorical features...")
    for col in categorical_features:
        train_data = reduce_cardinality(train_data, col, threshold=0.01)
        test_data = reduce_cardinality(test_data, col, threshold=0.01)

    log_memory_usage()

    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), numeric_features),
            ('cat', OneHotEncoder(drop='first', handle_unknown='ignore', sparse=False), categorical_features)
        ]
    )

    clf_pipeline = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('classifier', RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1))
    ])

    iso_pipeline = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('anomaly_detector', IsolationForest(n_estimators=100, contamination=0.01, random_state=42, n_jobs=-1))
    ])

    logging.info("Handling missing values...")
    train_data[numeric_features] = train_data[numeric_features].fillna(train_data[numeric_features].median())
    test_data[numeric_features] = test_data[numeric_features].fillna(test_data[numeric_features].median())

    if categorical_features:
        logging.info("Filling missing values with mode for categorical features...")
        for col in categorical_features:
            mode = train_data[col].mode()[0]
            train_data[col] = train_data[col].fillna(mode)
            test_data[col] = test_data[col].fillna(mode)

    log_memory_usage()

    logging.info("Applying Pipeline for data preprocessing...")
    X_train = train_data.drop('label', axis=1)
    y_train = train_data['label']
    X_test = test_data.drop('label', axis=1)
    y_test = test_data['label']

    clf_pipeline.fit(X_train, y_train)
    logging.info("Attack classification Pipeline trained.")

    log_memory_usage()

    iso_pipeline.fit(X_train)
    logging.info("Anomaly detection Pipeline trained.")

    log_memory_usage()

    X_train_processed = clf_pipeline.named_steps['preprocessor'].transform(X_train)
    X_test_processed = clf_pipeline.named_steps['preprocessor'].transform(X_test)

    logging.info("Balancing classes with RandomOverSampler...")
    ros = RandomOverSampler(random_state=42)
    X_train_balanced, y_train_balanced = ros.fit_resample(X_train_processed, y_train)
    logging.info(f"After RandomOverSampler: {Counter(y_train_balanced)}")

    log_memory_usage()

    logging.info("Saving feature list...")
    ohe = clf_pipeline.named_steps['preprocessor'].named_transformers_['cat']
    if hasattr(ohe, 'get_feature_names_out'):
        ohe_feature_names = ohe.get_feature_names_out(categorical_features)
    else:
        ohe_feature_names = ohe.get_feature_names(categorical_features)
    feature_columns = numeric_features + list(ohe_feature_names)
    joblib.dump(feature_columns, 'models/feature_columns.pkl')
    logging.info("Feature list saved to 'models/feature_columns.pkl'.")

    return clf_pipeline, iso_pipeline, X_train_balanced, y_train_balanced, X_test_processed, y_test

def train_random_forest(X_train, y_train):
    logging.info("Training Random Forest model...")
    rf_clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf_clf.fit(X_train, y_train)
    logging.info("Random Forest model trained successfully.")
    return rf_clf

def evaluate_model(model, X_test, y_test):
    logging.info("Evaluating model...")
    y_pred = model.predict(X_test)
    print("Classification Report:")
    print(classification_report(y_test, y_pred))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

def train_isolation_forest(X_train, y_train, contamination=0.01):
    logging.info("Training Isolation Forest model for anomaly detection...")
    benign_label = 0
    X_normal = X_train[y_train_balanced == benign_label]
    iso_forest = IsolationForest(n_estimators=100, contamination=contamination, random_state=42, n_jobs=-1)
    iso_forest.fit(X_normal)
    logging.info("Isolation Forest model trained successfully.")
    return iso_forest

def save_models(models, save_dir='models'):
    logging.info(f"Saving models to directory '{save_dir}'...")
    os.makedirs(save_dir, exist_ok=True)
    for model_name, model in models.items():
        joblib.dump(model, os.path.join(save_dir, f"{model_name}.pkl"))
        logging.info(f"Model '{model_name}' saved.")
    logging.info("All models saved successfully.")

def main():
    training_set_path = 'UNSW_NB15_training-set.csv'
    testing_set_path = 'UNSW_NB15_testing-set.csv'

    train_data, test_data = load_data(training_set_path, testing_set_path)
    explore_data(train_data)
    log_memory_usage()

    clf_pipeline, iso_pipeline, X_train_balanced, y_train_balanced, X_test_processed, y_test = preprocess_data(
        train_data, test_data)
    log_memory_usage()

    logging.info("Evaluating attack classification Pipeline on test data...")
    evaluate_model(clf_pipeline.named_steps['classifier'], X_test_processed, y_test)

    logging.info("Evaluating anomaly detection Pipeline on test data...")
    y_pred_iso = iso_pipeline.named_steps['anomaly_detector'].predict(X_test_processed)
    logging.info(f"Isolation Forest Prediction Counts: {Counter(y_pred_iso)}")
    print("Confusion Matrix for Isolation Forest:")
    y_test_iso = [1 if label == 0 else -1 for label in y_test]
    print(confusion_matrix(y_test_iso, y_pred_iso))

    models = {
        'random_forest_classifier': clf_pipeline.named_steps['classifier'],
        'isolation_forest': iso_pipeline.named_steps['anomaly_detector']
    }
    save_models(models)

    logging.info("Training and saving models completed.")
    log_memory_usage()

if __name__ == "__main__":
    main()
