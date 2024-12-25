import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, accuracy_score
import numpy as np
import joblib
import logging


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


file_path = 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
data = pd.read_csv(file_path)


data.columns = data.columns.str.strip()


logging.info(f"Columns in the dataset: {data.columns.tolist()}")


data = data.dropna()


if 'Label' not in data.columns:
    raise KeyError("The 'Label' column is not found in the dataset. Please check the column names.")


X = data.drop(columns=['Label'])
y = data['Label']


label_encoder = LabelEncoder()
y = label_encoder.fit_transform(y)


X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(X.mean())

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)

logging.info(f"Accuracy: {accuracy_score(y_test, y_pred)}")
logging.info(f"Classification Report:\n{classification_report(y_test, y_pred)}")

joblib.dump(model, 'random_forest_model.pkl')
joblib.dump(label_encoder, 'label_encoder.pkl')
joblib.dump(scaler, 'scaler.pkl')

logging.info("Model and preprocessors saved successfully")
