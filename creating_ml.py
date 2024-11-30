import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder

# Load the processed dataset
file_path = 'synthetic_dataset.csv'  # Adjust the path if necessary
df = pd.read_csv(file_path)

# Define features and target variable
# Exclude columns that are not useful for prediction
features = ['length', 'src_port', 'dst_port', 'syn_flag', 'ack_flag',
            'rst_flag', 'fin_flag', 'bytes_in_out_ratio']  # Updated features
target = 'anomaly'  # Assume "anomaly" column is present for labeling

# Check if the target exists in the dataset
if target not in df.columns:
    print("No 'anomaly' column found. Adding a placeholder for demonstration.")
    df[target] = 0  # Assume all normal traffic for testing

# Encode categorical features if necessary (e.g., protocol)
if 'protocol' in df.columns:
    le = LabelEncoder()
    df['protocol'] = le.fit_transform(df['protocol'])
    features.append('protocol')

# Prepare the feature matrix (X) and target vector (y)
X = df[features]
y = df[target]

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Initialize and train a Random Forest Classifier
clf = RandomForestClassifier(random_state=42, n_estimators=100, max_depth=None)
clf.fit(X_train, y_train)

# Make predictions
y_pred = clf.predict(X_test)

# Evaluate the model
print("Classification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Feature importance
feature_importances = pd.DataFrame({'Feature': features, 'Importance': clf.feature_importances_})
feature_importances = feature_importances.sort_values(by='Importance', ascending=False)
print("\nFeature Importances:")
print(feature_importances)

# Save the model (Optional)
import joblib
joblib.dump(clf, 'anomaly_detection_model_enhanced_synthetic.pkl')
print("\nModel saved as 'anomaly_detection_model_WhatItIs.pkl'.")
