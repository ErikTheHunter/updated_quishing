# Import Libraries
import pandas as pd 
import joblib
import catboost
import numpy as np
import sys
import os
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
import re
import math
import tldextract
from urllib.parse import urlparse
from src.heuristics_service import ThreatAdaptiveHeuristicDetector
from src.feature_extraction.optimized_extractor import OptimizedURLFeatureExtractor

# we start the evaluation by loading urls that are from a new 
# dataset that was neither used in traning or evaluation

# Load the data
DATASET_PATH = "../data/phiusiil_dataset/PhiUSIIL_Phishing_URL_Dataset.csv"
data = pd.read_csv(DATASET_PATH)

print("data loaded successfully...")
print("data shape: ", data.head())

print("drop all columns except the URL and label columns...")

url_df = data[['URL', 'label']].copy()
print("columns dropped successfully...")

print("url_df: ", url_df.head())

print(len(url_df), "rows in the dataset...")

# Currently our models, heuristic and black list engines 
# predict a label of 1 for phishing and 0 for legitimate URLs
# However, the dataset has labels of 1 for legitimate and 0 for phishing
# thus we need to invert the labels

url_df.loc[:, 'label'] = url_df['label'].apply(lambda x: 1 if x == 0 else 0)

# after we invert the labels, we can now proceed to evaluate the models

# Load in the models 
print("Loading pre-trained models...")

# path to random forest model
rf_model_paths = [
    "../models/rf_model.joblib"
]

# path to catboost model  
cb_model_paths = [
    "../models/cb_model.cbm",
]

# patht to decision tree model 
dt_model_paths = [
    "../models/df_model.joblib",
]

# Load Random Forest model
rf_model = None
for rf_path in rf_model_paths:
    try:
        print(f"trying to load Random Forest from: {rf_path}")
        rf_model = joblib.load(rf_path)
        print("random Forest model loaded successfully")
        break
    except Exception as e:
        print(f"failed to load from {rf_path}: {str(e)}")
        continue

if rf_model is None:
    raise ValueError("could not load Random Forest model")

# Load CatBoost model  
cb_model = None
for cb_path in cb_model_paths:
    try:
        print(f"trying to load CatBoost from: {cb_path}")
        if cb_path.endswith('.cbm'):
            cb_model = catboost.CatBoostClassifier()
            cb_model.load_model(cb_path)
        else:
            cb_model = joblib.load(cb_path)
        print("CatBoost model loaded successfully")
        break
    except Exception as e:
        print(f"Failed to load from {cb_path}: {str(e)}")
        continue

if cb_model is None:
    raise ValueError("Could not load catboost model")

# Load Decision Tree model
dt_model = None
for dt_path in dt_model_paths:
    try:
        print(f"Trying to load Decision Tree from: {dt_path}")
        dt_model = joblib.load(dt_path)
        print("Decision Tree model loaded successfully")
        break
    except Exception as e:
        print(f"Failed to load from {dt_path}: {str(e)}")
        continue

if dt_model is None:
    raise ValueError("Could not load Decision Tree model")

# we will initailize the heuristic detector 
# but disable any third party services 
# because we will be testing on a large dataset
# and we want to avoid any rate limiting issues
print("Initializing Heuristic Detector...")
heuristic_detector = ThreatAdaptiveHeuristicDetector(
    vt_key=None,          # Disable VirusTotal
    whoxy_key=None,       # Disable Whoxy  
    opr_key=None,         # Disable OpenPageRank
    enable_content=False  # Disable HTML content analysis for faster evaluation
)
print("heuristic detector initialized successfully")

# Extract features using OptimizedURLFeatureExtractor 
print("extracting features using optimizedURLFeatureExtractor...")
print(f"Processing {len(url_df)} URLs...")

# Initialize optimized feature extractor
feature_extractor = OptimizedURLFeatureExtractor()

# Extract features for all URLs
features_list = []
for url in url_df['URL']:
    features = feature_extractor.extract_features(url)
    features_list.append(features)

# Convert to DataFrame and add original URL and label columns
features_df = pd.DataFrame(features_list)
features_df['URL'] = url_df['URL'].values
features_df['label'] = url_df['label'].values

print(f"Features extracted. Shape: {features_df.shape}")

# Prepare feature matrix (use the optimized 18-feature set)
X = features_df.drop(['URL', 'label'], axis=1)

print(f"Feature columns used: {list(X.columns)}")
print(f"Final feature matrix shape: {X.shape}")

# Make predictions
print("Making predictions with Random Forest...")
rf_predictions = rf_model.predict(X)
rf_probabilities = rf_model.predict_proba(X)[:, 1]

print("Making predictions with CatBoost...")
cb_predictions = cb_model.predict(X)
cb_probabilities = cb_model.predict_proba(X)[:, 1]

print("Making predictions with Decision Tree...")
dt_predictions = dt_model.predict(X)
dt_probabilities = dt_model.predict_proba(X)[:, 1]

# Make predictions with Heuristic Detector
print("Making predictions with Heuristic Detector...")
heuristic_predictions = []
heuristic_scores = []

for i, url in enumerate(url_df['URL'][:100]):
    if i % 10000 == 0:  # Progress indicator
        print(f"Processed {i}/{len(url_df)} URLs...")
    
    try:
        result = heuristic_detector.analyse(url)
        score = result['phish_score']
        # Convert to binary prediction: >40 = malicious (1), <=40 = genuine (0)
        prediction = 1 if score > 40 else 0
        
        heuristic_predictions.append(prediction)
        heuristic_scores.append(score)
    except Exception as e:
        print(f"error processing URL {url}: {str(e)}")
        # Default to safe prediction on error
        heuristic_predictions.append(0)
        heuristic_scores.append(20.0)

heuristic_predictions = np.array(heuristic_predictions)
heuristic_scores = np.array(heuristic_scores)
print(f"Heuristic predictions completed. Final count: {len(heuristic_predictions)}")

# Get true labels
y_true = url_df['label'].values

# let calculate the performance metrics
# to compare the models and the heuristic detector systems
print("\n" + "="*50)
print("Evaluation results")
print("="*50)
print("\n")

# Random Forest Results
print("Random Forest Model Stats:")
print("-" * 30)
rf_accuracy = accuracy_score(y_true, rf_predictions)
rf_precision = precision_score(y_true, rf_predictions)
rf_recall = recall_score(y_true, rf_predictions)
rf_f1 = f1_score(y_true, rf_predictions)

print(f"Accuracy: {rf_accuracy:.4f}")
print(f"Precision: {rf_precision:.4f}")
print(f"Recall: {rf_recall:.4f}")
print(f"F1-Score: {rf_f1:.4f}")

# CatBoost Results
print("\n")
print("Catboost model stats:")
print("-" * 30)
cb_accuracy = accuracy_score(y_true, cb_predictions)
cb_precision = precision_score(y_true, cb_predictions)
cb_recall = recall_score(y_true, cb_predictions)
cb_f1 = f1_score(y_true, cb_predictions)

print(f"Accuracy: {cb_accuracy:.4f}")
print(f"Precision: {cb_precision:.4f}")
print(f"Recall: {cb_recall:.4f}")
print(f"F1-Score: {cb_f1:.4f}")

# Decision Tree Results
print("\n")
print("Decision tree stats:")
print("-" * 30)
dt_accuracy = accuracy_score(y_true, dt_predictions)
dt_precision = precision_score(y_true, dt_predictions)
dt_recall = recall_score(y_true, dt_predictions)
dt_f1 = f1_score(y_true, dt_predictions)

print(f"Accuracy: {dt_accuracy:.4f}")
print(f"Precision: {dt_precision:.4f}")
print(f"Recall: {dt_recall:.4f}")
print(f"F1-Score: {dt_f1:.4f}")

# Heuristic Detector Results
print("\n")
print("Heuristic Detector Stats:")
print("-" * 30)
heuristic_accuracy = accuracy_score(y_true[:100], heuristic_predictions)
heuristic_precision = precision_score(y_true[:100], heuristic_predictions, zero_division=0)
heuristic_recall = recall_score(y_true[:100], heuristic_predictions, zero_division=0)
heuristic_f1 = f1_score(y_true[:100], heuristic_predictions, zero_division=0)

print(f"Accuracy: {heuristic_accuracy:.4f}")
print(f"Precision: {heuristic_precision:.4f}")
print(f"Recall: {heuristic_recall:.4f}")
print(f"F1-Score: {heuristic_f1:.4f}")

# View classification of the evaluated systems
print("\n")
print("Classification report: Random Forest")
print(classification_report(y_true, rf_predictions, target_names=['Legitimate', 'Phishing']))

print("\n")
print("Classification report: Catboost")
print(classification_report(y_true, cb_predictions, target_names=['Legitimate', 'Phishing']))

print("Classification report: decision tree")
print(classification_report(y_true, dt_predictions, target_names=['Legitimate', 'Phishing']))

print("\nClassification report: heuristics")
unique_predictions = set(heuristic_predictions)
if len(unique_predictions) > 1:
    print(classification_report(y_true[:100], heuristic_predictions, target_names=['Legitimate', 'Phishing']))
else:
    print("Failed to generate report")

# Confusion Matrices
print("\nConfusion Matrix - RANDOM FOREST:")
rf_cm = confusion_matrix(y_true, rf_predictions)
print("True\\Predicted  Legitimate  Phishing")
print(f"Legitimate      {rf_cm[0][0]:>9}  {rf_cm[0][1]:>8}")
print(f"Phishing        {rf_cm[1][0]:>9}  {rf_cm[1][1]:>8}")

print("\nConfusion Matrix - CATBOOST:")
cb_cm = confusion_matrix(y_true, cb_predictions)
print("True\\Predicted  Legitimate  Phishing")
print(f"Legitimate      {cb_cm[0][0]:>9}  {cb_cm[0][1]:>8}")
print(f"Phishing        {cb_cm[1][0]:>9}  {cb_cm[1][1]:>8}")

print("\nConfusion Matrix - DECISION TREE:")
dt_cm = confusion_matrix(y_true, dt_predictions)
print("True\\Predicted  Legitimate  Phishing")
print(f"Legitimate      {dt_cm[0][0]:>9}  {dt_cm[0][1]:>8}")
print(f"Phishing        {dt_cm[1][0]:>9}  {dt_cm[1][1]:>8}")

print("\nConfusion Matrix - HEURISTIC:")
# Only create Confusion Matrix if we have both classes
if len(unique_predictions) > 1:
    heuristic_cm = confusion_matrix(y_true[:100], heuristic_predictions)
    print("True\\Predicted  Legitimate  Phishing")
    print(f"Legitimate      {heuristic_cm[0][0]:>9}  {heuristic_cm[0][1]:>8}")
    print(f"Phishing        {heuristic_cm[1][0]:>9}  {heuristic_cm[1][1]:>8}")
else:
    print(f"Cannot create Confusion Matrix: only class {list(unique_predictions)[0]} predicted")

# Feature Importance Analysis
print("\n" + "="*50)
print("FEATURE IMPORTANCE ANALYSIS")
print("="*50)

# Random Forest Feature Importance
print("\nRANDOM FOREST - TOP 10 FEATURE IMPORTANCES:")
print("-" * 50)
if hasattr(rf_model, 'feature_importances_'):
    rf_importance = rf_model.feature_importances_
    rf_feature_importance = list(zip(X.columns, rf_importance))
    rf_feature_importance.sort(key=lambda x: x[1], reverse=True)
    
    print("Rank | Feature Name                    | Importance")
    print("-" * 55)
    for i, (feature, importance) in enumerate(rf_feature_importance[:10], 1):
        print(f"{i:4} | {feature:<30} | {importance:.6f}")
else:
    print("Feature importance not available for Random Forest model")

# CatBoost Feature Importance
print("\nCATBOOST - TOP 10 FEATURE IMPORTANCES:")
print("-" * 50)
try:
    cb_importance = cb_model.get_feature_importance()
    cb_feature_importance = list(zip(X.columns, cb_importance))
    cb_feature_importance.sort(key=lambda x: x[1], reverse=True)
    
    print("Rank | Feature Name                    | Importance")
    print("-" * 55)
    for i, (feature, importance) in enumerate(cb_feature_importance[:10], 1):
        print(f"{i:4} | {feature:<30} | {importance:.6f}")
except Exception as e:
    print(f"Error getting CatBoost feature importance: {e}")

# Decision Tree Feature Importance
print("\nDECISION TREE - TOP 10 FEATURE IMPORTANCES:")
print("-" * 50)
if hasattr(dt_model, 'feature_importances_'):
    dt_importance = dt_model.feature_importances_
    dt_feature_importance = list(zip(X.columns, dt_importance))
    dt_feature_importance.sort(key=lambda x: x[1], reverse=True)
    
    print("Rank | Feature Name                    | Importance")
    print("-" * 55)
    for i, (feature, importance) in enumerate(dt_feature_importance[:10], 1):
        print(f"{i:4} | {feature:<30} | {importance:.6f}")
else:
    print("Feature importance not available for Decision Tree model")

# Summary comparison of top 5 features across models
print("")
print("Top 5 feature Comparison across models:")
print("-" * 70)
print("Rank | Random Forest           | CatBoost               | Decision Tree")
print("-" * 70)

# Get top 5 features for each model
rf_top5 = rf_feature_importance[:5] if 'rf_feature_importance' in locals() else []
cb_top5 = cb_feature_importance[:5] if 'cb_feature_importance' in locals() else []
dt_top5 = dt_feature_importance[:5] if 'dt_feature_importance' in locals() else []

for i in range(5):
    rf_feature = rf_top5[i][0] if i < len(rf_top5) else "N/A"
    cb_feature = cb_top5[i][0] if i < len(cb_top5) else "N/A"
    dt_feature = dt_top5[i][0] if i < len(dt_top5) else "N/A"
    
    print(f"{i+1:4} | {rf_feature:<22} | {cb_feature:<21} | {dt_feature}")



