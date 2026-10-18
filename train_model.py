# =============================================================================
# MACHINE LEARNING TRAINING SCRIPT - PHISHING URL DETECTION
# =============================================================================
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import pickle

np.random.seed(42)
n_samples = 2000

# Generating lexical feature dataset
X_legit = np.random.binomial(n=1, p=[0.02, 0.10, 0.05, 0.01, 0.02, 0.08, 0.12, 0.05], size=(n_samples // 2, 8))
y_legit = np.zeros(n_samples // 2)

X_phish = np.random.binomial(n=1, p=[0.45, 0.78, 0.65, 0.35, 0.40, 0.72, 0.68, 0.75], size=(n_samples // 2, 8))
y_phish = np.ones(n_samples // 2)

X = np.vstack([X_legit, X_phish])
y = np.concatenate([y_legit, y_phish])

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

clf = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42)
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"Model Training Complete. Test Accuracy: {acc * 100:.2f}%")
print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

with open('phishing_model.pkl', 'wb') as f:
    pickle.dump(clf, f)
print("Saved model to phishing_model.pkl")
