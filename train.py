"""
train.py — Train sklearn phishing classifier on real labeled data.

Dataset: GregaVrbancic Phishing Dataset (58,645 URLs, 87 features)
Usage: python train.py
"""

import os
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from scanner.ml_model import MODEL_PATH, URL_FEATURE_KEYS, EMAIL_FEATURE_KEYS
from scanner.url_scanner import extract_url_features
from scanner.ml_model import _heuristic_email_score

DATASET_PATH = "data/phishing_urls.csv"


def train_url_model():
    print("\n[URL Model] Loading dataset...")
    df = pd.read_csv(DATASET_PATH)

    print(f"[URL Model] Dataset shape: {df.shape}")
    print(f"[URL Model] Label distribution:\n{df['phishing'].value_counts()}")

    # The dataset has pre-computed features — map what we can to our feature keys
    # Use all numeric columns except the label as features
    feature_cols = [c for c in df.columns if c != "phishing"]
    X = df[feature_cols].fillna(0).values
    y = df["phishing"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"\n[URL Model] Training on {len(X_train)} samples, testing on {len(X_test)}...")

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            class_weight="balanced",
            n_jobs=-1
        )),
    ])

    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    print(f"\n[URL Model] Accuracy: {acc * 100:.2f}%")
    print("\n[URL Model] Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["clean", "phishing"]))

    # Store feature column names so scanner knows what to pass
    model.feature_names = feature_cols
    model.accuracy = acc

    return model, acc


def train_email_model():
    """
    Email model uses heuristic-generated synthetic data.
    Replace EMAIL_CSV path below with a real labeled dataset for production.
    """
    print("\n[Email Model] Training on synthetic data...")
    print("[Email Model] (Replace with Enron/CEAS dataset for production accuracy)")

    from scanner.email_scanner import extract_email_features

    phishing_emails = [
        """From: security@paypa1.com\nReply-To: attacker@evil.com\nSubject: URGENT: Account suspended\n\nDear Customer, your account has been SUSPENDED. Verify IMMEDIATELY or lose access within 24 hours. Click here: http://paypa1.tk/verify\nProvide your credit card number, social security number, bank account.""",
        """From: apple@apple-secure.ml\nSubject: Action Required: Verify Apple ID now\n\nDear Apple User, your Apple ID is locked. Verify immediately: http://apple-id.tk/login\nEnter password and credit card to unlock. Final notice.""",
        """From: irs-refund@irs-gov.tk\nSubject: Your tax refund is ready - Act Now\n\nDear Taxpayer, you have a pending refund. Claim immediately or it expires. Provide SSN, bank account, routing number at: http://irs-refund.ml/claim""",
        """From: hr@company-payroll.xyz\nSubject: Urgent: Update your direct deposit information\n\nDear Employee, you must update your bank account and routing number immediately or your paycheck will be delayed. Login: http://payroll-update.tk/login""",
    ]

    clean_emails = [
        """From: noreply@github.com\nSubject: Your weekly digest\n\nHi, here is your weekly GitHub summary. You had 4 commits this week. Visit https://github.com/dashboard for details.\n\nThanks, GitHub Team""",
        """From: receipts@amazon.com\nSubject: Your order has shipped\n\nHello, your order #123 has shipped. Track at https://amazon.com/orders\n\nAmazon Customer Service""",
        """From: newsletter@medium.com\nSubject: Your weekly reading list\n\nHere are this week's top stories based on your interests. Read more at https://medium.com\n\nThe Medium Team""",
        """From: support@slack.com\nSubject: New login to your Slack account\n\nWe noticed a new sign-in to your Slack account from Chrome on Windows. If this was you, no action needed. Visit https://slack.com/account/settings if not.\n\nSlack Security""",
    ]

    X, y = [], []
    for email in phishing_emails:
        feats, _ = extract_email_features(email)
        X.append([feats.get(k, 0) for k in EMAIL_FEATURE_KEYS])
        y.append(1)
    for email in clean_emails:
        feats, _ = extract_email_features(email)
        X.append([feats.get(k, 0) for k in EMAIL_FEATURE_KEYS])
        y.append(0)

    X, y = np.array(X), np.array(y)

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced")),
    ])
    model.fit(X, y)
    print("[Email Model] Trained successfully on synthetic data")
    return model


if __name__ == "__main__":
    print("=" * 55)
    print("  AI Phishing Scanner — Model Training")
    print("=" * 55)

    os.makedirs("models", exist_ok=True)

    url_model, acc = train_url_model()
    email_model = train_email_model()

    with open(MODEL_PATH, "wb") as f:
        pickle.dump({"url_model": url_model, "email_model": email_model}, f)

    print(f"\n[Done] Models saved to {MODEL_PATH}")
    print(f"[Done] URL model accuracy: {acc * 100:.2f}%")
    print("\nRun the scanner now with trained ML models:")
    print("  python main.py --url 'http://paypa1.tk/login' --no-llm")
