"""
ML Model — sklearn-based phishing classifier.

On first run with no saved model, falls back to a rule-based heuristic scorer
so the tool works out of the box. Run `python train.py` to train a real model
on labeled data and persist it to models/phishing_model.pkl.
"""

import os
import pickle
import numpy as np

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "phishing_model.pkl")

URL_FEATURE_KEYS = [
    "url_length", "hostname_length", "path_length", "subdomain_count",
    "has_https", "suspicious_tld", "brand_in_subdomain", "brand_in_path",
    "has_ip_address", "has_at_symbol", "special_char_ratio",
    "digit_ratio_in_host", "hostname_entropy", "homoglyph_suspicious",
    "suspicious_pattern_count", "has_port", "path_depth", "query_param_count",
]

EMAIL_FEATURE_KEYS = [
    "url_count", "url_mismatch_count", "urgency_keyword_count",
    "social_engineering_count", "sensitive_request_count",
    "has_reply_to_mismatch", "has_html", "has_hidden_text",
    "image_only_body", "word_count", "caps_ratio",
    "exclamation_count", "has_obfuscated_links", "href_count",
]


def _heuristic_url_score(features: dict) -> float:
    score = 0.0
    score += min(features.get("url_length", 0) / 200, 0.15)
    score += features.get("suspicious_tld", 0) * 0.20
    score += features.get("brand_in_subdomain", 0) * 0.25
    score += features.get("has_ip_address", 0) * 0.30
    score += features.get("has_at_symbol", 0) * 0.20
    score += features.get("homoglyph_suspicious", 0) * 0.25
    score += min(features.get("suspicious_pattern_count", 0) * 0.10, 0.30)
    entropy = features.get("hostname_entropy", 0)
    score += max(0, (entropy - 3.5) / 1.5) * 0.15
    score -= features.get("has_https", 0) * 0.05
    return min(max(score, 0.0), 1.0)


def _heuristic_email_score(features: dict) -> float:
    score = 0.0
    score += min(features.get("urgency_keyword_count", 0) * 0.08, 0.32)
    score += min(features.get("social_engineering_count", 0) * 0.10, 0.30)
    score += min(features.get("sensitive_request_count", 0) * 0.15, 0.30)
    score += features.get("has_reply_to_mismatch", 0) * 0.20
    score += features.get("url_mismatch_count", 0) * 0.15
    score += features.get("has_hidden_text", 0) * 0.15
    score += features.get("has_obfuscated_links", 0) * 0.10
    caps = features.get("caps_ratio", 0)
    score += max(0, (caps - 0.1) * 2) * 0.10
    return min(max(score, 0.0), 1.0)


class PhishingMLModel:
    def __init__(self):
        self.url_model = None
        self.email_model = None
        self._load_models()

    def _load_models(self):
        if os.path.exists(MODEL_PATH):
            try:
                with open(MODEL_PATH, "rb") as f:
                    saved = pickle.load(f)
                self.url_model = saved.get("url_model")
                self.email_model = saved.get("email_model")
            except Exception as e:
                print(f"[ML] Warning: could not load model ({e}). Using heuristics.")

    def predict_url(self, features: dict) -> tuple:
        if self.url_model:
            try:
                vec = np.array([[features.get(k, 0) for k in URL_FEATURE_KEYS]])
                prob = self.url_model.predict_proba(vec)[0][1]
                return float(prob), "ML"
            except Exception:
                pass
        return _heuristic_url_score(features), "HEURISTIC"

    def predict_email(self, features: dict) -> tuple:
        if self.email_model:
            try:
                vec = np.array([[features.get(k, 0) for k in EMAIL_FEATURE_KEYS]])
                prob = self.email_model.predict_proba(vec)[0][1]
                return float(prob), "ML"
            except Exception:
                pass
        return _heuristic_email_score(features), "HEURISTIC"

    def save(self, url_model, email_model):
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump({"url_model": url_model, "email_model": email_model}, f)
        print(f"[ML] Models saved to {MODEL_PATH}")
