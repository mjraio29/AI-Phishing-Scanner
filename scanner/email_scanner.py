"""
Email Scanner — extracts features from raw email text and optionally queries the LLM.
"""

import re
from .ml_model import PhishingMLModel
from .llm_analyzer import LLMAnalyzer
from .url_scanner import URLScanner, extract_url_features


URGENCY_KEYWORDS = [
    "urgent", "immediately", "action required", "verify now", "account suspended",
    "limited time", "expires soon", "respond within", "within 24 hours", "final notice",
    "last warning", "act now", "click here", "confirm your", "update your",
]

SOCIAL_ENGINEERING = [
    "dear customer", "dear user", "dear account holder", "valued member",
    "you have been selected", "congratulations", "you won", "claim your",
    "we have noticed", "unusual activity", "suspicious login", "security alert",
    "verify your identity", "confirm your information", "unlock your account",
]

SENSITIVE_REQUESTS = [
    "social security", "ssn", "credit card", "card number", "bank account",
    "routing number", "password", "pin number", "mother's maiden",
    "date of birth", "driver's license",
]


def extract_email_features(email_text: str) -> tuple:
    text_lower = email_text.lower()
    lines = email_text.split("\n")

    header_end = 0
    for i, line in enumerate(lines):
        if line.strip() == "":
            header_end = i
            break
    headers = "\n".join(lines[:header_end]).lower()
    body = "\n".join(lines[header_end:])
    body_lower = body.lower()

    urls = re.findall(r'https?://[^\s<>"\']+', email_text)
    url_count = len(urls)

    href_urls = re.findall(r'href=["\']([^"\']+)["\']', email_text, re.IGNORECASE)
    display_urls = re.findall(r'>(https?://[^<]+)<', email_text)
    url_mismatch = 0
    for display in display_urls:
        for href in href_urls:
            if display.strip() not in href and href not in display.strip():
                url_mismatch += 1

    has_reply_to_mismatch = 0
    from_match = re.search(r'^from:.*?<(.+?)>', headers, re.MULTILINE)
    reply_to_match = re.search(r'^reply-to:.*?<(.+?)>', headers, re.MULTILINE)
    if from_match and reply_to_match:
        from_domain = from_match.group(1).split("@")[-1]
        reply_domain = reply_to_match.group(1).split("@")[-1]
        has_reply_to_mismatch = int(from_domain != reply_domain)

    urgency_count = sum(1 for kw in URGENCY_KEYWORDS if kw in body_lower)
    social_eng_count = sum(1 for kw in SOCIAL_ENGINEERING if kw in body_lower)
    sensitive_count = sum(1 for kw in SENSITIVE_REQUESTS if kw in body_lower)

    has_html = int("<html" in text_lower or "<body" in text_lower)
    hidden_text = int("display:none" in text_lower or "visibility:hidden" in text_lower)
    image_only = int(len(re.findall(r'<img', text_lower)) > 2 and len(body.strip()) < 200)

    word_count = len(body.split())
    caps_ratio = sum(1 for c in body if c.isupper()) / max(len(body), 1)
    exclamation_count = body.count("!")
    has_obfuscated_links = int(bool(re.search(r'%[0-9a-fA-F]{2}', "\n".join(href_urls))))

    features = {
        "url_count": url_count,
        "url_mismatch_count": url_mismatch,
        "urgency_keyword_count": urgency_count,
        "social_engineering_count": social_eng_count,
        "sensitive_request_count": sensitive_count,
        "has_reply_to_mismatch": has_reply_to_mismatch,
        "has_html": has_html,
        "has_hidden_text": int(hidden_text),
        "image_only_body": int(image_only),
        "word_count": word_count,
        "caps_ratio": round(caps_ratio, 4),
        "exclamation_count": exclamation_count,
        "has_obfuscated_links": has_obfuscated_links,
        "href_count": len(href_urls),
    }

    return features, urls


class EmailScanner:
    def __init__(self, use_llm: bool = True):
        self.ml_model = PhishingMLModel()
        self.llm = LLMAnalyzer() if use_llm else None

    def scan(self, email_text: str) -> dict:
        features, urls = extract_email_features(email_text)
        ml_score, _ = self.ml_model.predict_email(features)

        url_scores = []
        for url in urls[:5]:
            url_feats = extract_url_features(url)
            url_ml_score, _ = self.ml_model.predict_url(url_feats)
            url_scores.append(url_ml_score)
        max_url_score = max(url_scores) if url_scores else 0.0

        combined_ml = max(ml_score, max_url_score * 0.8)

        flags = self._generate_flags(features, urls)

        llm_analysis = None
        llm_score = None
        if self.llm:
            truncated = email_text[:3000]
            llm_result = self.llm.analyze_email(truncated, features)
            llm_analysis = llm_result.get("explanation")
            llm_score = llm_result.get("score")

        if llm_score is not None:
            final_score = 0.4 * combined_ml + 0.6 * llm_score
        else:
            final_score = combined_ml

        verdict = self._score_to_verdict(final_score)

        return {
            "target": "(email)",
            "type": "email",
            "verdict": verdict,
            "score": round(final_score, 4),
            "ml_score": round(combined_ml, 4),
            "llm_score": round(llm_score, 4) if llm_score is not None else None,
            "ml_features": features,
            "llm_analysis": llm_analysis,
            "flags": flags,
            "urls_found": urls[:10],
        }

    def _generate_flags(self, features: dict, urls: list) -> list:
        flags = []
        if features.get("urgency_keyword_count", 0) >= 2:
            flags.append(f"High urgency language detected ({features['urgency_keyword_count']} indicators)")
        if features.get("social_engineering_count", 0) >= 1:
            flags.append(f"Social engineering phrases detected ({features['social_engineering_count']} indicators)")
        if features.get("sensitive_request_count", 0) >= 1:
            flags.append("Email requests sensitive personal/financial information")
        if features.get("has_reply_to_mismatch"):
            flags.append("Reply-To domain differs from From domain — possible spoofing")
        if features.get("url_mismatch_count", 0) > 0:
            flags.append(f"Link display text doesn't match actual URL ({features['url_mismatch_count']} mismatch(es))")
        if features.get("has_hidden_text"):
            flags.append("Hidden text detected — possible content obfuscation")
        if features.get("has_obfuscated_links"):
            flags.append("URL-encoded (obfuscated) links detected in email")
        if features.get("caps_ratio", 0) > 0.15:
            flags.append("Unusually high proportion of capital letters")
        return flags

    @staticmethod
    def _score_to_verdict(score: float) -> str:
        if score >= 0.65:
            return "PHISHING"
        elif score >= 0.35:
            return "SUSPICIOUS"
        else:
            return "CLEAN"
