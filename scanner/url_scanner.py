"""
URL Scanner — extracts ML features from a URL and optionally queries the LLM.
"""

import re
import math
from urllib.parse import urlparse
from .ml_model import PhishingMLModel
from .llm_analyzer import LLMAnalyzer


SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".link"}

SPOOFED_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "bank", "chase", "wellsfargo", "citibank",
    "irs", "fedex", "ups", "dhl", "usps"
]

SUSPICIOUS_PATTERNS = [
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"@",
    r"(login|signin|verify|secure|account|update|confirm|password)",
    r"(free|win|prize|lucky|bonus|gift|reward)",
    r"(urgent|immediately|suspended|verify now)",
]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def extract_url_features(url: str) -> dict:
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
    except Exception:
        return {}

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    full_url = url.lower()

    subdomain_count = hostname.count(".") - 1 if hostname else 0
    tld = "." + hostname.split(".")[-1] if "." in hostname else ""
    suspicious_tld = tld.lower() in SUSPICIOUS_TLDS
    brand_in_subdomain = any(b in hostname.split(".")[0].lower() for b in SPOOFED_BRANDS) if subdomain_count > 0 else False
    brand_in_path = any(b in path.lower() for b in SPOOFED_BRANDS)

    pattern_flags = []
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, full_url, re.IGNORECASE):
            pattern_flags.append(pattern)

    special_char_ratio = sum(1 for c in url if c in "-_@%~") / max(len(url), 1)
    digit_ratio = sum(1 for c in hostname if c.isdigit()) / max(len(hostname), 1)
    entropy = shannon_entropy(hostname)
    homoglyph_suspicious = bool(re.search(r"[0o][0o]|[1il]{2,}|rn(?=\w)", hostname))

    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "subdomain_count": subdomain_count,
        "has_https": int(parsed.scheme == "https"),
        "suspicious_tld": int(suspicious_tld),
        "brand_in_subdomain": int(brand_in_subdomain),
        "brand_in_path": int(brand_in_path),
        "has_ip_address": int(bool(re.match(r"\d+\.\d+\.\d+\.\d+", hostname))),
        "has_at_symbol": int("@" in url),
        "special_char_ratio": round(special_char_ratio, 4),
        "digit_ratio_in_host": round(digit_ratio, 4),
        "hostname_entropy": round(entropy, 4),
        "homoglyph_suspicious": int(homoglyph_suspicious),
        "suspicious_pattern_count": len(pattern_flags),
        "has_port": int(bool(parsed.port)),
        "path_depth": path.count("/"),
        "query_param_count": len(parsed.query.split("&")) if parsed.query else 0,
    }


class URLScanner:
    def __init__(self, use_llm: bool = True):
        self.ml_model = PhishingMLModel()
        self.llm = LLMAnalyzer() if use_llm else None

    def scan(self, url: str) -> dict:
        features = extract_url_features(url)
        ml_score, ml_verdict = self.ml_model.predict_url(features)
        flags = self._generate_flags(features, url)

        llm_analysis = None
        llm_score = None
        if self.llm:
            llm_result = self.llm.analyze_url(url, features)
            llm_analysis = llm_result.get("explanation")
            llm_score = llm_result.get("score")

        if llm_score is not None:
            final_score = 0.4 * ml_score + 0.6 * llm_score
        else:
            final_score = ml_score

        verdict = self._score_to_verdict(final_score)

        return {
            "target": url,
            "type": "url",
            "verdict": verdict,
            "score": round(final_score, 4),
            "ml_score": round(ml_score, 4),
            "llm_score": round(llm_score, 4) if llm_score is not None else None,
            "ml_features": features,
            "llm_analysis": llm_analysis,
            "flags": flags,
        }

    def _generate_flags(self, features: dict, url: str) -> list:
        flags = []
        if features.get("has_ip_address"):
            flags.append("URL uses raw IP address instead of domain name")
        if features.get("suspicious_tld"):
            flags.append("Suspicious or free TLD detected")
        if features.get("brand_in_subdomain"):
            flags.append("Legitimate brand name found in subdomain (possible spoofing)")
        if features.get("brand_in_path"):
            flags.append("Legitimate brand name found in URL path")
        if features.get("homoglyph_suspicious"):
            flags.append("Possible homoglyph/typosquat attack detected")
        if features.get("has_at_symbol"):
            flags.append("@ symbol in URL can be used to redirect to malicious host")
        if features.get("hostname_entropy", 0) > 3.8:
            flags.append(f"High hostname entropy ({features['hostname_entropy']:.2f}) — may be algorithmically generated")
        if features.get("url_length", 0) > 100:
            flags.append(f"Unusually long URL ({features['url_length']} chars)")
        if not features.get("has_https"):
            flags.append("No HTTPS — connection is unencrypted")
        return flags

    @staticmethod
    def _score_to_verdict(score: float) -> str:
        if score >= 0.65:
            return "PHISHING"
        elif score >= 0.35:
            return "SUSPICIOUS"
        else:
            return "CLEAN"
