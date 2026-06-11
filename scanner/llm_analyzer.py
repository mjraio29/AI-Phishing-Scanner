"""
LLM Analyzer — uses Claude API for deep semantic phishing analysis.
Requires ANTHROPIC_API_KEY environment variable.
"""

import os
import json
import re

SYSTEM_PROMPT = """You are a cybersecurity expert specializing in phishing detection.
Your job is to analyze URLs and emails and determine whether they are phishing attempts.

You must respond ONLY with valid JSON in this exact format:
{
  "score": <float between 0.0 (clean) and 1.0 (definitely phishing)>,
  "verdict": "<CLEAN | SUSPICIOUS | PHISHING>",
  "explanation": "<1-2 sentence explanation of your reasoning>",
  "tactics": [<list of phishing tactics detected, empty if clean>]
}

Be precise. Consider:
- Social engineering tactics (urgency, fear, greed)
- Brand impersonation and spoofing
- Requests for sensitive information
- Suspicious URL structure or domain tricks
- Mismatch between claimed identity and actual sender/domain
"""


class LLMAnalyzer:
    def __init__(self):
        try:
            import anthropic as _anthropic
        except ImportError:
            raise ImportError("anthropic package not installed. Run: pip install anthropic")
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "ANTHROPIC_API_KEY not set. "
                "Export it with: export ANTHROPIC_API_KEY=your_key_here\n"
                "Or run with --no-llm to skip LLM analysis."
            )
        self.client = _anthropic.Anthropic(api_key=api_key)

    def analyze_url(self, url: str, features: dict) -> dict:
        feature_summary = self._summarize_url_features(features)
        prompt = f"""Analyze this URL for phishing:

URL: {url}

Pre-computed feature flags:
{feature_summary}

Respond with JSON only."""
        return self._call_llm(prompt)

    def analyze_email(self, email_text: str, features: dict) -> dict:
        feature_summary = self._summarize_email_features(features)
        prompt = f"""Analyze this email for phishing:

--- EMAIL START ---
{email_text[:2500]}
--- EMAIL END ---

Pre-computed feature flags:
{feature_summary}

Respond with JSON only."""
        return self._call_llm(prompt)

    def _call_llm(self, prompt: str) -> dict:
        try:
            message = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=512,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = message.content[0].text.strip()
            raw = re.sub(r"```json\s*|```", "", raw).strip()
            parsed = json.loads(raw)
            return {
                "score": float(parsed.get("score", 0.5)),
                "verdict": parsed.get("verdict", "SUSPICIOUS"),
                "explanation": parsed.get("explanation", ""),
                "tactics": parsed.get("tactics", []),
            }
        except json.JSONDecodeError as e:
            return {"score": 0.5, "verdict": "SUSPICIOUS", "explanation": f"LLM parse error: {e}", "tactics": []}
        except Exception as e:
            return {"score": 0.5, "verdict": "SUSPICIOUS", "explanation": f"LLM error: {e}", "tactics": []}

    @staticmethod
    def _summarize_url_features(features: dict) -> str:
        flags = []
        if features.get("has_ip_address"):
            flags.append("- Uses raw IP address")
        if features.get("suspicious_tld"):
            flags.append("- Suspicious/free TLD")
        if features.get("brand_in_subdomain"):
            flags.append("- Brand name in subdomain (possible spoofing)")
        if features.get("homoglyph_suspicious"):
            flags.append("- Possible homoglyph/typosquat")
        if features.get("hostname_entropy", 0) > 3.8:
            flags.append(f"- High hostname entropy ({features['hostname_entropy']:.2f})")
        if not features.get("has_https"):
            flags.append("- No HTTPS")
        return "\n".join(flags) if flags else "- No major flags from feature extraction"

    @staticmethod
    def _summarize_email_features(features: dict) -> str:
        flags = []
        if features.get("urgency_keyword_count", 0) > 0:
            flags.append(f"- {features['urgency_keyword_count']} urgency keywords")
        if features.get("social_engineering_count", 0) > 0:
            flags.append(f"- {features['social_engineering_count']} social engineering phrases")
        if features.get("sensitive_request_count", 0) > 0:
            flags.append(f"- Requests sensitive info ({features['sensitive_request_count']} indicators)")
        if features.get("has_reply_to_mismatch"):
            flags.append("- Reply-To / From domain mismatch")
        if features.get("url_mismatch_count", 0) > 0:
            flags.append(f"- {features['url_mismatch_count']} display/href URL mismatches")
        return "\n".join(flags) if flags else "- No major flags from feature extraction"
