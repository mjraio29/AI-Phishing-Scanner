import re, json, os
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

URGENCY = ['urgent','immediately','verify','suspend','expire','limited','action required','click here']
SOCIAL = ['dear customer','dear user','valued member','winner','congratulations','free gift']
SENSITIVE = ['password','ssn','credit card','bank account','login','credentials']

class EmailScanner:
    def __init__(self, use_llm=True):
        self.use_llm = use_llm and ANTHROPIC_AVAILABLE

    def _extract_features(self, text):
        lower = text.lower()
        urls = re.findall(r'https?://\S+', text)
        return {
            "urgency_count": sum(lower.count(w) for w in URGENCY),
            "social_eng_count": sum(lower.count(w) for w in SOCIAL),
            "sensitive_word_count": sum(lower.count(w) for w in SENSITIVE),
            "url_count": len(urls),
            "exclamation_count": text.count("!"),
            "caps_ratio": round(sum(c.isupper() for c in text)/max(len(text),1), 4),
            "word_count": len(text.split()),
            "has_html": int("<html" in lower or "href=" in lower),
            "reply_to_mismatch": int("reply-to:" in lower and "from:" in lower),
            "has_attachment_ref": int(any(w in lower for w in ["attachment","attached","open the file"])),
            "generic_greeting": int(any(g in lower for g in ["dear customer","dear user","dear account holder"])),
            "request_credentials": int(any(w in lower for w in ["enter your password","verify your password","confirm your details"])),
            "link_count": lower.count("http"),
            "suspicious_phrases": sum(lower.count(w) for w in ["act now","limited time","risk free","guarantee"]),
        }

    def _heuristic_score(self, f):
        s = 0.0
        if f["urgency_count"] >= 2: s += 0.2
        if f["social_eng_count"] >= 1: s += 0.15
        if f["sensitive_word_count"] >= 2: s += 0.2
        if f["request_credentials"]: s += 0.25
        if f["generic_greeting"]: s += 0.1
        if f["caps_ratio"] > 0.15: s += 0.1
        return min(s, 1.0)

    def _llm_score(self, text, features):
        if not self.use_llm: return 0.0, ""
        try:
            client = anthropic.Anthropic()
            flags = [k for k,v in features.items() if v]
            prompt = "Analyze this email for phishing:\n" + text[:1500] + "\nFlags: " + str(flags) + '\nRespond JSON only: {"score": 0.0, "analysis": "reason"}'
            msg = client.messages.create(model="claude-opus-4-6", max_tokens=200, messages=[{"role":"user","content":prompt}])
            data = json.loads(msg.content[0].text.strip())
            return float(data["score"]), data["analysis"]
        except Exception as e:
            return 0.0, str(e)

    @staticmethod
    def _verdict(score):
        return "PHISHING" if score >= 0.65 else "SUSPICIOUS" if score >= 0.35 else "CLEAN"

    def scan(self, email_text):
        f = self._extract_features(email_text)
        ml = self._heuristic_score(f)
        llm, analysis = self._llm_score(email_text, f)
        score = (0.4*ml + 0.6*llm) if self.use_llm and llm > 0 else ml
        flags = []
        if f["request_credentials"]: flags.append("Requests credentials")
        if f["urgency_count"] >= 2: flags.append("Multiple urgency phrases")
        if f["generic_greeting"]: flags.append("Generic greeting")
        if f["social_eng_count"]: flags.append("Social engineering language")
        target = email_text[:80] + "..." if len(email_text) > 80 else email_text
        return {"verdict": self._verdict(score), "score": round(score,4), "target": target, "ml_features": f, "llm_analysis": analysis, "flags": flags}
