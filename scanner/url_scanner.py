import re, math, os, json
from urllib.parse import urlparse
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click'}
BRANDS = ['paypal','amazon','apple','microsoft','google','facebook','netflix','bank','secure','login','verify']

class URLScanner:
    def __init__(self, use_llm=True):
        self.use_llm = use_llm and ANTHROPIC_AVAILABLE

    def _extract_features(self, url):
        p = urlparse(url)
        domain = p.netloc or ""
        path = p.path or ""
        def entropy(s):
            if not s: return 0.0
            freq = {c: s.count(c)/len(s) for c in set(s)}
            return -sum(v*math.log2(v) for v in freq.values())
        tld = "." + domain.split(".")[-1] if "." in domain else ""
        subs = domain.split(".")[:-2] if domain.count(".") > 1 else []
        return {
            "url_length": len(url), "domain_length": len(domain),
            "path_length": len(path), "dot_count": url.count("."),
            "hyphen_count": domain.count("-"), "digit_count": sum(c.isdigit() for c in domain),
            "special_char_count": sum(c in "@?=&%" for c in url),
            "subdomain_count": len(subs), "entropy": round(entropy(domain), 4),
            "suspicious_tld": int(tld.lower() in SUSPICIOUS_TLDS),
            "has_ip": int(bool(re.match(r"\d+\.\d+\.\d+\.\d+", domain))),
            "has_https": int(p.scheme == "https"),
            "brand_in_subdomain": int(any(b in ".".join(subs).lower() for b in BRANDS)),
            "brand_in_path": int(any(b in path.lower() for b in BRANDS)),
            "double_slash_redirect": int("//" in path),
            "hex_encoding": int("%" in url),
            "query_length": len(p.query),
            "path_depth": path.count("/"),
        }

    def _heuristic_score(self, f):
        s = 0.0
        if f["has_ip"]: s += 0.3
        if f["suspicious_tld"]: s += 0.2
        if f["brand_in_subdomain"]: s += 0.25
        if f["hyphen_count"] > 2: s += 0.1
        if f["url_length"] > 75: s += 0.1
        if f["entropy"] > 3.5: s += 0.1
        if f["hex_encoding"]: s += 0.05
        return min(s, 1.0)

    def _llm_score(self, url, features):
        if not self.use_llm: return 0.0, ""
        try:
            client = anthropic.Anthropic()
            flags = [k for k,v in features.items() if v and k != "has_https"]
            prompt = "Analyze this URL for phishing: " + url + "\nFlags: " + str(flags) + '\nRespond JSON only: {"score": 0.0, "analysis": "reason"}'
            msg = client.messages.create(model="claude-opus-4-6", max_tokens=200, messages=[{"role":"user","content":prompt}])
            data = json.loads(msg.content[0].text.strip())
            return float(data["score"]), data["analysis"]
        except Exception as e:
            return 0.0, str(e)

    @staticmethod
    def _verdict(score):
        return "PHISHING" if score >= 0.65 else "SUSPICIOUS" if score >= 0.35 else "CLEAN"

    def scan(self, url):
        f = self._extract_features(url)
        ml = self._heuristic_score(f)
        llm, analysis = self._llm_score(url, f)
        score = (0.4*ml + 0.6*llm) if self.use_llm and llm > 0 else ml
        flags = []
        if f["has_ip"]: flags.append("IP address as domain")
        if f["suspicious_tld"]: flags.append("Suspicious TLD")
        if f["brand_in_subdomain"]: flags.append("Brand in subdomain")
        if f["hyphen_count"] > 2: flags.append("Excessive hyphens")
        return {"verdict": self._verdict(score), "score": round(score,4), "target": url, "ml_features": f, "llm_analysis": analysis, "flags": flags}
