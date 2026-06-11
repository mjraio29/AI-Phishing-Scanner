# AI Phishing Scanner

# AI Phishing Scanner

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)
![Claude API](https://img.shields.io/badge/Claude-API%20Powered-CC785C?style=for-the-badge&logo=anthropic&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)

A dual-layer phishing detection tool combining traditional machine learning feature engineering with LLM-powered semantic analysis. Scans both URLs and emails.

Built by Michael Raio as part of an AI/cybersecurity portfolio.

---

## How It Works

Detection uses two complementary layers:

**Layer 1 — ML Feature Classifier**
Extracts ~18 numerical features from URLs (entropy, TLD, subdomain structure, character ratios) and ~14 features from emails (urgency keywords, social engineering phrases, header anomalies). A trained Random Forest classifier scores each input. Falls back to rule-based heuristics if no trained model is found.

**Layer 2 — LLM Semantic Analysis (Claude)**
Sends the URL or email to Claude with the pre-computed feature flags. The LLM evaluates social engineering tactics, brand impersonation, and contextual intent that rules alone can miss. Scores are blended (40% ML, 60% LLM).

Final verdict: **CLEAN** / **SUSPICIOUS** / **PHISHING**

---

## Quickstart

```bash
git clone https://github.com/mjraio29/AI-Phishing-Scanner
cd AI-Phishing-Scanner
pip install -r requirements.txt
export ANTHROPIC_API_KEY=your_key_here
```

**Scan a URL:**
```bash
python main.py --url "http://paypa1-secure.tk/login"
```

**Scan an email:**
```bash
python main.py --email samples/phishing_email.txt
```

**Offline mode (no LLM):**
```bash
python main.py --url "http://suspicious-site.xyz" --no-llm
```

**JSON output (for integrations):**
```bash
python main.py --url "http://example.com" --json
```

**Verbose output:**
```bash
python main.py --email samples/phishing_email.txt --verbose
```

---

## Train the ML Model

The tool works out of the box using heuristics. To train a proper ML model:

```bash
python train.py
```

For best results, replace the synthetic training data in `train.py` with real labeled datasets:
- **URLs**: [PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) (UCI ML Repository)
- **Emails**: [CEAS 2008 Spam Dataset](http://www.ceas.cc/2008/) or [Enron-Spam Corpus](https://www2.aueb.gr/users/ion/data/enron-spam/)

---

## Project Structure
head -20 README.md
git log --oneline -3
