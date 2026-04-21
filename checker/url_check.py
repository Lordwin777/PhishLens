import re
import csv
import os
import joblib
import pandas as pd
from urllib.parse import urlparse

# ─────────────────────────────────────────
# BLACKLIST LOADER
# ─────────────────────────────────────────

BLACKLIST = set()
BLACKLIST_DOMAINS = set()

WHITELIST = {
    'google.com', 'www.google.com',
    'youtube.com', 'www.youtube.com',
    'facebook.com', 'www.facebook.com',
    'instagram.com', 'www.instagram.com',
    'twitter.com', 'www.twitter.com',
    'microsoft.com', 'www.microsoft.com',
    'apple.com', 'www.apple.com',
    'amazon.com', 'www.amazon.com',
    'github.com', 'www.github.com',
    'wikipedia.org', 'www.wikipedia.org',
    'linkedin.com', 'www.linkedin.com',
    'reddit.com', 'www.reddit.com',
    'netflix.com', 'www.netflix.com',
    'stackoverflow.com', 'www.stackoverflow.com',
}

def load_blacklist():
    global BLACKLIST, BLACKLIST_DOMAINS

    try:
        with open('datasets/Phishing URLs.csv', 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['Type'].strip().lower() == 'phishing':
                    url = row['url'].strip().lower()
                    BLACKLIST.add(url)
                    try:
                        BLACKLIST_DOMAINS.add(urlparse(url).netloc)
                    except:
                        pass
        print(f"✅ Dataset 1 loaded: {len(BLACKLIST)} phishing URLs")
    except FileNotFoundError:
        print("⚠️  Dataset 1 not found")

    c1 = len(BLACKLIST)
    try:
        with open('datasets/URL dataset.csv', 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['type'].strip().lower() == 'phishing':
                    url = row['url'].strip().lower()
                    BLACKLIST.add(url)
                    try:
                        BLACKLIST_DOMAINS.add(urlparse(url).netloc)
                    except:
                        pass
        print(f"✅ Dataset 2 loaded: {len(BLACKLIST) - c1} more phishing URLs")
    except FileNotFoundError:
        print("⚠️  Dataset 2 not found")

    c2 = len(BLACKLIST)
    try:
        with open('datasets/PhiUSIIL_Phishing_URL_Dataset.csv', 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['label'].strip() == '1':
                    url = row['URL'].strip().lower()
                    BLACKLIST.add(url)
                    try:
                        BLACKLIST_DOMAINS.add(urlparse(url).netloc)
                    except:
                        pass
        print(f"✅ Dataset 3 loaded: {len(BLACKLIST) - c2} more phishing URLs")
    except FileNotFoundError:
        print("⚠️  Dataset 3 not found")

    BLACKLIST_DOMAINS -= WHITELIST
    print(f"✅ Total: {len(BLACKLIST)} URLs | {len(BLACKLIST_DOMAINS)} domains indexed\n")

load_blacklist()

# ─────────────────────────────────────────
# RANDOM FOREST MODEL LOADER
# ─────────────────────────────────────────

ML_MODEL = None
ML_FEATURE_NAMES = None

def load_ml_model():
    global ML_MODEL, ML_FEATURE_NAMES
    model_path = os.path.join('model', 'phishlens_model.pkl')
    names_path = os.path.join('model', 'feature_names.pkl')
    try:
        ML_MODEL        = joblib.load(model_path)
        ML_FEATURE_NAMES = joblib.load(names_path)
        print(f"✅ ML model loaded: Random Forest ({ML_MODEL.n_estimators} trees)")
    except FileNotFoundError:
        print("⚠️  ML model not found — run train_model.py first")

load_ml_model()

# ─────────────────────────────────────────
# ML FEATURE EXTRACTOR
# ─────────────────────────────────────────

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "buff.ly",
    "adf.ly", "is.gd", "rb.gy", "cutt.ly", "shorturl.at"
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "account",
    "banking", "paypal", "ebay", "amazon", "confirm", "password",
    "credential", "webscr", "free", "lucky", "bonus", "support",
    "alert", "suspended"
]

def extract_ml_features(url):
    url = str(url).strip()
    try:
        domain_part = re.split(r"https?://", url)[-1].split("/")[0].lower()
        domain_only = domain_part.split(":")[0]
    except:
        domain_part = ""
        domain_only = ""
    parts  = [p for p in domain_only.split(".") if p]
    length = len(url)

    return {
        "has_ip":              1 if re.search(r"(\d{1,3}\.){3}\d{1,3}", url) else 0,
        "url_length":          0 if length < 54 else (1 if length <= 75 else 2),
        "is_shortened":        1 if domain_part in SHORTENERS else 0,
        "has_at":              1 if "@" in url else 0,
        "double_slash":        1 if url.find("//", 7) != -1 else 0,
        "has_hyphen":          1 if "-" in domain_only else 0,
        "subdomain":           0 if len(parts) <= 2 else (1 if len(parts) == 3 else 2),
        "has_https":           0 if url.lower().startswith("https") else 1,
        "https_in_domain":     1 if "https" in domain_only else 0,
        "suspicious_keywords": 1 if any(kw in url.lower() for kw in SUSPICIOUS_KEYWORDS) else 0,
    }

def run_ml_model(url):
    """Returns (prediction, confidence_pct) or (None, None) if model not loaded."""
    if ML_MODEL is None or ML_FEATURE_NAMES is None:
        return None, None
    try:
        features = extract_ml_features(url)
        X = pd.DataFrame([features])[ML_FEATURE_NAMES]
        prediction = ML_MODEL.predict(X)[0]             # 0 = legit, 1 = phishing
        proba      = ML_MODEL.predict_proba(X)[0]       # [prob_legit, prob_phish]
        confidence = round(float(proba[1]) * 100, 1)    # phishing probability %
        return int(prediction), confidence
    except Exception as e:
        print(f"⚠️  ML prediction error: {e}")
        return None, None

# ─────────────────────────────────────────
# BLACKLIST CHECK
# ─────────────────────────────────────────

def check_blacklist(url):
    url_clean = url.strip().lower()
    try:
        domain = urlparse(url_clean).netloc
    except:
        return 1, "Not found in blacklist"

    if domain in WHITELIST:
        return 1, "Trusted domain"

    if url_clean in BLACKLIST:
        return -1, "Exact URL found in phishing database"

    if domain in BLACKLIST_DOMAINS:
        return -1, "Domain found in phishing database"

    return 1, "Not found in blacklist"

# ─────────────────────────────────────────
# URL RULES
# ─────────────────────────────────────────

def check_url_rules(url):
    results = {}
    domain = urlparse(url).netloc

    ip_pattern = re.compile(r'http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    results['has_ip_address'] = -1 if ip_pattern.match(url) else 1

    url_length = len(url)
    if url_length < 54:
        results['url_length'] = 1
    elif url_length <= 75:
        results['url_length'] = 0
    else:
        results['url_length'] = -1

    shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
    results['is_shortened'] = -1 if any(s in url for s in shorteners) else 1

    results['has_at_symbol'] = -1 if '@' in url else 1

    results['double_slash_redirect'] = -1 if url.rfind('//') > 7 else 1

    results['has_hyphen_in_domain'] = -1 if '-' in domain else 1

    clean_domain = domain.replace('www.', '')
    dot_count = clean_domain.count('.')
    if dot_count == 1:
        results['subdomain'] = 1
    elif dot_count == 2:
        results['subdomain'] = 0
    else:
        results['subdomain'] = -1

    results['has_https'] = 1 if url.startswith('https') else -1

    results['https_in_domain'] = -1 if 'https' in domain.lower() else 1

    keywords = ['login', 'verify', 'secure', 'account', 'update',
                'confirm', 'banking', 'password', 'signin', 'webscr',
                'ebayisapi', 'paypal', 'free', 'lucky', 'bonus']
    results['suspicious_keywords'] = -1 if any(w in url.lower() for w in keywords) else 1

    return results

# ─────────────────────────────────────────
# SCANNER  (3-layer hybrid)
# ─────────────────────────────────────────

def scan(url):
    # ── Layer 1: Blacklist ──
    blacklist_score, blacklist_reason = check_blacklist(url)

    # ── Layer 2: Rule-based ──
    rule_results = check_url_rules(url)

    # ── Layer 3: Random Forest ML ──
    ml_prediction, ml_confidence = run_ml_model(url)

    # ── Combine rule scores ──
    all_results = {'in_blacklist': blacklist_score}
    all_results.update(rule_results)

    phishing_count  = sum(1 for v in all_results.values() if v == -1)
    suspicious_count = sum(1 for v in all_results.values() if v == 0)
    max_score       = len(all_results)

    # ── Rule-based confidence ──
    rules_confidence = round((phishing_count / max_score) * 100, 1)

    # ── Combined confidence (weighted average) ──
    # Blacklist hit → 100% phishing instantly
    # Otherwise: 60% weight on rules, 40% weight on ML
    if blacklist_score == -1:
        combined_confidence = 100.0
    elif ml_confidence is not None:
        combined_confidence = round((rules_confidence * 0.6) + (ml_confidence * 0.4), 1)
    else:
        combined_confidence = rules_confidence

    # ── Final verdict logic ──
    ml_says_phishing = (ml_prediction == 1) if ml_prediction is not None else False

    if blacklist_score == -1:
        verdict, verdict_icon, reason = "PHISHING", "🚨", blacklist_reason

    elif phishing_count >= 4 or (phishing_count >= 3 and ml_says_phishing):
        verdict, verdict_icon, reason = "PHISHING", "🚨", f"{phishing_count} phishing rules triggered" + (" + ML confirms" if ml_says_phishing else "")

    elif phishing_count == 3 or (phishing_count == 2 and ml_says_phishing):
        verdict, verdict_icon, reason = "LIKELY PHISHING", "🚨", f"{phishing_count} phishing rules triggered" + (" + ML confirms" if ml_says_phishing else "")

    elif phishing_count == 2 or suspicious_count >= 2 or (phishing_count == 1 and ml_says_phishing):
        verdict, verdict_icon, reason = "SUSPICIOUS", "⚠️", f"{phishing_count} phishing flags, {suspicious_count} suspicious flags"

    elif phishing_count == 1 or suspicious_count == 1:
        verdict, verdict_icon, reason = "SLIGHTLY SUSPICIOUS", "⚠️", f"{phishing_count} phishing flag, {suspicious_count} suspicious flag"

    else:
        verdict, verdict_icon, reason = "SAFE", "✅", "No phishing indicators found"

    # ── ML label for display ──
    if ml_prediction is None:
        ml_verdict = "Model not loaded"
    elif ml_prediction == 1:
        ml_verdict = f"Phishing ({ml_confidence}%)"
    else:
        ml_verdict = f"Legitimate ({100 - ml_confidence}% safe)"

    return {
        "url":              url,
        "verdict":          verdict,
        "verdict_icon":     verdict_icon,
        "confidence":       combined_confidence,
        "reason":           reason,
        "phishing_count":   phishing_count,
        "suspicious_count": suspicious_count,
        "blacklist_hit":    blacklist_score == -1,

        # Layer breakdown (shown separately in UI)
        "layer_blacklist":  "Hit 🚨" if blacklist_score == -1 else "Clear ✅",
        "layer_rules":      f"{phishing_count} flags ({rules_confidence}%)",
        "layer_ml":         ml_verdict,

        "details": all_results
    }