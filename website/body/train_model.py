import os, re, pandas as pd, joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

DATASET_PATH = "datasets/PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL_DIR    = "model"
MODEL_PATH   = os.path.join(MODEL_DIR, "phishlens_model.pkl")
NAMES_PATH   = os.path.join(MODEL_DIR, "feature_names.pkl")

SHORTENERS = {"bit.ly","tinyurl.com","goo.gl","ow.ly","t.co","buff.ly","adf.ly","is.gd","rb.gy","cutt.ly","shorturl.at"}
SUSPICIOUS_KEYWORDS = ["login","signin","verify","update","secure","account","banking","paypal","ebay","amazon","confirm","password","credential","webscr","free","lucky","bonus","support","alert","suspended"]

def extract_features(url):
    url = str(url).strip()
    try:
        domain_part = re.split(r"https?://", url)[-1].split("/")[0].lower()
        domain_only = domain_part.split(":")[0]
    except:
        domain_part = ""
        domain_only = ""
    parts = [p for p in domain_only.split(".") if p]
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

FEATURE_NAMES = list(extract_features("http://example.com").keys())

print("="*60)
print("  PhishLens - Random Forest Trainer")
print("="*60)

print("\n[1/5] Loading dataset...")
df = pd.read_csv(DATASET_PATH, encoding="utf-8", encoding_errors="ignore")
print(f"      Rows loaded: {len(df):,}")

url_col   = next(c for c in df.columns if c.strip().upper() == "URL")
label_col = next(c for c in df.columns if c.strip().lower() == "label")
df = df[[url_col, label_col]].dropna()
df.columns = ["url", "label"]
df["label"] = pd.to_numeric(df["label"], errors="coerce")
df = df.dropna(subset=["label"]).copy()
df["label"] = df["label"].astype(int)
print(f"      Clean rows:  {len(df):,}")
print(f"      Phishing:    {(df['label']==1).sum():,}")
print(f"      Legitimate:  {(df['label']==0).sum():,}")

print("\n[2/5] Extracting features... (1-3 mins)")
X = pd.DataFrame(list(df["url"].apply(extract_features)))[FEATURE_NAMES]
y = df["label"]
print(f"      Shape: {X.shape}")

print("\n[3/5] Splitting 80/20...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
print(f"      Train: {len(X_train):,} | Test: {len(X_test):,}")

print("\n[4/5] Training Random Forest...")
clf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=42, class_weight="balanced")
clf.fit(X_train, y_train)
print("      Done!")

print("\n[5/5] Evaluating...")
y_pred = clf.predict(X_test)
print(f"\n  *** Accuracy: {accuracy_score(y_test, y_pred)*100:.2f}% ***\n")
print(classification_report(y_test, y_pred, target_names=["Legitimate","Phishing"]))

print("  Feature Importances:")
for name, imp in sorted(zip(FEATURE_NAMES, clf.feature_importances_), key=lambda x: -x[1]):
    print(f"    {name:<22} {imp:.4f}  {'='*int(imp*40)}")

os.makedirs(MODEL_DIR, exist_ok=True)
joblib.dump(clf,           MODEL_PATH)
joblib.dump(FEATURE_NAMES, NAMES_PATH)
print(f"\n  Model saved -> {MODEL_PATH}")
print(f"  Names saved -> {NAMES_PATH}")
print("\n  Done! Run app.py to start PhishLens.")