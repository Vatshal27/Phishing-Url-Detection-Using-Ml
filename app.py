from flask import Flask, render_template, request
import joblib
import pandas as pd
import numpy as np
import re
import math, collections
import tldextract
from urllib.parse import urlparse

# ------------------- Initialize Flask -------------------
app = Flask(
    __name__,
    static_folder='static',
    static_url_path='/static',
    template_folder='templates'
)

# ------------------- Load Trained Artifacts -------------------
model = joblib.load("phishing_rf_best_model.pkl")
scaler = joblib.load("phishing_scaler.pkl")
feature_columns = joblib.load("feature_columns.pkl")

# ------------------- Utility Functions -------------------

def normalize_url(url):
    """Ensure URL starts with http:// or https://"""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def entropy_of(s):
    """Calculate Shannon entropy of a string"""
    if not s:
        return 0.0
    counts = collections.Counter(s)
    probs = [c / len(s) for c in counts.values()]
    return -sum(p * math.log2(p) for p in probs)


# ------------------- Feature Extraction -------------------

def extract_url_features(url):
    """Extract handcrafted and statistical URL features"""
    url = normalize_url(url)
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    host = parsed.netloc or ''
    path = parsed.path or ''

    f = {}
    # Basic statistical features
    f['length_url'] = len(url)
    f['length_hostname'] = len(host)
    f['ip'] = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host) else 0
    f['nb_dots'] = url.count('.')
    f['nb_hyphens'] = url.count('-')
    f['nb_at'] = url.count('@')
    f['nb_qm'] = url.count('?')
    f['nb_and'] = url.count('&')
    f['nb_eq'] = url.count('=')
    f['nb_slash'] = url.count('/')
    f['https_token'] = 1 if 'https' in host.lower() else 0
    f['ratio_digits_url'] = sum(c.isdigit() for c in url) / max(1, len(url))
    f['ratio_digits_host'] = sum(c.isdigit() for c in host) / max(1, len(host))
    f['nb_subdomains'] = len(ext.subdomain.split('.')) if ext.subdomain else 0
    f['prefix_suffix'] = 1 if '-' in ext.domain else 0
    f['shortening_service'] = 1 if any(s in host for s in ['bit.ly','tinyurl','t.co','goo.gl','ow.ly']) else 0
    f['suspecious_tld'] = 1 if ext.suffix in ['cf','ga','gq','ml','tk'] else 0
    f['phish_hints'] = int(any(w in url.lower() for w in ['secure','account','login','verify','update','paypal','bank']))

    # New heuristic features
    f['path_len'] = len(path)
    f['path_entropy'] = entropy_of(path)
    last_token = path.rstrip('/').split('/')[-1] if path.rstrip('/') else ''
    f['last_token_len'] = len(last_token)
    f['last_token_entropy'] = entropy_of(last_token)
    f['last_token_is_hex16plus'] = 1 if re.match(r'^[0-9a-fA-F]{16,}$', last_token) else 0
    f['has_validation_keyword'] = 1 if any(k in path.lower() for k in ['validate','validation','secure','login','account','verify']) else 0

    return f


# ------------------- Heuristic Phish Detection -------------------

def heuristic_phish(url):
    """Rule-based pre-screen for obviously malicious URLs"""
    url = url.strip().rstrip(" |,;")
    if not url.startswith(("http://","https://")):
        url = "http://" + url
    u = urlparse(url)
    host = (u.netloc or "").lower()
    path = (u.path or "").lower()

    # Obvious malicious patterns
    if '@' in url: 
        return True, "contains_at_symbol"
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
        return True, "host_is_ip"
    if re.search(r'/[0-9a-f]{16,}/?$', path) or re.search(r'/[0-9a-z]{20,}', path):
        return True, "long_random_token_in_path"
    if any(k in path for k in ('/validate','/validation','/secure','/account','/login','/verify')):
        return True, "suspicious_path_keyword"
    if len(path) > 150 or url.count('/') > 6:
        return True, "long_path_or_too_many_segments"
    if any(short in host for short in ('bit.ly','t.co','tinyurl','goo.gl','ow.ly','is.gd')):
        return True, "shortener"
    
    return False, None


# ------------------- Routes -------------------

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/predict', methods=['POST'])
def predict():
    url_raw = request.form['url']
    url = normalize_url(url_raw)

    # 1. Heuristic pre-check
    is_phish_h, reason = heuristic_phish(url)
    if is_phish_h:
        print(f"[HEURISTIC FLAGGED] {url} | reason = {reason}")
        return render_template(
            'result.html',
            url=url_raw,
            label="Phishing",
            confidence=99.0,
            color="danger"
        )

    # 2. Extract features
    feats = extract_url_features(url)
    data = pd.DataFrame([{c: feats.get(c, 0) for c in feature_columns}])

    print("\n--- URL FEATURE VECTOR ---")
    print(url)
    print(data.T)

    # 3. Model prediction
    X = scaler.transform(data)
    proba = model.predict_proba(X)[0]
    pred = model.predict(X)[0]

    # 4. Determine phishing probability
    if hasattr(model, 'classes_'):
        try:
            phish_index = list(model.classes_).index(1)
            phish_prob = proba[phish_index]
        except ValueError:
            phish_prob = proba[1] if len(proba) > 1 else proba[0]
    else:
        phish_prob = proba[1] if len(proba) > 1 else proba[0]

    print("MODEL classes:", getattr(model, 'classes_', None))
    print("PROBABILITIES:", proba)
    print("Phish probability:", phish_prob)

    # 5. Apply decision threshold
    threshold = 0.53  # Lowered for better phishing recall
    if phish_prob is not None and phish_prob >= threshold:
        label = "Phishing"
        confidence = round(phish_prob * 100, 2)
    else:
        label = "Legitimate"
        confidence = round((1 - phish_prob) * 100, 2) if phish_prob is not None else 50.0

    # 6. Render result
    return render_template(
        'result.html',
        url=url_raw,
        label=label,
        confidence=confidence,
        color="danger" if label == "Phishing" else "success"
    )


# ------------------- Run App -------------------

if __name__ == "__main__":
    app.run(debug=True)
