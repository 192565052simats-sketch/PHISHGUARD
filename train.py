"""
Module 2 (training part) - Random Forest model.

python train.py                 -> trains on a built-in generated dataset (works offline)
python train.py --csv data.csv  -> trains on a REAL dataset (columns: url,label ; label 1=phishing 0=legit)
"""
import argparse, json, random, string, sys
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix)
import features as F

R = random.Random(42)
WORDS = ("alpha bright cloud delta eagle forest green harbor island jungle kite lemon "
         "mango north ocean pearl quartz river solar tiger urban violet willow xenon "
         "yellow zebra tech soft media shop store news blog travel health edu learn "
         "design studio market food cafe photo music games sports fitness books "
         "cars homes garden energy finance consult labs works group global city "
         "info point hub zone world plus prime smart easy quick fresh royal").split()
LEGIT_TLDS = ["com"] * 6 + ["org", "net", "in", "co.in", "io", "edu", "ac.in", "info", "co.uk", "dev"]
BAD_TLDS = list(F.SUSPICIOUS_TLDS)
PATHS_OK = ["", "/", "/about", "/contact", "/products", "/blog", "/news", "/services",
            "/careers", "/faq", "/help", "/pricing", "/team", "/events", "/gallery",
            "/login", "/account", "/signin", "/support", "/search", "/cart", "/profile"]
BRAND_LIST = [b for b in F.BRANDS if len(b) >= 4]
KW = ["login", "signin", "verify", "update", "secure", "account", "confirm", "banking",
      "password", "wallet", "suspend", "unlock", "billing", "recover", "validate", "support"]


def rword(n=1):
    return "".join(R.choice(WORDS) for _ in range(n))


def rrand(n):
    return "".join(R.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def legit_url():
    r = R.random()
    if r < 0.30:  # famous trusted domain
        d = R.choice(sorted(F.TRUSTED_DOMAINS))
        host = ("www." if R.random() < 0.5 else R.choice(["", "mail.", "accounts.", "docs.", "support.", "m."])) + d
    else:
        d = rword(R.choice([1, 1, 2, 2, 3]))
        if R.random() < 0.08:
            d = rword() + "-" + rword()
        host = ("www." if R.random() < 0.55 else "") + d + "." + R.choice(LEGIT_TLDS)
    scheme = "https" if R.random() < 0.85 else "http"
    path = R.choice(PATHS_OK)
    if R.random() < 0.35:
        path += "/" + "-".join(R.choice(WORDS) for _ in range(R.randint(2, 7)))
    if R.random() < 0.15:
        path += "/" + str(R.randint(2015, 2026)) + "/" + str(R.randint(1, 12))
    if R.random() < 0.2:
        path += "?" + "&".join(f"{R.choice(['id','q','page','ref','lang','cat'])}={R.randint(1,999)}" for _ in range(R.randint(1, 3)))
    if R.random() < 0.05:
        path += ".html"
    return f"{scheme}://{host}{path}"


def phish_url():
    kinds = ["ip", "brand_sub", "brand_hyphen", "typo", "at", "tld_kw", "short",
             "chain", "puny", "rand_php", "brand_path", "hacked", "port", "encoded", "digits"]
    k = R.choice(kinds)
    scheme = "https" if R.random() < 0.45 else "http"
    brand = R.choice(BRAND_LIST)
    kw = lambda n=1: "-".join(R.sample(KW, n))
    if k == "ip":
        ip = ".".join(str(R.randint(1, 255)) for _ in range(4))
        port = (":" + str(R.choice([8080, 8000, 81, 8888]))) if R.random() < 0.3 else ""
        return f"http://{ip}{port}/{R.choice(['login','verify','secure','account','bank'])}/{R.choice(['index.php','signin.html','update.php',''])}"
    if k == "brand_sub":
        return f"{scheme}://{brand}.{kw()}.{rword()}.{R.choice(BAD_TLDS + ['com','net'])}/{R.choice(KW)}"
    if k == "brand_hyphen":
        return f"{scheme}://{brand}-{kw(R.randint(1,2))}.{R.choice(BAD_TLDS + ['com','net','info','online','site'])}/{R.choice(['','login','signin.php','verify'])}"
    if k == "typo":
        b = R.choice([x for x in BRAND_LIST if len(x) >= 5])
        i = R.randrange(len(b))
        mode = R.random()
        if mode < 0.4:
            t = b.replace("o", "0").replace("l", "1") if any(c in b for c in "ol") else b + b[-1]
        elif mode < 0.7:
            t = b[:i] + b[i + 1:]
        else:
            t = b[:i] + b[i] + b[i:]
        if t == b:
            t = b + "s"
        return f"{scheme}://www.{t}.{R.choice(['com','net','in','co','org'] + BAD_TLDS[:6])}/{R.choice(['login','account','verify',''])}"
    if k == "at":
        return f"http://{R.choice(['www.'+brand+'.com', brand+'.com', 'accounts.google.com'])}@{rrand(R.randint(5,9))}.{R.choice(BAD_TLDS + ['com','ru'])}/{R.choice(KW)}"
    if k == "tld_kw":
        return f"{scheme}://{rword(R.randint(1,2))}-{kw()}.{R.choice(BAD_TLDS)}/{R.choice(KW)}/{rrand(6)}"
    if k == "short":
        return f"http://{R.choice(sorted(F.SHORTENERS))}/{rrand(R.randint(5,8))}"
    if k == "chain":
        return f"{scheme}://{'.'.join(R.sample(KW,R.randint(2,4)))}.{rword()}.{R.choice(['com','net','xyz','top'])}/{R.choice(KW)}.php?id={rrand(10)}"
    if k == "puny":
        return f"{scheme}://xn--{rrand(R.randint(6,10))}-{R.choice(['9ua','bva','cwa'])}.{R.choice(['com','net','xyz'])}/{R.choice(KW)}"
    if k == "rand_php":
        return f"http://{rrand(R.randint(8,14))}.{R.choice(BAD_TLDS + ['com','net'])}/{R.choice(KW)}.php?email={rrand(6)}%40mail.com&session={rrand(24)}"
    if k == "brand_path":
        return f"{scheme}://{rword(2)}.{R.choice(['com','net','org','info'])}/{brand}/{R.choice(KW)}/index.php"
    if k == "hacked":
        return f"{scheme}://{'www.' if R.random()<.5 else ''}{rword(2)}.{R.choice(['com','org','net','in'])}/wp-includes/{R.choice(['verify','secure','signin','update'])}/{R.choice(KW)}.php?cmd=_{R.choice(KW)}"
    if k == "port":
        return f"http://{rword(2)}-{kw()}.{R.choice(['com','net'] + BAD_TLDS[:5])}:{R.choice([8080,8443,2083,81])}/{R.choice(KW)}"
    if k == "encoded":
        return f"{scheme}://{rword()}.{R.choice(['com','net','xyz'])}/%2e%2e/{R.choice(KW)}%20{R.choice(KW)}/%{R.randint(10,99)}%{R.randint(10,99)}?u={rrand(12)}"
    return f"http://{rword()}{R.randint(100,99999)}.{R.choice(BAD_TLDS + ['com','net'])}/{R.choice(KW)}{R.randint(1,9)}/index.php"


def build_dataset(n=7000):
    rows = []
    for _ in range(n):
        rows.append((legit_url(), 0))
        rows.append((phish_url(), 1))
    return pd.DataFrame(rows, columns=["url", "label"])


def featurize(df):
    X, y, kept = [], [], []
    for u, lab in zip(df["url"], df["label"]):
        try:
            X.append(F.vector(F.analyze_structure(u)["features"]))
            y.append(int(lab)); kept.append(u)
        except Exception:
            continue
    return np.array(X), np.array(y), kept


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", help="CSV with columns url,label (1=phishing, 0=legit)")
    a = ap.parse_args()
    if a.csv:
        df = pd.read_csv(a.csv)
        df.columns = [c.lower() for c in df.columns]
        if "label" not in df.columns and "status" in df.columns:
            df["label"] = df["status"].map(lambda s: 1 if str(s).lower() in ("phishing", "1", "bad") else 0)
        source = f"real dataset: {a.csv}"
    else:
        df = build_dataset()
        source = "built-in generated dataset (offline)"
    X, y, _ = featurize(df)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=7, stratify=y)
    clf = RandomForestClassifier(n_estimators=250, max_depth=14, min_samples_leaf=2,
                                 random_state=7, n_jobs=-1, class_weight="balanced")
    clf.fit(Xtr, ytr)
    pred = clf.predict(Xte)
    cv = cross_val_score(RandomForestClassifier(n_estimators=100, max_depth=14, random_state=7, n_jobs=-1),
                         X, y, cv=5)
    cm = confusion_matrix(yte, pred).tolist()
    metrics = {
        "source": source, "samples": int(len(y)),
        "accuracy": round(accuracy_score(yte, pred), 4),
        "precision": round(precision_score(yte, pred), 4),
        "recall": round(recall_score(yte, pred), 4),
        "f1": round(f1_score(yte, pred), 4),
        "cv_mean": round(float(cv.mean()), 4),
        "confusion_matrix": cm,
        "importance": sorted(
            [{"name": n, "label": F.FEATURE_LABELS[n], "value": round(float(v), 4)}
             for n, v in zip(F.FEATURE_NAMES, clf.feature_importances_)],
            key=lambda d: -d["value"]),
    }
    joblib.dump(clf, "model.pkl")
    json.dump(metrics, open("metrics.json", "w"), indent=2)
    print(json.dumps({k: v for k, v in metrics.items() if k != "importance"}, indent=2))
    print("Top features:", [d["label"] for d in metrics["importance"][:6]])
    print("Saved model.pkl and metrics.json")


if __name__ == "__main__":
    main()
