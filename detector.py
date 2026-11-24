"""
Module 2 + 3 - ML detection (Random Forest) and Risk Analysis.
Hybrid: Random Forest probability + transparent rule score + trusted-domain check.
"""
import os
import joblib
import features as F

_HERE = os.path.dirname(os.path.abspath(__file__))
_MODEL = joblib.load(os.path.join(_HERE, "model.pkl"))


def _rule_score(a):
    f, flags, s = a["features"], [], 0.0

    def add(w, text):
        nonlocal s
        s += w
        flags.append(text)

    if f["has_ip"]:
        add(0.55, "Website address is a raw IP address instead of a domain name")
    if f["has_at_symbol"]:
        add(0.55, "Contains '@' - everything before it is ignored by the browser (classic redirect trick)")
    if a["typosquat_of"]:
        add(0.75, f"Look-alike of a well-known site ('{a['typosquat_of']}') - possible typosquatting")
    elif a["brand_hits"]:
        add(0.60, "Uses the brand name '" + "', '".join(a["brand_hits"]) + "' but is NOT the official domain")
    elif a["path_brand"]:
        add(0.45, "Brand name '" + "', '".join(a["path_brand"]) + "' appears in the path of an unrelated domain")
    if a["free_hosting"]:
        add(0.40, f"Hosted on a free/public hosting platform ({a['registered_domain']}) - anyone can publish a site here, so the owner cannot be verified")
    if a["blocklisted"]:
        add(0.90, "MATCHES BLOCKLIST - known phishing/malware test or threat domain")
    if f["has_punycode"]:
        add(0.40, "Punycode (xn--) domain - may hide look-alike foreign characters")
    if f["is_shortener"]:
        add(0.35, "Shortened link - the real destination is hidden")
    if f["suspicious_tld"]:
        add(0.30, "Domain ends with a TLD often abused by phishing sites (." + a["suffix"] + ")")
    if f["keyword_count"]:
        add(min(0.12 * f["keyword_count"], 0.40),
            "Suspicious keywords: " + ", ".join(a["keywords"][:6]))
    if f["num_hyphens_host"] >= 3:
        add(0.20, f"{f['num_hyphens_host']} hyphens in the hostname")
    elif f["num_hyphens_host"] == 2:
        add(0.08, "2 hyphens in the hostname")
    if f["num_subdomains"] >= 4:
        add(0.25, f"Too many subdomain levels ({f['num_subdomains']})")
    elif f["num_subdomains"] == 3:
        add(0.10, "3 subdomain levels")
    if f["url_length"] > 100:
        add(0.12, f"Very long URL ({f['url_length']} characters)")
    elif f["url_length"] > 75:
        add(0.06, f"Long URL ({f['url_length']} characters)")
    if not f["has_https"]:
        add(0.10, "Does not use HTTPS (connection not encrypted)")
    if f["nonstandard_port"]:
        add(0.15, "Uses a non-standard port")
    if f["host_digit_ratio"] > 0.3 and not f["has_ip"]:
        add(0.15, "Many digits inside the hostname")
    if f["double_slash_in_path"]:
        add(0.10, "'//' found inside the path")
    if f["encoded_chars"] >= 3:
        add(0.10, "Many encoded (%xx) characters")
    if f["host_entropy"] > 3.4 and len(a["host"]) > 12:
        add(0.12, "Random-looking hostname")
    return min(s, 1.0), flags


def analyze(raw_url):
    a = F.analyze_structure(raw_url)
    f = a["features"]
    ml_prob = float(_MODEL.predict_proba([F.vector(f)])[0][1])
    rule, flags = _rule_score(a)

    score = 0.5 * ml_prob + 0.5 * rule
    # hard overrides for unmistakable attacks
    strong = f["has_ip"] or f["has_at_symbol"] or a["typosquat_of"] or a["brand_hits"]
    if strong:
        score = max(score, 0.85 if (a["typosquat_of"] or a["brand_hits"] or f["has_at_symbol"]) else 0.75)
    if f["is_shortener"]:
        score = min(max(score, 0.45), 0.64)
    if a["free_hosting"]:
        score = max(score, 0.45)      # never "Legitimate" - owner unknown
        if a["keywords"] or not f["has_https"]:
            score = max(score, 0.60)
    if a["blocklisted"]:
        score = max(score, 0.97)

    reasons_good = []
    trusted = False
    if a["is_trusted"]:
        trusted = True
        score = min(score, 0.06)
        reasons_good.append(f"'{a['registered_domain']}' is a verified, well-known official domain")
    elif a["is_restricted_tld"] and not strong:
        trusted = True
        score = min(score, 0.12)
        reasons_good.append(f"Government/education domain (.{a['suffix']}) - only registrable by verified institutions")
    if f["has_https"]:
        reasons_good.append("Uses HTTPS")
    if not flags:
        reasons_good.append("No suspicious patterns found in the URL structure")

    score = round(max(0.0, min(score, 1.0)), 4)
    if score >= 0.65:
        verdict, risk = "Phishing", "High"
    elif score >= 0.40:
        verdict, risk = "Suspicious", "Medium"
    else:
        verdict, risk = "Legitimate", "Low"

    if trusted:
        flags = [x for x in flags if "HTTPS" not in x]
    return {
        "url": a["url"], "host": a["host"], "registered_domain": a["registered_domain"],
        "verdict": verdict, "risk_level": risk,
        "risk_score": round(score * 100, 1),
        "ml_probability": round(ml_prob * 100, 1),
        "rule_score": round(rule * 100, 1),
        "trusted_domain": trusted,
        "red_flags": flags if not trusted else flags,
        "good_signs": reasons_good,
        "features": [{"name": n, "label": F.FEATURE_LABELS[n], "value": f[n]} for n in F.FEATURE_NAMES],
    }
