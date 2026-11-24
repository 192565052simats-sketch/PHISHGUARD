"""
Module 1 - URL Input and Feature Extraction
Converts a raw URL into numerical features + human readable red flags.
Works fully OFFLINE (no internet needed).
"""
import re
import math
import ipaddress
from urllib.parse import urlparse, parse_qs, unquote

# ---------------------------------------------------------------- knowledge
MULTI_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "ac.in", "gov.in", "nic.in",
    "edu.in", "org.in", "net.in", "res.in", "co.jp", "com.au", "net.au", "org.au",
    "com.br", "com.cn", "com.sg", "com.my", "co.za", "co.nz", "com.pk", "com.bd",
    "com.mx", "com.tr", "co.kr", "com.hk", "edu.au", "gov.au", "edu.sg",
}
RESTRICTED_SUFFIX = {"gov.in", "nic.in", "ac.in", "edu.in", "res.in", "gov", "edu",
                     "mil", "gov.uk", "ac.uk", "edu.au", "gov.au", "edu.sg"}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "link", "work", "support",
    "loan", "zip", "mov", "country", "kim", "men", "review", "buzz", "rest", "icu",
    "cyou", "monster", "cam", "download", "racing", "stream", "gdn", "bid", "date",
    "party", "science", "trade", "webcam", "accountant", "win", "vip", "life", "live",
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "bl.ink",
    "lnkd.in", "soo.gd", "s.id", "v.gd",
}
KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification", "update",
    "secure", "security", "account", "banking", "confirm", "password", "passwd",
    "wallet", "suspend", "suspended", "unlock", "billing", "invoice", "webscr",
    "authenticate", "recover", "alert", "validate", "credential", "support",
    "helpdesk", "free", "bonus", "prize", "lucky", "winner", "claim", "refund",
    "kyc", "otp", "limited", "urgent", "expire",
]

# brand -> official registered domains
BRANDS = {
    "paypal": ["paypal.com", "paypal.me"],
    "google": ["google.com", "google.co.in", "googleapis.com", "goo.gl"],
    "gmail": ["gmail.com"],
    "youtube": ["youtube.com", "youtu.be"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com"],
    "apple": ["apple.com", "icloud.com"],
    "icloud": ["icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "microsoftonline.com"],
    "outlook": ["outlook.com", "live.com"],
    "office365": ["office.com", "microsoft.com"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
    "twitter": ["twitter.com", "x.com"],
    "github": ["github.com", "github.io", "githubusercontent.com"],
    "dropbox": ["dropbox.com"],
    "ebay": ["ebay.com", "ebay.in"],
    "adobe": ["adobe.com"],
    "yahoo": ["yahoo.com"],
    "spotify": ["spotify.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "metamask": ["metamask.io"],
    "telegram": ["telegram.org", "t.me"],
    "snapchat": ["snapchat.com"],
    "zoom": ["zoom.us"],
    "walmart": ["walmart.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "hsbc": ["hsbc.com", "hsbc.co.in"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    # India
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com", "sbi.bank.in"],
    "hdfc": ["hdfcbank.com", "hdfc.com"],
    "hdfcbank": ["hdfcbank.com"],
    "icici": ["icicibank.com", "icicidirect.com"],
    "icicibank": ["icicibank.com"],
    "axisbank": ["axisbank.com"],
    "kotak": ["kotak.com"],
    "canarabank": ["canarabank.com"],
    "paytm": ["paytm.com", "paytmbank.com"],
    "phonepe": ["phonepe.com"],
    "flipkart": ["flipkart.com"],
    "irctc": ["irctc.co.in"],
    "saveetha": ["saveetha.com"],
}

# well-known sites that are trusted as-is (registered domain, exact match)
TRUSTED_EXTRA = [
    "wikipedia.org", "stackoverflow.com", "reddit.com", "bing.com", "duckduckgo.com",
    "mozilla.org", "python.org", "pypi.org", "w3schools.com", "geeksforgeeks.org",
    "medium.com", "quora.com", "cloudflare.com", "oracle.com", "ibm.com", "intel.com",
    "nvidia.com", "samsung.com", "cisco.com", "kaggle.com", "coursera.org",
    "udemy.com", "nptel.ac.in", "bbc.com", "bbc.co.uk", "nytimes.com", "cnn.com",
    "theguardian.com", "thehindu.com", "timesofindia.com", "indiatimes.com",
    "ndtv.com", "hindustantimes.com", "indianexpress.com", "swiggy.com", "zomato.com",
    "myntra.com", "ajio.com", "nykaa.com", "bookmyshow.com", "makemytrip.com",
    "redbus.in", "naukri.com", "indeed.com", "glassdoor.com", "uidai.gov.in",
    "incometax.gov.in", "india.gov.in", "digilocker.gov.in", "tn.gov.in",
    "annauniv.edu", "mit.edu", "stanford.edu", "harvard.edu", "iitm.ac.in",
    "tcs.com", "infosys.com", "wipro.com", "zoho.com", "freshworks.com",
    "slack.com", "notion.so", "figma.com", "canva.com", "trello.com", "atlassian.com",
    "gitlab.com", "stackexchange.com", "kali.org", "nmap.org", "owasp.org",
    "hackerone.com", "tryhackme.com", "virustotal.com", "phishtank.com",
    "twitch.tv", "pinterest.com", "tumblr.com", "wordpress.com", "wordpress.org",
    "whatsapp.com", "discord.com", "openai.com", "anthropic.com", "claude.ai",
    "visa.com", "mastercard.com", "americanexpress.com", "citi.com", "uber.com",
    "ola.com", "olacabs.com", "airtel.in", "jio.com", "bsnl.co.in", "vi.com",
    "msn.com", "office.com", "live.com", "skype.com", "bit.ly.com",
]


def _build_trusted():
    s = set(TRUSTED_EXTRA)
    for v in BRANDS.values():
        s.update(v)
    s.discard("bit.ly.com")
    return s


TRUSTED_DOMAINS = _build_trusted()
TRUSTED_SLDS = {d.split(".")[0] for d in TRUSTED_DOMAINS}

# free hosting / user-content platforms: ANYONE can publish a page here, so the domain
# itself proves nothing (heavily abused for phishing)
FREE_HOSTING = {
    "appspot.com", "github.io", "herokuapp.com", "netlify.app", "vercel.app", "web.app",
    "firebaseapp.com", "pages.dev", "workers.dev", "blogspot.com", "weebly.com",
    "wixsite.com", "000webhostapp.com", "ngrok.io", "ngrok-free.app", "glitch.me",
    "repl.co", "replit.app", "onrender.com", "azurewebsites.net", "amazonaws.com",
    "googleapis.com", "duckdns.org", "no-ip.org", "ddns.net", "myshopify.com",
    "godaddysites.com", "webflow.io", "framer.app", "surge.sh", "infinityfreeapp.com",
    "rf.gd", "epizy.com", "byethost.com", "sites.google.com", "cloudfront.net",
    "trycloudflare.com", "r2.dev", "fly.dev", "railway.app", "carrd.co", "yolasite.com",
}
# known phishing / malware DEMO and TEST sites (blocklist style match)
KNOWN_THREAT_TESTS = {
    "testsafebrowsing.appspot.com", "testingmcafeesites.com", "demo.smartscreen.msft.net",
    "wicar.org", "eicar.org", "internetbadguys.com", "malware.testing.google.test",
    "testcategory.com", "phishing.testcategory.com", "malware.testcategory.com",
}

HOMOGLYPH = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
                           "7": "t", "8": "b", "$": "s", "@": "a"})

FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "num_dots", "num_hyphens_host",
    "num_digits", "digit_ratio", "num_special_chars", "has_https", "has_ip",
    "has_at_symbol", "num_subdomains", "num_params", "keyword_count",
    "suspicious_tld", "is_shortener", "has_punycode", "brand_abuse", "typosquat",
    "double_slash_in_path", "nonstandard_port", "host_entropy", "encoded_chars",
    "host_digit_ratio",
]

FEATURE_LABELS = {
    "url_length": "URL length", "hostname_length": "Hostname length",
    "path_length": "Path length", "num_dots": "Number of dots",
    "num_hyphens_host": "Hyphens in hostname", "num_digits": "Digits in URL",
    "digit_ratio": "Digit ratio", "num_special_chars": "Special characters",
    "has_https": "Uses HTTPS", "has_ip": "IP address as host",
    "has_at_symbol": "'@' symbol in URL", "num_subdomains": "Subdomain levels",
    "num_params": "Query parameters", "keyword_count": "Suspicious keywords",
    "suspicious_tld": "Risky TLD", "is_shortener": "URL shortener",
    "has_punycode": "Punycode (xn--)", "brand_abuse": "Brand name misuse",
    "typosquat": "Look-alike domain", "double_slash_in_path": "'//' in path",
    "nonstandard_port": "Non-standard port", "host_entropy": "Hostname randomness",
    "encoded_chars": "Encoded (%) chars", "host_digit_ratio": "Digits in hostname",
}


# ---------------------------------------------------------------- helpers
def levenshtein(a, b):
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def entropy(s):
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def normalize_url(raw):
    raw = (raw or "").strip().strip("\"'<>")
    raw = re.sub(r"\s+", "", raw)
    if not raw:
        raise ValueError("Please enter a URL.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "http://" + raw
    return raw


def split_host(host):
    """return (subdomain_labels, sld, suffix, registered_domain)"""
    labels = host.lower().strip(".").split(".")
    if len(labels) == 1:
        return [], labels[0], "", labels[0]
    two = ".".join(labels[-2:])
    if two in MULTI_SUFFIX and len(labels) >= 3:
        suffix = two
        sld = labels[-3]
        sub = labels[:-3]
    else:
        suffix = labels[-1]
        sld = labels[-2]
        sub = labels[:-2]
    return sub, sld, suffix, f"{sld}.{suffix}"


def is_ip(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    # decimal / hex / octal obfuscated IPs like http://3232235777 or 0xC0A80001
    if re.fullmatch(r"\d{8,10}", host) or re.fullmatch(r"0x[0-9a-fA-F]{6,8}", host):
        return True
    return False


def _brand_hits(host_labels, registered):
    """brand tokens present in hostname although the domain is not the official one"""
    hits = []
    tokens = []
    for lab in host_labels:
        tokens.extend([t for t in re.split(r"[-_]", lab) if t])
    for brand, official in BRANDS.items():
        if registered in official:
            continue
        for t in tokens:
            tt = t.translate(HOMOGLYPH).replace("vv", "w").replace("rn", "m")
            if t == brand or tt == brand or (len(brand) >= 5 and brand in tt):
                hits.append(brand)
                break
    return hits


def _typosquat(sld, registered):
    if registered in TRUSTED_DOMAINS or len(sld) < 4:
        return None
    norm = sld.translate(HOMOGLYPH).replace("vv", "w").replace("rn", "m")
    for t in TRUSTED_SLDS:
        if len(t) < 4:
            continue
        if sld == t:
            continue
        if norm == t:
            return t
        if len(t) >= 6 and levenshtein(sld, t) == 1 and abs(len(sld) - len(t)) <= 1:
            return t
        if len(t) >= 6 and levenshtein(norm, t) == 1 and abs(len(norm) - len(t)) <= 1:
            return t
    return None


# ---------------------------------------------------------------- main API
def analyze_structure(raw_url):
    """Parse URL and return dict with parsed parts, numeric features, and flags."""
    url = normalize_url(raw_url)
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        raise ValueError("This does not look like a valid URL.")
    if not host:
        raise ValueError("Could not find a website address in this URL.")
    if not is_ip(host):
        if "." not in host and host != "localhost":
            raise ValueError("This does not look like a valid website address (no domain).")
        if not re.fullmatch(r"[a-z0-9._\-\u00a1-\uffff]+", host) or ".." in host:
            raise ValueError("This URL has invalid characters in the website address.")
    if len(url) > 2048:
        raise ValueError("URL is too long to analyse.")

    ip_host = is_ip(host)
    if ip_host:
        sub, sld, suffix, registered = [], host, "", host
    else:
        sub, sld, suffix, registered = split_host(host)

    path = p.path or ""
    query = p.query or ""
    decoded = unquote(url).lower()
    full_lower = url.lower()
    netloc_has_at = "@" in (p.netloc or "")

    keyword_text = (host + path + "?" + query).lower()
    kw_found = sorted({k for k in KEYWORDS if k in keyword_text})

    host_labels = [] if ip_host else host.split(".")
    brand_hits = [] if ip_host else _brand_hits(host_labels, registered)
    # brand used in path while domain is unrelated (e.g. evil.com/paypal/login)
    path_brand = []
    if not ip_host:
        for brand, official in BRANDS.items():
            if registered not in official and len(brand) >= 5 and brand in (path + query).lower():
                path_brand.append(brand)
    typo = None if ip_host else _typosquat(sld, registered)
    if typo and not brand_hits:
        brand_hits = [typo]

    digits = sum(c.isdigit() for c in url)
    host_digits = sum(c.isdigit() for c in host)
    specials = sum(url.count(c) for c in "@?&=_%~#$!*")
    default_port = {"http": 80, "https": 443}.get(p.scheme)
    nonstd_port = int(port is not None and port != default_port)

    feats = {
        "url_length": len(url),
        "hostname_length": len(host),
        "path_length": len(path),
        "num_dots": host.count("."),
        "num_hyphens_host": host.count("-"),
        "num_digits": digits,
        "digit_ratio": round(digits / max(len(url), 1), 4),
        "num_special_chars": specials,
        "has_https": int(p.scheme == "https"),
        "has_ip": int(ip_host),
        "has_at_symbol": int(netloc_has_at),
        "num_subdomains": len(sub),
        "num_params": len(parse_qs(query)),
        "keyword_count": len(kw_found),
        "suspicious_tld": int(suffix.split(".")[-1] in SUSPICIOUS_TLDS) if suffix else 0,
        "is_shortener": int(registered in SHORTENERS),
        "has_punycode": int("xn--" in host),
        "brand_abuse": int(bool(brand_hits) or (bool(path_brand) and True)),
        "typosquat": int(typo is not None),
        "double_slash_in_path": int("//" in path),
        "nonstandard_port": nonstd_port,
        "host_entropy": round(entropy(sld if not ip_host else ""), 3),
        "encoded_chars": len(re.findall(r"%[0-9a-fA-F]{2}", url)),
        "host_digit_ratio": round(host_digits / max(len(host), 1), 4),
    }

    free_host = (not ip_host) and (registered in FREE_HOSTING or host in FREE_HOSTING)
    blocklisted = (not ip_host) and any(host == d or host.endswith("." + d)
                                        for d in KNOWN_THREAT_TESTS)
    return {
        "free_hosting": free_host,
        "blocklisted": blocklisted,
        "url": url,
        "scheme": p.scheme,
        "host": host,
        "registered_domain": registered,
        "suffix": suffix,
        "subdomains": sub,
        "path": path,
        "query": query,
        "features": feats,
        "keywords": kw_found,
        "brand_hits": sorted(set(brand_hits)),
        "path_brand": sorted(set(path_brand)),
        "typosquat_of": typo,
        "is_trusted": (registered in TRUSTED_DOMAINS) and not netloc_has_at and not ip_host
                      and not free_host and not blocklisted,
        "is_restricted_tld": suffix in RESTRICTED_SUFFIX and not netloc_has_at,
    }


def vector(feats):
    return [float(feats[n]) for n in FEATURE_NAMES]
