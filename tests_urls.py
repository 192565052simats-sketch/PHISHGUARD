"""Run: python tests_urls.py  -> checks many known-real and known-fake style URLs."""
import detector

LEGIT = """
https://www.google.com
https://www.google.com/search?q=python+tutorial
https://accounts.google.com/signin
https://mail.google.com/mail/u/0/
https://www.youtube.com/watch?v=dQw4w9WgXcQ
https://www.facebook.com/login
https://www.instagram.com/accounts/login/
https://www.amazon.in
https://www.amazon.com/gp/css/homepage.html
https://www.flipkart.com/account/login
https://www.paypal.com/signin
https://github.com/login
https://github.com/torvalds/linux
https://stackoverflow.com/questions/11227809
https://en.wikipedia.org/wiki/Phishing
https://www.microsoft.com/en-in/security
https://login.microsoftonline.com
https://www.linkedin.com/in/someone
https://www.netflix.com/in/login
https://www.apple.com/in/
https://www.saveetha.com
https://www.irctc.co.in
https://onlinesbi.sbi
https://www.hdfcbank.com/personal/login
https://www.icicibank.com
https://www.paytm.com
https://www.incometax.gov.in
https://uidai.gov.in
https://www.nptel.ac.in
https://www.iitm.ac.in
https://www.mit.edu
https://www.python.org/downloads/
https://pypi.org/project/scikit-learn/
https://www.bbc.com/news
https://www.thehindu.com/news/national/
https://openai.com
https://claude.ai
google.com
www.wikipedia.org
https://www.kaggle.com/datasets
https://www.geeksforgeeks.org/python-programming-language/
https://my-local-bakery.com/menu
https://www.brightcafe.in/about
https://smartmedia.io/blog/2024/10/how-to-learn-python
http://www.oldschoolforum.org/index.html
https://www.harborstudio.com/contact
""".split()

PHISH = """
http://paypa1.com/login
http://www.paypal-secure-login.xyz/verify
http://secure-paypal-verify.xyz
http://paypal.com.account-verify.tk/signin
http://192.168.1.5/login.php
http://45.33.32.156:8080/bank/verify/index.php
http://google.com@evil.tk/login
https://accounts.google.com@malicious-site.ru/signin
http://g00gle.com/login
http://www.gooogle.com
http://arnazon-india-offers.com/account/verify
http://amaz0n-india.top/login
http://amazon.verify-account-info.com/signin
http://facebook-login-secure.top/index.php
http://faceb00k.com/login
https://instagrarn.com/accounts/login
http://netflix-billing-update.xyz/payment
http://netflix.account-suspended.click/login
http://sbi-kyc-update.top/login.php
http://onlinesbi.verify-kyc-update.xyz/otp
http://hdfc-bank-netbanking-login.xyz
http://icici-bank.secure-verify.work/login
http://paytm-kyc-verify.top/update
http://irctc-refund-claim.xyz/login
http://appleid.apple.com.verify-id.xyz/signin
http://apple-id-locked.top/unlock
http://microsoft-support-alert.click/call
http://login.microsoftonline.com.secure-verify.ml/
http://secure.login.verify.account.update.example-bank.com/login.php?id=83743hd7
http://xn--pypal-4ve.com/login
http://free-prize-winner-claim.xyz/lucky
http://whatsapp-gold-free-download.top
http://metamask-wallet-recover.xyz/unlock
http://binance-account-suspended.click/verify
http://dhl-parcel-redelivery.top/confirm
http://randomsite.com/paypal/login/index.php
http://kjh38dkq2m9xz.xyz/login.php?email=a%40b.com&session=ab3d92ks8d7s
http://saveetha-university-login.xyz/student/verify
http://github.com.secure-login.top/signin
http://wellsfargo.secure-account-update.info/signin
http://steam-community-gift.xyz/trade
http://login-verify-account.tk
""".split()

PHISH += """
http://testsafebrowsing.appspot.com/
http://testsafebrowsing.appspot.com/s/phishing.html
http://testsafebrowsing.appspot.com/s/malware.html
http://www.testingmcafeesites.com/
http://demo.smartscreen.msft.net/phishingdemo.html
https://paypal-login.netlify.app
""".split()
SUSPICIOUS_OK = ["https://myportfolio.github.io", "https://storage.googleapis.com/x/login.html", "https://bit.ly/3xYz9", "http://tinyurl.com/y8abcd", "https://t.co/AbCd123"]

fail = 0
print("=== SHOULD BE LEGITIMATE ===")
for u in LEGIT:
    r = detector.analyze(u)
    ok = r["verdict"] == "Legitimate"
    fail += not ok
    print("PASS" if ok else "FAIL", f"{r['risk_score']:>5}%", r["verdict"], u)
print("\n=== SHOULD BE PHISHING ===")
for u in PHISH:
    r = detector.analyze(u)
    ok = r["verdict"] == "Phishing"
    fail += not ok
    print("PASS" if ok else "FAIL", f"{r['risk_score']:>5}%", r["verdict"], u)
print("\n=== SHORTENERS (should be Suspicious) ===")
for u in SUSPICIOUS_OK:
    r = detector.analyze(u)
    ok = r["verdict"] == "Suspicious"
    fail += not ok
    print("PASS" if ok else "FAIL", f"{r['risk_score']:>5}%", r["verdict"], u)
print("\n=== INVALID INPUT (should give clean error) ===")
for u in ["", "   ", "hello world", "http://", "abc", "http://exa mple.com", "javascript:alert(1)"]:
    try:
        r = detector.analyze(u)
        print("INFO ", repr(u), "->", r["verdict"])
    except ValueError as e:
        print("PASS ", repr(u), "->", e)
total = len(LEGIT) + len(PHISH) + len(SUSPICIOUS_OK)
print(f"\nRESULT: {total - fail}/{total} passed, {fail} failed")
