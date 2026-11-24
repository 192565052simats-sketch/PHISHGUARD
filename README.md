# PhishGuard - AI-Powered Phishing URL Detection and Risk Analysis System
SIMATS | CSA0819 Python | Random Forest

## Run (Windows / Linux / Mac)
    pip install -r requirements.txt
    python train.py        (re-trains the model; model.pkl + metrics.json are already included)
    python app.py          (open http://127.0.0.1:5000 in the browser)

Command line check:  python cli.py "http://paypa1.com/login"
Self-test (91 URLs):  python tests_urls.py

## Files = PPT modules
- features.py  -> Module 1: URL input + feature extraction (24 numerical features)
- train.py     -> Module 2: Random Forest training
- detector.py  -> Module 2+3: classification + risk score (Low/Medium/High) + red flags
- app.py + templates/index.html -> Module 3: dashboard, graphs, CSV report download

## Use a REAL dataset (recommended)
Download a phishing URL CSV (Kaggle "Phishing Site URLs" / PhishTank) with columns url,label
(1 = phishing, 0 = legitimate) and run:  python train.py --csv yourfile.csv
