"""PhishGuard - AI-Powered Phishing URL Detection and Risk Analysis System
Run:  python app.py   then open http://127.0.0.1:5000
"""
import csv, io, json, os, threading
from datetime import datetime
from flask import Flask, jsonify, render_template, request, Response
import detector

app = Flask(__name__)
HISTORY, LOCK = [], threading.Lock()
HERE = os.path.dirname(os.path.abspath(__file__))
METRICS = json.load(open(os.path.join(HERE, "metrics.json")))


def stats():
    with LOCK:
        h = list(HISTORY)
    return {
        "total": len(h),
        "legitimate": sum(1 for x in h if x["verdict"] == "Legitimate"),
        "suspicious": sum(1 for x in h if x["verdict"] == "Suspicious"),
        "phishing": sum(1 for x in h if x["verdict"] == "Phishing"),
        "low": sum(1 for x in h if x["risk_level"] == "Low"),
        "medium": sum(1 for x in h if x["risk_level"] == "Medium"),
        "high": sum(1 for x in h if x["risk_level"] == "High"),
        "history": h[:15],
    }


@app.get("/")
def index():
    return render_template("index.html", metrics=METRICS)


@app.post("/api/analyze")
def api_analyze():
    data = request.get_json(silent=True) or {}
    try:
        r = detector.analyze(data.get("url", ""))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception:
        return jsonify({"error": "Could not analyse this URL."}), 400
    r["time"] = datetime.now().strftime("%H:%M:%S")
    with LOCK:
        HISTORY.insert(0, {k: r[k] for k in ("url", "verdict", "risk_level", "risk_score", "time")}
                       | {"flags": "; ".join(r["red_flags"])})
    return jsonify(r)


@app.get("/api/stats")
def api_stats():
    return jsonify(stats())


@app.post("/api/clear")
def api_clear():
    with LOCK:
        HISTORY.clear()
    return jsonify(ok=True)


@app.get("/api/model")
def api_model():
    return jsonify(METRICS)


@app.get("/report.csv")
def report():
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Time", "URL", "Verdict", "Risk Level", "Risk Score (%)", "Red Flags"])
    with LOCK:
        for x in reversed(HISTORY):
            w.writerow([x["time"], x["url"], x["verdict"], x["risk_level"], x["risk_score"], x["flags"]])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=phishing_report.csv"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
