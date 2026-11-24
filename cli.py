import sys, detector
for u in sys.argv[1:]:
    try:
        r = detector.analyze(u)
        print(f"{r['verdict']:<11} risk={r['risk_level']:<6} score={r['risk_score']:>5}%  {u}")
        for x in r['red_flags']: print("    !", x)
    except ValueError as e:
        print("ERROR", u, "->", e)
