from app.services.detector import detect_in_text
text = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
results = detect_in_text(text)
if results:
    for r in results:
        print(f"{r.secret_type}: confidence={r.confidence} reason={r.detection_reason}")
else:
    print("no match")
