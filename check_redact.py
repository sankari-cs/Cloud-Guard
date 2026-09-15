from app.services.detector import detect_in_text
from app.services.fingerprint import fingerprint_prefix, fingerprint_secret
from app.services.redactor import redact_secret, safe_context_snippet
text = 'AWS_ACCESS_KEY_ID = "AKIA' + "A" * 16 + '"\npassword = "s3cr3t-value-xyz"'
dets = detect_in_text(text)
for d in dets:
    print(f"{d.secret_type:20} redacted={redact_secret(d.matched_value)}")
    print(f"{'':20} fp={fingerprint_prefix(d.matched_value, 16)}")
secrets = [d.matched_value for d in dets]
print("--- snippet ---")
print(safe_context_snippet(text, line_number=1, secrets=secrets, radius=1))
