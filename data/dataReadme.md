# 🧪 Scrub — Test Data

Drop all files from this folder into `data/input/` before running.

---

## Files

| File | Mode | Tests |
|---|---|---|
| `email.txt` | doc | Names, emails, phones, IBAN, credit card, Emirates ID, passport |
| `hr_record.txt` | doc | Full PII set — name, DOB, national ID, passport, IBAN, vehicle, medical |
| `employees.csv` | doc | Bulk PII across multiple rows — names, emails, phones, IBANs, national IDs |
| `config.json` | code | AWS keys, Stripe, SendGrid, Slack, JWT secret, DB connection string, IPs |
| `.env.production` | code | Full .env file — all credential types |
| `user_service.py` | code | Python — credentials + 10 security vulnerabilities (SQL injection, pickle, eval, etc.) |
| `api.js` | code | JavaScript — credentials + SQL injection, eval, TLS disabled, hardcoded JWT |
| `ai_response.txt` | restore | Pre-masked AI output — use with `make restore` to test vault reapplication |

---

## Suggested test commands

```bash
# Doc mode tests
make mask file=email.txt vault=email_test output=masked_email.txt
make mask file=hr_record.txt vault=hr_test output=masked_hr.txt
make mask file=employees.csv vault=csv_test output=masked_employees.csv

# Code mode tests
make mask file=user_service.py mode=code vault=py_test output=masked_service.py
make mask file=api.js mode=code vault=js_test output=masked_api.js
make mask file=config.json mode=code vault=config_test output=masked_config.json
make mask file=.env.production mode=code vault=env_test output=masked.env

# Restore test (uses email vault)
# 1. First mask the email to create the vault:
make mask file=email.txt vault=email_test

# 2. Then restore the sample AI response with it:
make restore file=ai_response.txt vault=email_test output=restored_response.txt
```

---

## What to expect

**Doc mode on `email.txt`** should catch:
- 2 names (Sarah Johnson, James Miller)
- 2 email addresses
- 4 phone numbers
- 1 credit card
- 1 IBAN
- 1 Emirates ID
- 1 passport number

**Code mode on `user_service.py`** should catch:
- 8+ credentials (AWS, Stripe, OpenAI, Anthropic, SendGrid, GitHub, DB password, JWT secret, private key, webhook)
- 10 security findings including CRITICAL (SQL injection x2, pickle, yaml.load, eval, TLS disabled, debug mode) and HIGH (MD5, path traversal, logging password)

**Restore on `ai_response.txt`** should swap all `{{PLACEHOLDER}}` tokens back to real values from the vault.