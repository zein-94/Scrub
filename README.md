# 🧹 Scrub

> Sanitize sensitive data before you send it to AI agents — fully offline, nothing stored, nothing sent.

Scrub is a CLI tool that detects and masks sensitive information in documents, emails, spreadsheets, and source code before you share them with AI assistants. After the AI responds, Scrub can restore all real values back into the output — so your workflow stays intact without ever exposing private data.

---

## Table of Contents

- [What Scrub Does](#what-scrub-does)
- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [Setup](#setup)
- [Usage](#usage)
- [Document Mode](#document-mode)
- [Code Mode](#code-mode)
- [Restoring AI Output](#restoring-ai-output)
- [Vault Encryption](#vault-encryption)
- [Supported File Types](#supported-file-types)
- [What Gets Detected](#what-gets-detected)
- [Security Analysis Rules](#security-analysis-rules)
- [Privacy Guarantee](#privacy-guarantee)
- [Project Structure](#project-structure)
- [Known Shortcomings](#known-shortcomings)
- [Troubleshooting](#troubleshooting)

---

## What Scrub Does

When you share documents or code with an AI agent, you risk exposing:

- Names, emails, phone numbers, IBANs, credit card numbers, national IDs
- API keys, passwords, tokens, database connection strings, private keys
- Internal IP addresses, server hostnames, webhook URLs

Scrub sits between you and the AI. It replaces every sensitive value with a typed placeholder like `{{EMAIL_1}}` or `{{API_KEY_1}}`, lets you work with the AI safely, then swaps all the real values back into the AI's response.

Everything runs locally. No data is sent anywhere. No data is stored unless you explicitly save a vault file.

---

## How It Works

```
Your file → [Scrub mask] → Sanitized file → AI Agent → AI Response → [Scrub restore] → Final output
                               ↓
                         Encrypted vault
                    (placeholder ↔ real value map)
```

1. **Mask** — Scrub scans your input, replaces sensitive values with placeholders, and optionally saves an encrypted vault mapping placeholders back to real values.
2. **Send** — You copy the masked output to the AI agent of your choice.
3. **Restore** — You paste the AI's response into a file and run `scrub restore` with your vault to get the final output with real values reinstated.

---

## Requirements

- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/) (included in Docker Desktop)
- Make (pre-installed on macOS/Linux; Windows users can use [Git Bash](https://git-scm.com/downloads) or [WSL](https://learn.microsoft.com/en-us/windows/wsl/install))

No Python installation required — everything runs inside Docker.

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/youruser/scrub.git
cd scrub
```

### 2. Configure your encryption secret

```bash
cp .env.example .env
```

Open `.env` and set a strong secret:

```bash
SCRUB_SECRET=replace-with-a-long-random-string
```

This secret is used to encrypt vault files locally. It never leaves your machine.

> **Tip:** Generate a strong secret with `openssl rand -hex 32`

### 3. Build the Docker image

```bash
make build
```

This will:
- Pull the Python 3.11 base image
- Install all dependencies
- Download the spaCy `en_core_web_lg` NER model (~750MB) at build time

The build takes a few minutes on first run. Subsequent builds are cached.

### 4. Prepare your working folders

```
scrub/
└── data/
    ├── input/    ← drop your files here before running
    ├── output/   ← masked and restored files appear here
    └── vaults/   ← encrypted vault files are saved here
```

These folders are created automatically on first run. They are gitignored and never committed.

### 5. Verify the setup

```bash
docker compose run --rm scrub --version
```

You should see:

```
🧹 Scrub v1.0.0
```

---

## Usage

All commands follow this pattern:

```bash
make mask file=<filename> [mode=doc|code] [vault=<name>] [output=<filename>]
make restore file=<filename> [vault=<name>] [output=<filename>]
```

Or using Docker Compose directly:

```bash
docker compose run --rm scrub mask /data/input/<file> --mode doc --vault /data/vaults/<name>.vault
docker compose run --rm scrub restore /data/input/<file> --vault /data/vaults/<name>.vault
```

### Quick reference

| Command | Description |
|---|---|
| `make build` | Build the Docker image |
| `make mask file=email.txt` | Mask a document (doc mode, default) |
| `make mask file=main.py mode=code` | Mask source code |
| `make mask file=report.docx vault=proj1` | Mask and save vault as `proj1` |
| `make restore file=ai_out.txt vault=proj1` | Restore real values using `proj1` vault |
| `make clean` | Remove containers and build cache |

---

## Document Mode

Document mode detects PII (Personally Identifiable Information) in text, emails, Word documents, spreadsheets, PDFs, and more.

### Basic usage

Place your file in `data/input/`, then:

```bash
make mask file=email.txt
```

Masked output prints to the terminal. To save it:

```bash
make mask file=email.txt output=masked_email.txt
```

### Saving a vault for later restore

```bash
make mask file=contract.docx vault=contract_session output=masked_contract.txt
```

This saves an encrypted vault to `data/vaults/contract_session.vault` that you will use in the restore step.

### Specifying language

```bash
docker compose run --rm scrub mask /data/input/document.txt --mode doc --lang fr
```

Supported language codes: `en`, `fr`, `de`, `es`, `it`, `pt`, `nl`, `pl`, `ar` (and others supported by spaCy + Presidio).

### Example — before masking

```
Hi John,

Please find attached the invoice for your account.
Your card ending in 4242 (Visa) will be charged $1,200.
Please confirm your details: john.smith@example.com | +971 50 123 4567
Emirates ID: 784-1990-1234567-1

Thanks,
Sarah
```

### Example — after masking

```
Hi {{NAME_1}},

Please find attached the invoice for your account.
Your card ending in {{CREDIT_CARD_1}} (Visa) will be charged $1,200.
Please confirm your details: {{EMAIL_1}} | {{PHONE_1}}
Emirates ID: {{NATIONAL_ID_1}}

Thanks,
{{NAME_2}}
```

---

## Code Mode

Code mode scans source files for credentials and secrets, runs static security analysis, and masks everything it finds.

### Basic usage

```bash
make mask file=app.py mode=code
```

### With vault (required if you want to restore later)

```bash
make mask file=config.py mode=code vault=myproject output=masked_config.py
```

### What you see

Scrub runs two phases and reports both:

**Phase 1 — Security analysis**

```
→ Running static security analysis...
┌─────────────────────────────────────────────────────┐
│  🔴 1 CRITICAL  🟠 2 HIGH  🟡 1 MEDIUM  🔵 0 LOW   │
└─────────────────────────────────────────────────────┘

  🔴 SCRUB-001 — SQL Injection Risk
  Line 42: cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
  String formatting used to build SQL query.
  → Fix: Use parameterized queries or an ORM.

⚠  DO NOT share this code with AI agents until these are resolved.
```

**Phase 2 — Credential masking**

```
→ Scanning for credentials and secrets...
✓ Masked 3 credential(s):

  · AWS_ACCESS_KEY: 1
  · PASSWORD: 1
  · JWT_TOKEN: 1

  Line 5  AWS Access Key ID  (confidence: 99%)
  Line 12 Hardcoded Password  (confidence: 80%)
  Line 31 JWT Token  (confidence: 95%)
```

### Blocker behaviour

If CRITICAL or HIGH security issues are found, Scrub prints a hard warning and advises you not to share the code — even after credentials are masked. The logic vulnerabilities (SQL injection, eval(), disabled TLS, etc.) are in the code structure itself, not just in the values.

---

## Restoring AI Output

After the AI responds, save its response to a file in `data/input/`, then:

```bash
make restore file=ai_response.txt vault=myproject output=final_output.txt
```

Scrub reads the vault, finds every placeholder in the AI's response, and replaces them with the original real values.

### Example

AI response containing:

```
Hi {{NAME_1}}, I've reviewed the contract for {{ORG_1}}.
Please have {{NAME_2}} sign and return to {{EMAIL_1}}.
```

After restore:

```
Hi John Smith, I've reviewed the contract for Acme Corp.
Please have Sarah Jones sign and return to legal@acme.com.
```

### Stdin / stdout piping

Scrub supports piping for scripting and automation:

```bash
# Pipe input directly
cat email.txt | docker compose run -T scrub mask - --mode doc --vault /data/vaults/session.vault

# Chain mask and restore
cat email.txt | docker compose run -T scrub mask - --mode doc | \
  <your AI CLI tool> | \
  docker compose run -T scrub restore - --vault /data/vaults/session.vault
```

---

## Vault Encryption

Vault files store the mapping between placeholders and real values. They are encrypted using [Fernet](https://cryptography.io/en/latest/fernet/) (AES-128-CBC with HMAC-SHA256).

The encryption key is derived from your `SCRUB_SECRET` environment variable. Without the correct secret, a vault file is unreadable.

### Important rules

- Vault files are only created when you pass `--vault` or use `vault=` in the Makefile
- Without a vault, the placeholder mapping is lost when the session ends
- Always use the same `SCRUB_SECRET` for both masking and restoring
- Never commit vault files — they are gitignored by default

### Stronger secrets

Set a long random secret in your `.env`:

```bash
SCRUB_SECRET=$(openssl rand -hex 32)
```

---

## Supported File Types

### Document mode

| Extension | Format |
|---|---|
| `.txt` | Plain text |
| `.md` | Markdown |
| `.docx` | Word document |
| `.xlsx` | Excel spreadsheet |
| `.csv` | CSV file |
| `.pdf` | PDF document |
| `.eml` | Email file |
| `.html` | HTML file |
| `.json` | JSON file |
| `.xml` | XML file |

### Code mode

Python, JavaScript, TypeScript, JSX, TSX, Go, Ruby, Rust, Java, Kotlin, Swift, C#, C++, C, PHP, Shell/Bash, YAML, TOML, Terraform (HCL), SQL, Dockerfile, JSON, XML, `.env` files.

---

## What Gets Detected

### Document mode — PII

| Type | Examples |
|---|---|
| Names | John Smith, Dr. Sarah Jones |
| Email addresses | john@example.com |
| Phone numbers | +971 50 123 4567, (800) 555-0100 |
| IBANs | GB29 NWBK 6016 1331 9268 19 |
| Credit card numbers | 4111 1111 1111 1111 |
| National IDs / SSNs | 784-1990-1234567-1, 123-45-6789 |
| Passport numbers | A12345678 |
| Dates (contextual) | 01/01/1990, 2024-03-15 |
| IP addresses | 192.168.1.1, 2001:db8::1 |
| URLs | https://internal.company.com/api |
| Locations | Dubai, United Arab Emirates |
| Organizations | Acme Corp, Ministry of Finance |
| Vehicle plates / VINs | AB12 CDE, 1HGBH41JXMN109186 |
| Medical license numbers | |
| Bank account numbers | |

### Code mode — Credentials

| Type | Examples |
|---|---|
| AWS keys | AKIA... |
| GCP service account keys | -----BEGIN RSA PRIVATE KEY----- |
| Azure client secrets | |
| GitHub / GitLab tokens | ghp_..., glpat-... |
| Slack tokens | xoxb-... |
| Stripe keys | sk_live_..., pk_test_... |
| OpenAI / Anthropic keys | sk-..., sk-ant-... |
| SendGrid / Twilio / Mailchimp / Mapbox keys | |
| JWT tokens | eyJ... |
| Bearer / OAuth / Refresh tokens | |
| Passwords and secrets (hardcoded) | password = "..." |
| Database connection strings | postgresql://user:pass@host/db |
| PEM private keys and certificates | |
| SSH public keys | ssh-rsa AAAA... |
| Webhook URLs (Slack, Discord) | |
| Hardcoded IP addresses (in code context) | |

---

## Security Analysis Rules

Code mode runs 20 custom security rules plus Bandit (Python only). Findings are rated CRITICAL, HIGH, MEDIUM, or LOW.

| Rule | Severity | Description |
|---|---|---|
| SCRUB-001 | 🔴 CRITICAL | SQL Injection — string formatting in queries |
| SCRUB-002 | 🔴 CRITICAL | Command Injection — user input in shell calls |
| SCRUB-003 | 🟠 HIGH | LDAP Injection |
| SCRUB-004 | 🟠 HIGH | XPath Injection |
| SCRUB-005 | 🟠 HIGH | Weak hashing — MD5 or SHA1 |
| SCRUB-006 | 🟠 HIGH | Hardcoded salt or IV |
| SCRUB-007 | 🟡 MEDIUM | Insecure RNG — `random` module in security context |
| SCRUB-008 | 🔴 CRITICAL | Unsafe pickle deserialization |
| SCRUB-009 | 🔴 CRITICAL | Unsafe `yaml.load()` without SafeLoader |
| SCRUB-010 | 🔴 CRITICAL | Unsafe `eval()` on dynamic input |
| SCRUB-011 | 🔴 CRITICAL | TLS certificate verification disabled |
| SCRUB-012 | 🟡 MEDIUM | Plain HTTP URL (non-HTTPS) |
| SCRUB-013 | 🟡 MEDIUM | Server binding to 0.0.0.0 |
| SCRUB-014 | 🔴 CRITICAL | Hardcoded JWT secret |
| SCRUB-015 | 🟠 HIGH | Weak or short session secret |
| SCRUB-016 | 🟠 HIGH | Path traversal risk |
| SCRUB-017 | 🟡 MEDIUM | Insecure temp file (`mktemp`) |
| SCRUB-018 | 🟠 HIGH | Debug mode enabled |
| SCRUB-019 | 🟠 HIGH | Sensitive data in log statements |
| SCRUB-020 | 🔵 LOW | Unpinned dependency |

All CWE references are included in the CLI output for traceability.

---

## Privacy Guarantee

Scrub is designed with a strict privacy-first model:

- **No network calls** — all processing runs inside the Docker container with no outbound connections
- **No persistent storage** — the in-memory vault is discarded at the end of every session unless you explicitly save it with `--vault`
- **No telemetry** — no usage data, crash reports, or analytics of any kind
- **No logs** — Scrub does not write logs containing your data
- **Encrypted vaults** — vault files are encrypted at rest using AES-128-CBC; only readable with your `SCRUB_SECRET`
- **Offline models** — the spaCy NER model is downloaded once at build time and runs entirely locally

---

## Project Structure

```
scrub/
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── .env.example
├── .gitignore
├── requirements.txt
├── cli.py                  # Entry point — mask and restore commands
├── vault.py                # In-memory vault + encrypted file I/O
├── modes/
│   ├── document.py         # Document mode orchestration
│   └── code.py             # Code mode orchestration
├── detectors/
│   ├── pii.py              # Presidio + spaCy + custom regex PII detection
│   └── secrets.py          # Credential and secret detection
├── analyzers/
│   └── security.py         # Bandit + 20 custom exploit/vulnerability rules
└── data/                   # Gitignored — your working files
    ├── input/
    ├── output/
    └── vaults/
```

---

## Known Shortcomings

Scrub is built entirely on local, offline models and regex patterns — no cloud inference, no LLM assistance during masking. This is a deliberate privacy trade-off, and it comes with real limitations. Here is an honest account of what Scrub does not do well and why.

---

### 1. NER-based name detection misses low-context text

**What happens:** Names like "Carlos Rivera" or "Sophie Dubois" are sometimes not masked in CSV rows or flat structured files.

**Why:** Scrub uses spaCy's `en_core_web_lg` Named Entity Recognition model, which was trained on natural language corpora — news articles, books, web text. NER models rely heavily on surrounding sentence structure and context to identify names. In a CSV row like `EMP003 | Carlos Rivera | ...`, there is no sentence, no verb, no grammatical signal — the model sees a list of tokens and often fails to classify the name correctly.

**Accepted trade-off:** Fixing this fully would require an LLM with contextual reasoning, which conflicts with the offline requirement. A low-confidence regex fallback exists for title-case two-word names, but it is intentionally set to a low score to avoid false positives on phrases like "Senior Engineer" or "AXA Gulf".

---

### 2. False positives on structural text and field labels

**What happens:** Section headers (`PERSONAL INFORMATION`), field labels (`Full Name`, `Job Title`), separator lines (`━━━━━━━`), and words like `Mobile` or `Emirates` are occasionally detected as names or locations.

**Why:** spaCy's NER model sees capitalized words and treats them probabilistically based on training data. "Mobile" is a city in Alabama. "Emirates" is a recognized geopolitical entity. "Full Name" and "Job Title" are two capitalized words side by side — a common pattern for person names in training data. The model has no way to know these are document labels without understanding the full document schema.

**Mitigation:** Scrub maintains a denylist of known false positive labels and a structural character filter. New false positives can be added to `_NAME_DENYLIST` and `_LOCATION_DENYLIST` in `detectors/pii.py`. This is an ongoing manual process.

---

### 3. Regex credential patterns are format-sensitive

**What happens:** Some credentials are missed if their format differs slightly from the pattern — e.g. a SendGrid key with a shorter middle segment, a GitHub token with fewer characters, or a Redis URL with an empty username (`redis://:password@host`).

**Why:** Every secret pattern in `detectors/secrets.py` is a hand-written regex. Credential formats are defined by the issuing service and change over time. Scrub's patterns were written against known formats at the time of development. Services sometimes issue tokens in slightly different lengths or with different prefixes in different plans or regions.

**Mitigation:** Patterns are tuned conservatively to avoid false positives (flagging random strings as secrets). When a credential is missed, the relevant pattern's length bounds or prefix can be loosened in `detectors/secrets.py`. The full list of patterns is easy to extend.

---

### 4. Entity span boundary conflicts (phone vs. IBAN, URL vs. email)

**What happens:** Earlier versions of Scrub masked `AE07 {{PHONE_4}}` instead of `{{IBAN_1}}`, and split email addresses like `{{URL_2}}hnson@{{URL_1}}` because the URL recognizer fired on bare domain names inside email addresses.

**Why:** Multiple recognizers fire independently and return overlapping spans. Presidio resolves conflicts by keeping the first result it finds, not the most semantically appropriate one. Scrub adds score-based deduplication (highest confidence span wins) and explicitly removes Presidio's built-in `UrlRecognizer`, replacing it with a stricter version that requires `http://` or `www.` prefixes and whitespace boundaries.

**Remaining edge cases:** Any token that is simultaneously valid as two entity types (a phone number that looks like part of a national ID, a short date that looks like a version number) may still resolve incorrectly depending on surrounding context and relative recognizer scores.

---

### 5. IBAN detection requires standard formatting

**What happens:** IBANs written without spaces (`AE070331123456789012345`) are detected correctly. IBANs with non-standard spacing may be missed or partially matched.

**Why:** The IBAN regex allows optional spaces every 4 characters, which covers the standard print format (`AE07 0331 1234 5678 9012 345`). Non-standard groupings like `AE07-0331-1234` (hyphens) or `AE07  0331` (double spaces) fall outside the pattern.

**Mitigation:** Pre-normalize IBANs to standard 4-character groups before passing to Scrub if your documents use non-standard formatting.

---

### 6. Static security analysis is Python-only for deep analysis

**What happens:** Bandit (AST-based static analysis) only runs on `.py` files. JavaScript, TypeScript, Go, and other languages only get the 20 custom regex rules.

**Why:** Bandit is a Python-specific tool that parses Python's AST to detect issues like `pickle.loads()`, `eval()`, or `subprocess` with `shell=True`. There is no equivalent cross-language AST tool that runs fully offline and is embeddable in this architecture. The custom regex rules in `analyzers/security.py` apply to all languages but are shallower — they match patterns in text, not code structure.

**Accepted trade-off:** For JavaScript and other languages, Scrub catches credentials and common textual patterns but will miss AST-level issues like unsafe deserialization or SQL injection in ORM calls that span multiple lines.

---

### 7. Non-English names and international PII

**What happens:** Arabic names, Chinese names, and other non-Latin-script names are generally not detected by the NER model.

**Why:** Scrub uses spaCy's `en_core_web_lg` model, which is trained primarily on English text. It has limited awareness of non-English naming conventions. Presidio supports multiple languages but requires separate language models to be downloaded and configured for each one.

**Mitigation:** For Arabic or other language documents, pass `--lang ar` (or the appropriate language code). This requires a compatible spaCy model for that language to be installed in the Docker image. Multilingual support is on the roadmap.

---

### 8. PDF support is basic

**What happens:** Scrub extracts text from PDFs page by page using `pdfplumber`. Scanned PDFs (image-based) return no text and produce no detections.

**Why:** Scanned PDFs require OCR (Optical Character Recognition) to convert images to text before any NLP can run. OCR tools like Tesseract add significant image processing complexity, container size, and processing time. They were excluded from v1 to keep the tool lightweight and fast.

**Mitigation:** Pre-process scanned PDFs with an external OCR tool and pass the resulting text file to Scrub instead.

---

### 9. Session vault is lost if `--vault` is not specified

**What happens:** If you run `scrub mask` without `--vault`, the placeholder-to-real-value mapping is discarded when the container exits. You cannot run `scrub restore` later.

**Why:** This is intentional — Scrub defaults to the most private behaviour. Writing vault data to disk without explicit user consent would be a privacy violation. The warning is printed at the end of every mask run that omits `--vault`.

**Mitigation:** Always pass `--vault session_name` when you intend to restore later. The Makefile default already includes a `vault=session` parameter.

---

### 10. Vault key is derived from `SCRUB_SECRET` — not a user password

**What happens:** Vault files are encrypted using a key derived from the `SCRUB_SECRET` environment variable. There is no per-vault password prompt.

**Why:** Requiring a password prompt would break pipe-based workflows and scripting. The `SCRUB_SECRET` approach means the key is machine-local and session-consistent without user interaction.

**Trade-off:** If `SCRUB_SECRET` is weak or left as the default, the vault encryption is weaker. Always set a strong random secret in `.env` for sensitive use cases: `openssl rand -hex 32`.

---

## Troubleshooting

### Build fails on spaCy model download

If the build fails while downloading `en_core_web_lg`, check your internet connection and retry:

```bash
make clean
make build
```

### "File not found" error

Make sure your file is inside `data/input/` before running. Scrub maps that folder into the container at `/data/input/`.

### Vault decryption fails

This usually means the `SCRUB_SECRET` in your `.env` is different from when the vault was created. Make sure you're using the same `.env` file and haven't changed the secret between mask and restore.

### No PII detected when you expect some

Try lowering the score threshold (default is 0.5). You can call the analyzer directly:

```bash
docker compose run --rm scrub mask /data/input/file.txt --mode doc
```

If detection is still missing items, they may need a custom regex pattern added to `detectors/pii.py`.

### Code mode shows no findings for non-Python files

Bandit only runs on Python files. Custom rules run on all file types. If you are scanning JavaScript or another language, only the 20 custom rules apply. Bandit support for additional languages is a planned future enhancement.

### Permission errors on output files

If output files are created by Docker with root ownership, fix with:

```bash
sudo chown -R $USER:$USER data/
```

---

## Roadmap

- PDF form field extraction
- Multi-language PII models (Arabic, French, German)
- Bandit-equivalent static analysis for JavaScript and TypeScript
- Interactive review mode — confirm each finding before masking
- Named entity allowlist — skip known safe values (e.g. your company name)
- VS Code extension wrapper