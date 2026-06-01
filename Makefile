# ─────────────────────────────────────────────
# Scrub — Makefile shortcuts
# ─────────────────────────────────────────────

.PHONY: build mask restore clean help

# Default target
help:
	@echo ""
	@echo "  🧹 Scrub — Makefile shortcuts"
	@echo ""
	@echo "  make build                          Build the Docker image"
	@echo "  make mask file=email.txt            Mask a doc/email (doc mode)"
	@echo "  make mask file=main.py mode=code    Mask source code"
	@echo "  make restore file=ai_out.txt        Restore placeholders from AI output"
	@echo "  make clean                          Remove containers and cache"
	@echo ""

build:
	docker compose build

# ── Mask ──────────────────────────────────────
# Usage:
#   make mask file=email.txt
#   make mask file=main.py mode=code
#   make mask file=report.docx vault=mysession
mode   ?= doc
vault  ?= session
output ?= masked_$(notdir $(file))

mask:
ifndef file
	$(error ✗ file is required. Usage: make mask file=yourfile.txt)
endif
	docker compose run --rm scrub mask \
		/data/input/$(notdir $(file)) \
		--mode $(mode) \
		--vault /data/vaults/$(vault).vault \
		--output /data/output/$(output)

# ── Restore ───────────────────────────────────
# Usage:
#   make restore file=ai_response.txt
#   make restore file=ai_response.txt vault=mysession output=final.txt
restore_output ?= restored_$(notdir $(file))

restore:
ifndef file
	$(error ✗ file is required. Usage: make restore file=ai_response.txt)
endif
	docker compose run --rm scrub restore \
		/data/input/$(notdir $(file)) \
		--vault /data/vaults/$(vault).vault \
		--output /data/output/$(restore_output)

# ── Clean ─────────────────────────────────────
clean:
	docker compose down --rmi local --volumes --remove-orphans
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -name "*.pyc" -delete