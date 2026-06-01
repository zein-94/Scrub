FROM python:3.11-slim

# System deps for spaCy + pdfplumber
RUN apt-get update && apt-get install -y \
    build-essential \
    libpoppler-cpp-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
ENV PYTHONPATH=/app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

ENTRYPOINT ["python", "cli.py"]