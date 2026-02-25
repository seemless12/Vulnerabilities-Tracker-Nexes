FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy everything (dockerignore handles exclusions)
COPY . .

# Render sets $PORT dynamically — use shell form so the variable is expanded
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-10000}
