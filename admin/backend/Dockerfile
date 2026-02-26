FROM python:3.12-slim

WORKDIR /app

# Docker socket is mounted at runtime; we use the Docker Python SDK (no CLI needed)

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY static/ ./static/

ENV PYTHONUNBUFFERED=1
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
