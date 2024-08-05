FROM python:3.11.9-alpine@sha256:700b4aa84090748aafb348fc042b5970abb0a73c8f1b4fcfe0f4e3c2a4a9fcca

COPY . /app
WORKDIR /app

RUN pip install --no-cache-dir -r requirements.txt

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
