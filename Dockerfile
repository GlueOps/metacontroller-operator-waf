FROM python:3.12.2-alpine3.19@sha256:25a82f6f8b720a6a257d58e478a0a5517448006e010c85273f4d9c706819478c

COPY . /app
WORKDIR /app

RUN pip install --no-cache-dir -r requirements.txt

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
