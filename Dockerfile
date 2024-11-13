FROM python:3.11.10-alpine@sha256:65c34f59d896f939f204e64c2f098db4a4c235be425bd8f0804fd389b1e5fd80

COPY . /app
WORKDIR /app

RUN pip install --no-cache-dir -r requirements.txt

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
