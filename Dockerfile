FROM python:3.11.9-alpine@sha256:cab9026aeb3d95351c22e7cdd979133e74d5525985e50fc5b39ef3ef372f616e

COPY . /app
WORKDIR /app

RUN pip install --no-cache-dir -r requirements.txt

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
