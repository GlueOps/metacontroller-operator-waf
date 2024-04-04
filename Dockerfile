FROM python:3.11.9-alpine@sha256:506861259a53e68b95992ff711dd2aab9ff8dc8a50ff4dca24c6e88dc461563e

COPY . /app
WORKDIR /app

RUN pip install --no-cache-dir -r requirements.txt

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
