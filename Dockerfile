FROM python:3.11.9-alpine@sha256:5745fa2b8591a756160721b8305adba3972fb26a9132789ed60160f21e55f5dc

COPY . /app
WORKDIR /app

RUN pip install --no-cache-dir -r requirements.txt

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
