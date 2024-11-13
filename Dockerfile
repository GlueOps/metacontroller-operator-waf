FROM python:3.12.7-alpine@sha256:5049c050bdc68575a10bcb1885baa0689b6c15152d8a56a7e399fb49f783bf98

COPY . /app
WORKDIR /app

RUN pip install --no-cache-dir -r requirements.txt

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
