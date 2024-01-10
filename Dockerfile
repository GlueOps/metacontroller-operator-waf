FROM python:3.11.7-alpine3.19

COPY . /app
WORKDIR /app

RUN pip install --no-cache-dir -r requirements.txt
RUN pip install newrelic
ENV NEW_RELIC_CONFIG_FILE=newrelic.ini

CMD ["newrelic-admin", "run-program" "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
