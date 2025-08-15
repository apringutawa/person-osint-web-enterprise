FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends     exiftool curl ca-certificates git gnupg chromium  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

RUN curl -sSL https://raw.githubusercontent.com/sundowndev/phoneinfoga/master/support/scripts/install | bash  && mv ./phoneinfoga /usr/local/bin/phoneinfoga  && phoneinfoga version || true

COPY app /app/app

ENV DATA_DIR=/data
VOLUME ["/data"]

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
