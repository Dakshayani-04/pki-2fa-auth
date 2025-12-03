# Stage 1: Builder
FROM python:3.11-slim as builder

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

ENV TZ=UTC

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends cron tzdata && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN ln -snf /usr/share/zoneinfo/UTC /etc/localtime && \
    echo UTC > /etc/timezone

COPY --from=builder /root/.local /root/.local

ENV PATH=/root/.local/bin:$PATH

COPY main.py /app/main.py
COPY scripts /app/scripts
COPY cron /app/cron

RUN chmod +x /app/scripts/log_2fa_cron.py
RUN mkdir -p /data /cron && chmod 755 /data /cron
RUN chmod 0644 /app/cron/2fa-cron
RUN crontab /app/cron/2fa-cron

EXPOSE 8080

CMD ["sh", "-c", "cron && /usr/local/bin/python3 /app/main.py"]
