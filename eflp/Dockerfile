FROM python:3.9-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    nginx \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
