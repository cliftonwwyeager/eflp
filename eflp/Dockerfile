FROM python:3.9-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    nginx \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

COPY eflp_app/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY eflp_app/ /app/
COPY nginx/nginx.conf /tmp/nginx.conf
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

RUN mkdir -p /etc/nginx/certs && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout /etc/nginx/certs/nginx.key \
      -out /etc/nginx/certs/nginx.crt \
      -subj "/C=US/ST=State/L=City/O=EFLP/CN=localhost" && \
    rm -f /etc/nginx/conf.d/default.conf && \
    sed 's#http://eflp_app:5000#http://127.0.0.1:5000#g' /tmp/nginx.conf > /etc/nginx/conf.d/default.conf && \
    rm -f /tmp/nginx.conf /tmp/requirements.txt

EXPOSE 80
EXPOSE 8443
EXPOSE 5000

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
