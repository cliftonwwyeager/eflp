FROM nginx:1.27-alpine

RUN apk add --no-cache openssl

RUN mkdir -p /etc/nginx/certs && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout /etc/nginx/certs/nginx.key \
      -out /etc/nginx/certs/nginx.crt \
      -subj "/C=US/ST=State/L=City/O=EFLP/CN=localhost"

RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
EXPOSE 8443

CMD ["nginx", "-g", "daemon off;"]
