FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt /app/

RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

EXPOSE 5000
EXPOSE 5514/udp

CMD ["python", "eflp_app.py"]
