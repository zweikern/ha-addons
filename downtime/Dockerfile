FROM ghcr.io/home-assistant/base-python:3.13-alpine3.22

ENV PYTHONUNBUFFERED=1

RUN apk add --no-cache \
    bash \
    iputils \
    py3-paho-mqtt \
    python3

COPY run.sh /
COPY app /app

RUN chmod a+x /run.sh

CMD ["/run.sh"]
