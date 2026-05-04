FROM ghcr.io/home-assistant/base-python:3.13-alpine3.22

ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1

RUN apk add --no-cache \
    bash \
    iputils

COPY app/requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

COPY run.sh /
COPY app /app

RUN chmod a+x /run.sh

CMD ["/run.sh"]
