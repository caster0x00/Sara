FROM python:3-alpine

RUN apk update && \
    apk add --no-cache py3-colorama && \
    pip install --no-cache-dir setuptools && \
    rm -rf /var/cache/apk/*

WORKDIR /app

COPY . /app

RUN python3 setup.py install


CMD [ "sara", "--config-file", "/config/routeros.rsc" ]