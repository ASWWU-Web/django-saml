FROM python:3.7-alpine3.9

MAINTAINER aswwu.webmaster@wallawalla.edu

RUN apk add mariadb-dev pcre pcre-dev && \
    apk add --no-cache --virtual .build-deps gcc libc-dev linux-headers libffi-dev libxml2-dev libxslt-dev xmlsec-dev && \
    pip install pipenv && \
    pip install uwsgi && \
    set -e && \
    adduser -S django

WORKDIR /home/django

COPY . django_server

WORKDIR /home/django/django_server
RUN pipenv install --system --deploy

ENV DJANGO_ENV=prod
ENV DOCKER_CONTAINER=1

EXPOSE 8000

RUN apk del .build-deps

USER django
CMD ["uwsgi", "--ini", "/home/django/django_server/uwsgi.ini"]
