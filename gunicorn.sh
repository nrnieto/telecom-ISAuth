#!/usr/bin/env bash

NPROC=$(($(nproc)*2+1))
PORT=5000
LOG_LEVEL=info
WORKER_CLASS=gevent
CERTFILE=./certs/wildcard_corp_cablevision.crt
KEYFILE=./certs/wildcard_corp_cablevision.key

gunicorn --log-level=${LOG_LEVEL} \
         --workers=${NPROC} \
         --worker-class=${WORKER_CLASS} \
         --certfile=${CERTFILE} \
         --keyfile=${KEYFILE} \
         --bind 0.0.0.0:${PORT} \
         ISAuth.app:APP
