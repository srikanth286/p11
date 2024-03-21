FROM ubuntu:20.04

# install build dependencies
RUN apt update && \
    apt-get -y install rsyslog softhsm2 curl g++ swig build-essential linux-headers-generic python3-dev && \
    sed -i 's/log.level = ERROR/log.level = DEBUG/g' /etc/softhsm/softhsm2.conf && \
    sed -i '/imklog/s/^/#/' /etc/rsyslog.conf

WORKDIR /tmp
RUN curl "https://bootstrap.pypa.io/pip/3.6/get-pip.py" -o "get-pip.py" \
    && python3 get-pip.py \
    && python3 -m pip install pykcs11

WORKDIR /
COPY init_softhsm.py init_softhsm.py
RUN python3 init_softhsm.py

ENTRYPOINT  ["tail", "-f", "/dev/null"]
# rsyslogd