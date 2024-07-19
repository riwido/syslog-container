FROM lscr.io/linuxserver/syslog-ng:latest

RUN \
  apk add -U --upgrade --no-cache  \
  python3-dev \
  py-pip  && \
  ln -sf /usr/bin/python3 /usr/bin/python && \
  rm -rf \
  /tmp/*

# RUN curl -sS https://bootstrap.pypa.io/get-pip.py | python3
# RUN python3 -m pip install lmtool
# RUN apk del build-base libffi-dev

COPY run /etc/s6-overlay/s6-rc.d/svc-syslog-ng/run
COPY syslog-ng.conf /config/syslog-ng.conf
COPY puller.py /puller.py
COPY healthcheck.sh /healthcheck.sh
RUN chown -R abc:abc /config

EXPOSE 5514/udp

HEALTHCHECK CMD ["/healthcheck.sh"]
