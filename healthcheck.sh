#!/usr/bin/env bash

grep -q $HEALTH_FILE <<< $(find / -path $HEALTH_FILE -mmin -5 2>/dev/null) \
  && grep -q /config/syslog-ng.conf <<< $(ps -ef)
