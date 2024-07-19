__Setup:__
```
cp blank_envvars.txt envvars.txt
```

modify envvars.txt

```
docker build . --tag logger

__Run:__
```
docker run --rm -d --name logger \
  -p 514:5514/udp \
  --env-file=envvars.txt \
  -v /syslog:/var/log \
  logger
```
__Shell:__
```
docker exec -it puller /bin/bash
```
__Debug:__
```
syslog-ng-ctl trace --set=on --control=/config/syslog-ng.ctl
syslog-ng-ctl debug --set=on --control=/config/syslog-ng.ctl
syslog-ng-ctl verbose --set=on --control=/config/syslog-ng.ctl
```
