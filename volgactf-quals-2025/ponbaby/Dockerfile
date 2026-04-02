FROM ubuntu:26.04@sha256:fed6ddb82c61194e1814e93b59cfcb6759e5aa33c4e41bb3782313c2386ed6df AS ubuntu

FROM pwn.red/jail

COPY --from=ubuntu / /srv

RUN mkdir -p /srv/app
COPY flag.txt /srv/app/flag.txt
RUN mv /srv/app/flag.txt /srv/app/flag-$(md5sum /srv/app/flag.txt | awk '{print $1}').txt
COPY chall /srv/app/chall
RUN chmod 555 /srv/app/chall
COPY run.sh /srv/app/run
RUN chmod 555 /srv/app/run
