FROM archlinux@sha256:c136b06a4f786b84c1cc0d2494fabdf9be8811d15051cd4404deb5c3dc0b2e57 AS builder

FROM pwn.red/jail@sha256:ee52ad5fd6cfed7fd8ea30b09792a6656045dd015f9bef4edbbfa2c6e672c28c
COPY --from=builder / /srv

COPY chal /srv/app/run
COPY flag.txt /srv/app/flag.txt
COPY ./libc.so.6 /srv/lib/libc.so.6

RUN chmod 755 /srv/app/run
RUN chmod 755 /srv/lib/libc.so.6
RUN chmod 744 /srv/app/flag.txt

ENV JAIL_TIME=1500
ENV JAIL_MEM=50M
ENV JAIL_PIDS=100

# RUN echo "mount --rbind /dev /srv/dev" >> /jail/hook.sh 
# ENV JAIL_DEV=
