FROM ubuntu:24.04@sha256:d22e4fb389065efa4a61bb36416768698ef6d955fe8a7e0cdb3cd6de80fa7eec AS builder

RUN dpkg --add-architecture i386 && apt update -y && apt install -y libc6:i386

FROM pwn.red/jail@sha256:ee52ad5fd6cfed7fd8ea30b09792a6656045dd015f9bef4edbbfa2c6e672c28c


COPY --from=builder / /srv

# Change `./source/` to `./` if you want to run the Dockerfile.
COPY ./chal /srv/app/run
COPY ./flag.txt /srv/app/flag.txt

RUN chmod 755 /srv/app/run
RUN chmod 744 /srv/app/flag.txt

ENV JAIL_TIME=120
ENV JAIL_MEM=100M
ENV JAIL_TMP_SIZE=100M
