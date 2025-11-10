FROM ubuntu@sha256:66460d557b25769b102175144d538d88219c077c678a49af4afca6fbfc1b5252 as app
RUN apt-get update && \
    apt-get install -y \
    build-essential clang uidmap && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Makefile chall.cpp flag.txt ./

RUN make && \
    rm Makefile chall.cpp && \
    chmod 440 flag.txt && \
    chmod 550 chall

FROM ghcr.io/cscosu/jail:sha-7f273770804b4caac02c629fe196fefe9e949446
COPY --from=app / /srv

WORKDIR /srv

RUN mv /srv/app/chall /srv/app/run && \
    chmod 444 /srv/app/flag.txt && \
    chmod 555 /srv/app/run

RUN cp /etc/hosts /srv/etc/hosts && \
cp /etc/resolv.conf /srv/etc/resolv.conf && \
cp /etc/nsswitch.conf /srv/etc/nsswitch.conf

# jail configuration
ENV JAIL_TIME=300
ENV JAIL_CPU=100
ENV JAIL_PORT=1024
ENV JAIL_MEM=5M
