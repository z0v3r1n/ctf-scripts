FROM ubuntu:24.04@sha256:d22e4fb389065efa4a61bb36416768698ef6d955fe8a7e0cdb3cd6de80fa7eec AS base
WORKDIR /app
COPY --chmod=555 run .
COPY --chmod=555 chall .
RUN echo "FLAG{*** REDACTED ***}" > /flag.txt
RUN mv /flag.txt /flag-$(md5sum /flag.txt | awk '{print $1}').txt
ENTRYPOINT "/app/run"
