FROM ubuntu:22.04
RUN apt-get update --fix-missing && \
 apt-get install -y socat python3 && \
 rm -rf /var/lib/apt/lists/*
RUN groupadd -r ctf && useradd -r -g ctf ctf

COPY challenge/ /home/ctf/
RUN chmod 555 /home/ctf/blinded /home/ctf/ld-2.35.so
RUN chmod 444 /home/ctf/libc.so.6
RUN chmod 400 /home/ctf/server.py

WORKDIR /home/ctf
EXPOSE 1337
ENTRYPOINT ["socat", "tcp-l:1337,reuseaddr,fork", "EXEC:python3 server.py,stderr"]
