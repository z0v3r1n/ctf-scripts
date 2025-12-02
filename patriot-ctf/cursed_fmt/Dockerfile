FROM debian@sha256:849d9d34d5fe0bf88b5fb3d09eb9684909ac4210488b52f4f7bbe683eedcb851

# Packages
RUN apt-get update
RUN apt-get install -y build-essential socat gcc make
RUN rm -rf /var/lib/apt/lists/*

# Low priv user
RUN useradd -d /home/ctf -m -p ctf -s /bin/bash ctf
RUN echo "ctf:ctf" | chpasswd
RUN ulimit -c 0

# Build
COPY src/flag.txt /home/ctf/flag.txt
COPY src/Makefile /home/ctf/Makefile
COPY src/cursed_format.c /home/ctf/cursed_format.c
RUN chmod 444 /home/ctf/flag.txt
WORKDIR /home/ctf
RUN make

# Service
EXPOSE 8888
CMD socat TCP-LISTEN:8888,reuseaddr,fork EXEC:"/home/ctf/cursed_format",stderr
