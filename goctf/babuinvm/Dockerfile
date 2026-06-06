FROM ubuntu:26.04@sha256:fed6ddb82c61194e1814e93b59cfcb6759e5aa33c4e41bb3782313c2386ed6df

RUN apt-get update
RUN apt-get install -y socat

RUN mkdir -p /srv/app
WORKDIR /srv/app

COPY chall .
COPY run.sh .
RUN chmod 555 chall
RUN chmod 555 run.sh
RUN echo "flag{test_flag}" > /flag.txt

RUN useradd pwn

EXPOSE 6702
CMD ["./run.sh"]

