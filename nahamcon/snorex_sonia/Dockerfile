FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y gcc make libc6-dev libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY snorex_sonia /app/

RUN chmod +x snorex_sonia

ENV SNOREX_SERIAL=FAKEZ-2K-CAM01
ENV SNOREX_MAC=AB:12:4D:7C:20:10
ENV FLAG=flag{now_repeat_against_remote_server}

EXPOSE 3500

CMD ["./snorex_sonia"]
