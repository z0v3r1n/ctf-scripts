FROM golang:1.25.0 AS builder
COPY bashtille.go ./
RUN go build bashtille.go

FROM debian
RUN mkdir /app
RUN mkdir -m 0333 /app/jails
USER 1000
WORKDIR /app
COPY flag.txt /app/flag.txt
COPY --from=builder /go/bashtille /app/bashtille
CMD ["/bin/bash", "-c", "while true; do timeout 1h /app/bashtille server; done"]
