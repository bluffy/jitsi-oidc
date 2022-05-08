ARG GO_VERSION=1.16

FROM golang:${GO_VERSION}-alpine AS builder

WORKDIR /src

COPY . .

RUN go build -ldflags "-w -s" -o jitsi-oidc

FROM alpine

WORKDIR /app

COPY --from=builder /src/jitsi-oidc .
COPY LICENSE .

EXPOSE 3001

ENTRYPOINT ["/app/jitsi-oidc"]