FROM golang:1.23.6-alpine3.20 AS builder
WORKDIR /build
COPY go.mod .
COPY go.sum .
# Get dependancies - will also be cached if we won't change mod/sum
RUN go mod download
# Build
COPY . .
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
# There is no guarantee this is the latest TAG
RUN /go/bin/xcaddy build --with github.com/loafoe/caddy-token@{{TAG}}

FROM alpine:latest
USER root
COPY --from=builder /build/caddy /usr/bin
