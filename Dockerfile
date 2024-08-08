FROM golang:1.22.6-alpine3.20 AS builder
WORKDIR /build
COPY go.mod .
COPY go.sum .
# Get dependancies - will also be cached if we won't change mod/sum
RUN go mod download
# Build
COPY . .
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
RUN /go/bin/xcaddy build --with github.com/loafoe/caddy-token

FROM alpine:latest
USER root
COPY --from=builder /build/caddy /usr/bin
