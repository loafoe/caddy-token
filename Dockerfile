# Pinned by digest for reproducible, tamper-evident builds.
FROM golang:1.26.4@sha256:87a41d2539e5671777734e91f467499ed5eafb1fb1f77221dff2744db7a51775 AS builder
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

FROM alpine:3.22@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601
# Run as an unprivileged user rather than root.
RUN addgroup -S caddy && adduser -S -G caddy caddy
COPY --from=builder /build/caddy /usr/bin/caddy
# Grant the net-bind capability so caddy can still listen on ports < 1024
# (e.g. 80/443) without running as root.
RUN apk add --no-cache libcap \
    && setcap cap_net_bind_service=+ep /usr/bin/caddy \
    && apk del libcap
USER caddy
ENTRYPOINT ["/usr/bin/caddy"]
