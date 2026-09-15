# Pinned by digest for reproducible, tamper-evident builds.
FROM golang:1.27.1@sha256:f44f6e88636cfb311f9ebace870ded69d943f227bb3cb27d32ffd84ea18c43ea AS builder
WORKDIR /build
COPY go.mod .
COPY go.sum .
# Get dependancies - will also be cached if we won't change mod/sum
RUN go mod download
# Build
COPY . .
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
# There is no guarantee this is the latest TAG
# caddy-mirror is versioned independently of this repo; bump its pinned tag
# below when a new caddy-mirror release should be picked up by default.
RUN /go/bin/xcaddy build \
    --with github.com/loafoe/caddy-token@{{TAG}} \
    --with github.com/loafoe/caddy-mirror@v0.1.2

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
# Run as an unprivileged user rather than root.
RUN addgroup -S caddy && adduser -S -G caddy caddy
COPY --from=builder /build/caddy /usr/bin/caddy
# No file capabilities are set on the binary. An effective-bit file capability
# (setcap cap_net_bind_service=+ep) makes the kernel refuse to execve() the
# binary under NoNewPrivs (Kubernetes allowPrivilegeEscalation: false with all
# capabilities dropped), failing with "operation not permitted". Deployments
# should listen on high ports (>= 1024); to bind privileged ports, grant
# NET_BIND_SERVICE via the container securityContext instead.
USER caddy
ENTRYPOINT ["/usr/bin/caddy"]
