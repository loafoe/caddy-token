# Pinned by digest for reproducible, tamper-evident builds.
FROM golang:1.27.1@sha256:512690a5660563b57d37ecc31129e7f136e831db2aed24a1dbeb8ad7380dc0fa AS builder
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

FROM alpine:3.24@sha256:5b02b42e375f7426f8d65c3af331ca05d9878f9989230354504e0b9dfd431f60
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
