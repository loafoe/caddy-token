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

FROM alpine:3.24@sha256:f5064d3e5f88c467c714509f491853ab2d951932c5cad699c0cb969dcec6f3b4
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
