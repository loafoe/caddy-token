package token

import (
	"io"
	"net/http"
	"strconv"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus"
)

const metricsNamespace = "caddytoken"

// tenantMetrics holds the per-tenant counters registered on the shared Caddy
// metrics registry. Fields are nil when metrics collection is disabled.
type tenantMetrics struct {
	requestsTotal      *prometheus.CounterVec
	requestBytesTotal  *prometheus.CounterVec
	responseBytesTotal *prometheus.CounterVec
}

// initTenantMetrics registers the tenant activity counters on ctx's shared
// Prometheus registry. A Caddyfile with more than one server block that each
// configure a token{} handler (e.g. separate :80 and :443 listeners sharing
// one Caddyfile) provisions one Middleware instance per block, and Caddy
// calls Provision on each -- all against the same shared registry. The
// second instance's registration attempt would otherwise panic ("duplicate
// metrics collector registration attempted"), so registerOrReuse recovers
// the already-registered collector instead and every instance shares (and
// therefore correctly aggregates into) the same counters.
func initTenantMetrics(ctx caddy.Context) *tenantMetrics {
	registry := ctx.GetMetricsRegistry()
	labels := []string{"tenant", "path", "method", "code"}
	byteLabels := []string{"tenant", "path"}

	return &tenantMetrics{
		requestsTotal: registerOrReuseCounterVec(registry, prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: "tenant",
			Name:      "requests_total",
			Help:      "Count of upstream requests per tenant after X-Scope-OrgID resolution.",
		}, labels),
		requestBytesTotal: registerOrReuseCounterVec(registry, prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: "tenant",
			Name:      "request_bytes_total",
			Help:      "Bytes read from tenant request bodies (ingest) as they are forwarded upstream.",
		}, byteLabels),
		responseBytesTotal: registerOrReuseCounterVec(registry, prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: "tenant",
			Name:      "response_bytes_total",
			Help:      "Bytes written back to the tenant in upstream responses (egress).",
		}, byteLabels),
	}
}

// registerOrReuseCounterVec registers a new CounterVec on registry, or -- if
// a collector under the same fully-qualified name is already registered --
// returns that existing collector instead of panicking. Panics only if the
// name collides with a collector of a different type, which would indicate a
// real bug (e.g. a Help/label mismatch) rather than a benign re-provision.
func registerOrReuseCounterVec(registry prometheus.Registerer, opts prometheus.CounterOpts, labelNames []string) *prometheus.CounterVec {
	cv := prometheus.NewCounterVec(opts, labelNames)
	if err := registry.Register(cv); err != nil {
		are, ok := err.(prometheus.AlreadyRegisteredError)
		if !ok {
			panic(err)
		}
		existing, ok := are.ExistingCollector.(*prometheus.CounterVec)
		if !ok {
			panic(err)
		}
		return existing
	}
	return cv
}

// countingReadCloser wraps an io.ReadCloser and counts bytes as they are
// read, without buffering. Safe for concurrent use is not required: a
// request body is only ever read by a single goroutine.
type countingReadCloser struct {
	io.ReadCloser
	n int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	atomic.AddInt64(&c.n, int64(n))
	return n, err
}

func (c *countingReadCloser) count() int64 {
	return atomic.LoadInt64(&c.n)
}

// sanitizeMethod normalizes an HTTP method for use as a metric label,
// preventing unbounded cardinality from arbitrary client input. Caddy's own
// equivalent (internal/metrics.SanitizeMethod) is unexported outside its
// module, so this is a small local reimplementation.
func sanitizeMethod(m string) string {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodConnect,
		http.MethodOptions, http.MethodTrace:
		return m
	default:
		return "OTHER"
	}
}

// sanitizeCode normalizes an HTTP status code for use as a metric label,
// matching Caddy's own convention of treating 0 (never written) as 200.
func sanitizeCode(code int) string {
	if code == 0 {
		code = http.StatusOK
	}
	return strconv.Itoa(code)
}

// recordTenantActivity wraps r.Body and w to measure ingest/egress bytes for
// tenant, then calls next and records all three counters. tenant must be
// non-empty; callers should skip instrumentation entirely otherwise.
func (m *Middleware) recordTenantActivity(w http.ResponseWriter, r *http.Request, tenant string, next caddyhttp.Handler) error {
	var crc *countingReadCloser
	if r.Body != nil && r.Body != http.NoBody {
		crc = &countingReadCloser{ReadCloser: r.Body}
		r.Body = crc
	}

	wrec := caddyhttp.NewResponseRecorder(w, nil, func(status int, header http.Header) bool {
		return false // never buffer; we only need the byte count and status
	})

	err := next.ServeHTTP(wrec, r)

	path := r.URL.Path
	method := sanitizeMethod(r.Method)
	code := sanitizeCode(wrec.Status())

	m.metrics.requestsTotal.WithLabelValues(tenant, path, method, code).Inc()
	if crc != nil {
		m.metrics.requestBytesTotal.WithLabelValues(tenant, path).Add(float64(crc.count()))
	}
	m.metrics.responseBytesTotal.WithLabelValues(tenant, path).Add(float64(wrec.Size()))

	return err
}
