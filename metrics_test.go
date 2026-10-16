package token

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

type stubHandler struct {
	status       int
	responseBody []byte
	readBody     bool
}

func (s stubHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	if s.readBody && r.Body != nil {
		_, _ = io.ReadAll(r.Body)
	}
	w.WriteHeader(s.status)
	_, _ = w.Write(s.responseBody)
	return nil
}

func newTestMiddleware(t *testing.T) *Middleware {
	t.Helper()
	m := &Middleware{
		logger:            zaptest.NewLogger(t),
		Metrics:           true,
		AllowUpstreamAuth: true,
		InjectOrgHeader:   true,
	}
	m.metrics = &tenantMetrics{
		requestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace, Subsystem: "tenant", Name: "requests_total",
		}, []string{"tenant", "path", "method", "code"}),
		requestBytesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace, Subsystem: "tenant", Name: "request_bytes_total",
		}, []string{"tenant", "path"}),
		responseBytesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace, Subsystem: "tenant", Name: "response_bytes_total",
		}, []string{"tenant", "path"}),
	}
	return m
}

func TestServeHTTP_RecordsTenantActivity(t *testing.T) {
	m := newTestMiddleware(t)

	reqBody := []byte("0123456789")      // 10 bytes ingest
	respBody := []byte("hello world!!!") // 14 bytes egress

	req := httptest.NewRequest(http.MethodPost, "/loki/api/v1/push", bytes.NewReader(reqBody))
	req.Header.Set("X-Scope-OrgID", "tenant-a")
	rw := httptest.NewRecorder()

	next := stubHandler{status: http.StatusOK, responseBody: respBody, readBody: true}

	err := m.ServeHTTP(rw, req, next)
	require.NoError(t, err)

	assert.Equal(t, float64(1), testutil.ToFloat64(
		m.metrics.requestsTotal.WithLabelValues("tenant-a", "/loki/api/v1/push", "POST", "200")))
	assert.Equal(t, float64(10), testutil.ToFloat64(
		m.metrics.requestBytesTotal.WithLabelValues("tenant-a", "/loki/api/v1/push")))
	assert.Equal(t, float64(14), testutil.ToFloat64(
		m.metrics.responseBytesTotal.WithLabelValues("tenant-a", "/loki/api/v1/push")))
}

func TestServeHTTP_SkipsMetricsWithoutTenant(t *testing.T) {
	m := newTestMiddleware(t)
	m.AllowUpstreamAuth = false

	req := httptest.NewRequest(http.MethodGet, "/loki/api/v1/query", nil)
	rw := httptest.NewRecorder()

	next := stubHandler{status: http.StatusUnauthorized}

	// No auth method configured and no upstream header allowed: the auth
	// check itself fails before metrics are ever considered.
	err := m.ServeHTTP(rw, req, next)
	assert.Error(t, err)
	if caddyErr, ok := err.(caddyhttp.HandlerError); ok {
		assert.Equal(t, http.StatusUnauthorized, caddyErr.StatusCode)
	}

	assert.Equal(t, float64(0), testutil.ToFloat64(m.metrics.requestsTotal.WithLabelValues(
		"", "/loki/api/v1/query", "GET", "200")))
}

func TestServeHTTP_NoMetricsWhenDisabled(t *testing.T) {
	m := newTestMiddleware(t)
	m.Metrics = false
	m.metrics = nil

	req := httptest.NewRequest(http.MethodGet, "/loki/api/v1/query", nil)
	req.Header.Set("X-Scope-OrgID", "tenant-a")
	rw := httptest.NewRecorder()

	next := stubHandler{status: http.StatusOK}

	err := m.ServeHTTP(rw, req, next)
	assert.NoError(t, err)
}

// TestInitTenantMetrics_MultipleServerBlocksShareRegistry reproduces the
// production panic: a Caddyfile with more than one server block that each
// configure "token { metrics true }" (e.g. separate :8080 and :8443
// listeners, as otlp-gateway's loadbalancer.enabled mode produces) gets one
// Middleware instance per block, and Caddy calls Provision -> initTenantMetrics
// on each against the *same* shared registry. Before the fix, the second call
// panicked with "duplicate metrics collector registration attempted" instead
// of returning.
func TestInitTenantMetrics_MultipleServerBlocksShareRegistry(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	var first, second *tenantMetrics
	require.NotPanics(t, func() {
		first = initTenantMetrics(ctx)
	})
	require.NotPanics(t, func() {
		second = initTenantMetrics(ctx)
	}, "a second token{} handler provisioned against the same registry must not panic")

	// Not just "didn't panic" -- the second instance must share the exact
	// same collectors as the first, so activity recorded by either server
	// block's handler aggregates into one series instead of silently
	// splitting (or worse, one of the two going unregistered/unexported).
	assert.Same(t, first.requestsTotal, second.requestsTotal)
	assert.Same(t, first.requestBytesTotal, second.requestBytesTotal)
	assert.Same(t, first.responseBytesTotal, second.responseBytesTotal)

	first.requestsTotal.WithLabelValues("tenant-a", "/loki/api/v1/push", "POST", "204").Inc()
	second.requestsTotal.WithLabelValues("tenant-a", "/loki/api/v1/push", "POST", "204").Inc()
	assert.Equal(t, float64(2), testutil.ToFloat64(
		second.requestsTotal.WithLabelValues("tenant-a", "/loki/api/v1/push", "POST", "204")))
}
