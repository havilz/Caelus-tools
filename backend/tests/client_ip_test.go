package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/havilz/caelus-cloud/backend/internal/delivery/http/middleware"
)

func TestIPValidator_DirectConnection_SpoofedHeadersIgnored(t *testing.T) {
	validator := middleware.NewIPValidator([]string{"127.0.0.1", "10.0.0.0/8"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	req.RemoteAddr = "198.51.100.55:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.195")
	req.Header.Set("X-Real-IP", "203.0.113.195")

	clientIP := validator.ExtractClientIP(req)
	if clientIP != "198.51.100.55" {
		t.Fatalf("expected remote IP '198.51.100.55' (spoofed headers ignored), got: '%s'", clientIP)
	}
}

func TestIPValidator_TrustedProxy_SingleIP(t *testing.T) {
	validator := middleware.NewIPValidator([]string{"127.0.0.1", "::1"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	req.RemoteAddr = "127.0.0.1:45678"
	req.Header.Set("X-Forwarded-For", "203.0.113.195")

	clientIP := validator.ExtractClientIP(req)
	if clientIP != "203.0.113.195" {
		t.Fatalf("expected client IP '203.0.113.195' from trusted proxy, got: '%s'", clientIP)
	}
}

func TestIPValidator_TrustedProxy_CIDR(t *testing.T) {
	validator := middleware.NewIPValidator([]string{"10.0.0.0/8", "172.16.0.0/12"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	req.RemoteAddr = "10.244.5.12:45678"
	req.Header.Set("X-Forwarded-For", "198.51.100.99")

	clientIP := validator.ExtractClientIP(req)
	if clientIP != "198.51.100.99" {
		t.Fatalf("expected client IP '198.51.100.99' from trusted CIDR proxy, got: '%s'", clientIP)
	}
}

func TestIPValidator_MultiHopProxyChain(t *testing.T) {
	// Chain: Client (203.0.113.5) -> Trusted CDN (10.10.10.1) -> Trusted Ingress (10.0.0.2) -> Backend
	validator := middleware.NewIPValidator([]string{"10.0.0.2", "10.10.10.1"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	req.RemoteAddr = "10.0.0.2:34567"
	req.Header.Set("X-Forwarded-For", "203.0.113.5, 10.10.10.1")

	clientIP := validator.ExtractClientIP(req)
	if clientIP != "203.0.113.5" {
		t.Fatalf("expected first untrusted upstream IP '203.0.113.5', got: '%s'", clientIP)
	}
}

func TestIPValidator_MalformedHeaderFallback(t *testing.T) {
	validator := middleware.NewIPValidator([]string{"127.0.0.1"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	req.RemoteAddr = "127.0.0.1:45678"
	req.Header.Set("X-Forwarded-For", "not-a-valid-ip, another-invalid")

	clientIP := validator.ExtractClientIP(req)
	if clientIP != "127.0.0.1" {
		t.Fatalf("expected fallback to remote host '127.0.0.1', got: '%s'", clientIP)
	}
}

func TestClientIPMiddleware_Integration(t *testing.T) {
	validator := middleware.NewIPValidator([]string{"127.0.0.1"})

	r := chi.NewRouter()
	r.Use(middleware.ClientIPMiddleware(validator))
	r.Get("/test-ip", func(w http.ResponseWriter, req *http.Request) {
		extracted := middleware.ExtractClientIP(req)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fmt.Appendf(nil, "ip:%s,remote:%s", extracted, req.RemoteAddr))
	})

	// 1. Direct connection from untrusted IP attempting spoofing
	reqUntrusted := httptest.NewRequest(http.MethodGet, "/test-ip", nil)
	reqUntrusted.RemoteAddr = "198.51.100.77:9999"
	reqUntrusted.Header.Set("X-Forwarded-For", "1.1.1.1")
	recUntrusted := httptest.NewRecorder()

	r.ServeHTTP(recUntrusted, reqUntrusted)
	if recUntrusted.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recUntrusted.Code)
	}
	expectedUntrusted := "ip:198.51.100.77,remote:198.51.100.77:9999"
	if recUntrusted.Body.String() != expectedUntrusted {
		t.Fatalf("expected '%s', got '%s'", expectedUntrusted, recUntrusted.Body.String())
	}

	// 2. Request through trusted proxy with XFF
	reqTrusted := httptest.NewRequest(http.MethodGet, "/test-ip", nil)
	reqTrusted.RemoteAddr = "127.0.0.1:8888"
	reqTrusted.Header.Set("X-Forwarded-For", "203.0.113.88")
	recTrusted := httptest.NewRecorder()

	r.ServeHTTP(recTrusted, reqTrusted)
	if recTrusted.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recTrusted.Code)
	}
	expectedTrusted := "ip:203.0.113.88,remote:203.0.113.88:8888"
	if recTrusted.Body.String() != expectedTrusted {
		t.Fatalf("expected '%s', got '%s'", expectedTrusted, recTrusted.Body.String())
	}
}

func TestAuthRateLimiter_MitigateSpoofingBypass(t *testing.T) {
	// Configure trusted proxies to ONLY 127.0.0.1 (attacker is direct at 198.51.100.50)
	middleware.SetTrustedProxies([]string{"127.0.0.1"})

	limiter := middleware.NewAuthRateLimiter(5, 1*time.Minute)
	handler := limiter.Limit()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	attackerRemoteAddr := "198.51.100.50:43210"

	// Attacker attempts to bypass rate limiting by rotating X-Forwarded-For on each request
	for i := 1; i <= 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
		req.RemoteAddr = attackerRemoteAddr
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("192.0.2.%d", i))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d should be allowed, got: %d", i, rec.Code)
		}
	}

	// 6th request with yet another spoofed IP: MUST BE BLOCKED (HTTP 429)
	reqBlocked := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	reqBlocked.RemoteAddr = attackerRemoteAddr
	reqBlocked.Header.Set("X-Forwarded-For", "192.0.2.99")
	recBlocked := httptest.NewRecorder()

	handler.ServeHTTP(recBlocked, reqBlocked)
	if recBlocked.Code != http.StatusTooManyRequests {
		t.Fatalf("request 6 must be blocked with HTTP 429, got: %d (Spoofing bypass succeeded!)", recBlocked.Code)
	}
}

func TestAuthRateLimiter_TrustedProxy_DifferentClientsAllowed(t *testing.T) {
	// Configure 127.0.0.1 as trusted reverse proxy
	middleware.SetTrustedProxies([]string{"127.0.0.1"})

	limiter := middleware.NewAuthRateLimiter(5, 1*time.Minute)
	handler := limiter.Limit()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	proxyRemoteAddr := "127.0.0.1:43210"

	// Client A exhausts its limit (5 requests)
	for i := 1; i <= 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
		req.RemoteAddr = proxyRemoteAddr
		req.Header.Set("X-Forwarded-For", "203.0.113.1")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("client A request %d should be allowed, got: %d", i, rec.Code)
		}
	}

	// Client A's 6th request is blocked
	reqA6 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	reqA6.RemoteAddr = proxyRemoteAddr
	reqA6.Header.Set("X-Forwarded-For", "203.0.113.1")
	recA6 := httptest.NewRecorder()
	handler.ServeHTTP(recA6, reqA6)
	if recA6.Code != http.StatusTooManyRequests {
		t.Fatalf("client A 6th request should be blocked, got: %d", recA6.Code)
	}

	// Client B behind the same trusted proxy sends request: MUST BE ALLOWED (fair rate limiting)
	reqB := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	reqB.RemoteAddr = proxyRemoteAddr
	reqB.Header.Set("X-Forwarded-For", "203.0.113.2")
	recB := httptest.NewRecorder()
	handler.ServeHTTP(recB, reqB)
	if recB.Code != http.StatusOK {
		t.Fatalf("client B should be allowed with status 200, got: %d", recB.Code)
	}
}
