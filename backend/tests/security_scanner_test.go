package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/havilz/caelus-cloud/backend/internal/domain"
	"github.com/havilz/caelus-cloud/backend/internal/sentinel"
	"github.com/havilz/caelus-cloud/backend/internal/sentinel/scanner"
)

func TestPortScanner_ScanLocalhost(t *testing.T) {
	s := scanner.NewPortScanner(100 * time.Millisecond)
	if s.Type() != domain.ScanTypePort {
		t.Fatalf("tipe scanner tidak sesuai, dapat: %s", s.Type())
	}

	target := domain.ScanTarget{
		IPAddress: "127.0.0.1",
		Hostname:  "localhost",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	findings, err := s.Scan(ctx, target)
	if err != nil {
		t.Fatalf("scan port gagal: %v", err)
	}

	t.Logf("Hasil port scan localhost: %d temuan", len(findings))
}

func TestHeadersScanner_AuditsHeaders(t *testing.T) {

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello Secure World"))
	}))
	defer srv.Close()

	s := scanner.NewHeadersScanner(1 * time.Second)
	if s.Type() != domain.ScanTypeHeaders {
		t.Fatalf("tipe scanner tidak sesuai: %s", s.Type())
	}

	target := domain.ScanTarget{
		Hostname:  srv.Listener.Addr().String(),
		IPAddress: srv.Listener.Addr().String(),
	}

	ctx := context.Background()
	findings, err := s.Scan(ctx, target)
	if err != nil {
		t.Fatalf("scan headers gagal: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("seharusnya mendeteksi missing security headers pada mock server")
	}

	foundHSTS := false
	for _, f := range findings {
		if f.Category != domain.CategoryHTTPHeaders {
			t.Errorf("kategori temuan harus http_headers, dapat: %s", f.Category)
		}
		if f.CheckID == "missing-header-strict_transport_security" {
			foundHSTS = true
		}
	}

	if !foundHSTS {
		t.Errorf("seharusnya mendeteksi missing HSTS header")
	}
}

func TestHostConfigScanner_EvaluatesTelemetry(t *testing.T) {
	s := scanner.NewHostConfigScanner()
	if s.Type() != domain.ScanTypeHostConfig {
		t.Fatalf("tipe scanner tidak sesuai: %s", s.Type())
	}

	target := domain.ScanTarget{
		TelemetryData: &domain.HostMetricsPayload{
			CPUUsagePct:    50.0,
			MemoryUsagePct: 98.5,
			DiskUsagePct:   94.0,
			UptimeSeconds:  200 * 86400,
			Platform:       "ubuntu",
		},
	}

	ctx := context.Background()
	findings, err := s.Scan(ctx, target)
	if err != nil {
		t.Fatalf("scan host config gagal: %v", err)
	}

	if len(findings) < 3 {
		t.Fatalf("seharusnya mendeteksi minimal 3 isu host (memory, disk, uptime), dapat %d", len(findings))
	}
}

func TestVulnScanner_EvaluatesOS(t *testing.T) {
	s := scanner.NewVulnScanner()
	if s.Type() != domain.ScanTypeVuln {
		t.Fatalf("tipe scanner tidak sesuai: %s", s.Type())
	}

	target := domain.ScanTarget{
		OSType: "Ubuntu 24.04 LTS (Noble Numbat)",
		TelemetryData: &domain.HostMetricsPayload{
			OS: "Linux 6.8.0-generic",
		},
	}

	ctx := context.Background()
	findings, err := s.Scan(ctx, target)
	if err != nil {
		t.Fatalf("scan vuln gagal: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("seharusnya menemukan aturan vuln untuk Ubuntu")
	}
}

func TestFindingNormalizer_GeneratesFingerprint(t *testing.T) {
	norm := sentinel.NewFindingNormalizer()
	orgID := uuid.New()
	serverID := uuid.New()
	scanID := uuid.New()

	raw := domain.NormalizedFinding{
		CheckID:     "test-check-1",
		Category:    domain.CategoryNetwork,
		Severity:    domain.SeverityCritical,
		Title:       "Test Exposed Redis",
		Description: "Redis exposed",
		Evidence:    map[string]any{"port": 6379},
	}

	f1, err := norm.Normalize(orgID, &serverID, &scanID, raw)
	if err != nil {
		t.Fatalf("normalisasi gagal: %v", err)
	}

	if f1.Fingerprint == "" {
		t.Fatalf("fingerprint tidak boleh kosong")
	}

	f2, _ := norm.Normalize(orgID, &serverID, &scanID, raw)
	if f1.Fingerprint != f2.Fingerprint {
		t.Fatalf("fingerprint harus konsisten untuk checkID dan serverID yang sama")
	}
}

func TestHostConfigScanner_SSHHardenedSkipped(t *testing.T) {
	s := scanner.NewHostConfigScanner()
	target := domain.ScanTarget{
		TelemetryData: &domain.HostMetricsPayload{
			SSHHardened: true,
			Platform:    "ubuntu",
		},
	}

	findings, err := s.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("scan gagal: %v", err)
	}

	for _, f := range findings {
		if f.CheckID == "host-ssh-hardening-check" {
			t.Fatalf("host-ssh-hardening-check seharusnya tidak muncul jika server sudah di-harden")
		}
	}
}

func TestVulnScanner_DockerSocketSkippedWhenNoMount(t *testing.T) {
	s := scanner.NewVulnScanner()
	target := domain.ScanTarget{
		OSType:               "linux",
		HasDockerSocketMount: false,
	}

	findings, err := s.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("scan gagal: %v", err)
	}

	for _, f := range findings {
		if f.CheckID == "vuln-docker-socket-mount-security" {
			t.Fatalf("vuln-docker-socket-mount-security seharusnya tidak muncul jika tidak ada container yang me-mount socket")
		}
	}
}
