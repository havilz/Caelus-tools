package scanner

import (
	"context"
	"fmt"

	"github.com/havilz/caelus-cloud/backend/internal/domain"
)

type HostConfigScanner struct{}

func NewHostConfigScanner() *HostConfigScanner {
	return &HostConfigScanner{}
}

func (s *HostConfigScanner) Type() domain.ScanType {
	return domain.ScanTypeHostConfig
}

func (s *HostConfigScanner) Scan(ctx context.Context, target domain.ScanTarget) ([]domain.NormalizedFinding, error) {
	var findings []domain.NormalizedFinding

	if target.TelemetryData != nil {
		uptimeDays := target.TelemetryData.UptimeSeconds / 86400
		if uptimeDays > 180 {
			findings = append(findings, domain.NormalizedFinding{
				CheckID:     "host-reboot-required-stale-uptime",
				Category:    domain.CategoryHostConfig,
				Severity:    domain.SeverityMedium,
				Title:       "Server Belum Di-reboot Lebih dari 180 Hari",
				Description: fmt.Sprintf("Server memiliki uptime %d hari. Kernel update dan security patches sistem operasi kemungkinan belum diaplikasikan ke memory.", uptimeDays),
				Evidence: map[string]any{
					"uptime_days":    uptimeDays,
					"uptime_seconds": target.TelemetryData.UptimeSeconds,
					"os_platform":    target.TelemetryData.Platform,
				},
				Recommendation:     "Jadwalkan jendela pemeliharaan (maintenance window) untuk me-reboot server dan mengaplikasikan patch kernel terbaru.",
				RemediationCommand: "sudo apt update && sudo apt upgrade -y && sudo reboot",
			})
		}

		if target.TelemetryData.MemoryTotalMB > 0 {
			usedPct := target.TelemetryData.MemoryUsagePct
			if usedPct > 95.0 {
				findings = append(findings, domain.NormalizedFinding{
					CheckID:     "host-memory-exhaustion-risk",
					Category:    domain.CategoryHostConfig,
					Severity:    domain.SeverityHigh,
					Title:       "Kapasitas RAM Kritis (> 95% Terpakai)",
					Description: fmt.Sprintf("Penggunaan memori server mencapai %.1f%%, berisiko memicu kernel OOM (Out-Of-Memory) killer yang dapat mematikan proses keamanan dan database.", usedPct),
					Evidence: map[string]any{
						"memory_usage_pct": usedPct,
						"memory_used_mb":   target.TelemetryData.MemoryUsedMB,
						"memory_total_mb":  target.TelemetryData.MemoryTotalMB,
					},
					Recommendation:     "Tingkatkan kapasitas RAM server atau optimasi aplikasi untuk mencegah server crash.",
					RemediationCommand: "free -m && ps aux --sort=-%mem | head -n 10",
				})
			}
		}

		if target.TelemetryData.DiskUsagePct > 90.0 {
			findings = append(findings, domain.NormalizedFinding{
				CheckID:     "host-disk-space-critical",
				Category:    domain.CategoryHostConfig,
				Severity:    domain.SeverityHigh,
				Title:       "Penyimpanan Partisi Root Kritis (> 90% Terpakai)",
				Description: fmt.Sprintf("Kapasitas disk utama mencapai %.1f%%. Ruang disk yang habis dapat menghentikan penulisan security log dan memicu kegagalan database.", target.TelemetryData.DiskUsagePct),
				Evidence: map[string]any{
					"disk_usage_pct": target.TelemetryData.DiskUsagePct,
					"disk_used_gb":   target.TelemetryData.DiskUsedGB,
					"disk_total_gb":  target.TelemetryData.DiskTotalGB,
				},
				Recommendation:     "Bersihkan berkas log lama, cache apt/docker, atau perbesar volume penyimpanan SSD.",
				RemediationCommand: "sudo apt clean && sudo docker system prune -af --volumes",
			})
		}
	}

	if target.TelemetryData == nil || !target.TelemetryData.SSHHardened {
		findings = append(findings, domain.NormalizedFinding{
			CheckID:     "host-ssh-hardening-check",
			Category:    domain.CategoryHostConfig,
			Severity:    domain.SeverityLow,
			Title:       "Audit Konfigurasi SSH Daemon (CIS Benchmark)",
			Description: "Pastikan konfigurasi OpenSSH menolak login langsung user root dan menonaktifkan autentikasi password plaintext.",
			Evidence: map[string]any{
				"recommended_permit_root_login": "no",
				"recommended_password_auth":     "no",
				"config_path":                   "/etc/ssh/sshd_config",
			},
			Recommendation:     "Ubah 'PermitRootLogin no' dan 'PasswordAuthentication no' pada file /etc/ssh/sshd_config.",
			RemediationCommand: "sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl reload ssh",
		})
	}

	return findings, nil
}
