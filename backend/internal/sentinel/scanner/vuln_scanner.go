package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/havilz/caelus-cloud/backend/internal/domain"
)

type KnownVulnRule struct {
	CheckID        string
	OSTypePattern  string
	Severity       domain.FindingSeverity
	Title          string
	Description    string
	Remediation    string
	RemediationCmd string
}

var knownVulnRules = []KnownVulnRule{
	{
		CheckID:        "vuln-ubuntu-noble-security-baseline",
		OSTypePattern:  "ubuntu",
		Severity:       domain.SeverityLow,
		Title:          "Audit Paket Keamanan Sistem Operasi Ubuntu",
		Description:    "Pemeriksaan ketersediaan pembaruan paket keamanan Linux (Security Updates).",
		Remediation:    "Jalankan pembaruan paket repositori berkala untuk menambal kerentanan CVE terbaru.",
		RemediationCmd: "sudo apt update && sudo apt dist-upgrade -y",
	},
	{
		CheckID:        "vuln-openssh-regresshion-cve-2024-6387",
		OSTypePattern:  "ubuntu",
		Severity:       domain.SeverityHigh,
		Title:          "Potensi Kerentanan OpenSSH (CVE-2024-6387 / regreSSHion)",
		Description:    "Server yang menggunakan versi OpenSSH yang belum dipatch rentan terhadap eksploitasi remote code execution unauthenticated.",
		Remediation:    "Segera lakukan upgrade paket openssh-server ke versi patch keamanan terbaru.",
		RemediationCmd: "sudo apt update && sudo apt install --only-upgrade openssh-server -y",
	},
	{
		CheckID:        "vuln-sudo-baron-samedit-cve-2021-3156",
		OSTypePattern:  "linux",
		Severity:       domain.SeverityHigh,
		Title:          "Audit Privilege Escalation Sudo (CVE-2021-3156 / Baron Samedit)",
		Description:    "Pemeriksaan kerentanan buffer overflow pada utilitas sudo yang memungkinkan pengguna biasa memperoleh akses root lokal.",
		Remediation:    "Perbarui biner paket sudo ke versi terbaru repositori OS.",
		RemediationCmd: "sudo apt update && sudo apt install --only-upgrade sudo -y || sudo yum update sudo -y",
	},
	{
		CheckID:        "vuln-docker-socket-mount-security",
		OSTypePattern:  "linux",
		Severity:       domain.SeverityCritical,
		Title:          "Audit Keamanan Izin Bind-Mount Socket Docker (/var/run/docker.sock)",
		Description:    "Paparan socket daemon Docker ke container yang tidak terpercaya memungkinkan pengambilalihan kontrol host penuh.",
		Remediation:    "Gunakan proxy API Docker terbatas (seperti socket-proxy) atau jalankan container tanpa bind-mount docker.sock.",
		RemediationCmd: "ls -la /var/run/docker.sock",
	},
}

type VulnScanner struct{}

func NewVulnScanner() *VulnScanner {
	return &VulnScanner{}
}

func (s *VulnScanner) Type() domain.ScanType {
	return domain.ScanTypeVuln
}

func (s *VulnScanner) Scan(ctx context.Context, target domain.ScanTarget) ([]domain.NormalizedFinding, error) {
	var findings []domain.NormalizedFinding
	osLower := strings.ToLower(target.OSType)
	if osLower == "" && target.TelemetryData != nil {
		osLower = strings.ToLower(target.TelemetryData.Platform)
	}

	for _, rule := range knownVulnRules {
		if rule.CheckID == "vuln-docker-socket-mount-security" && !target.HasDockerSocketMount {
			continue
		}
		if rule.OSTypePattern == "" || strings.Contains(osLower, rule.OSTypePattern) {
			findings = append(findings, domain.NormalizedFinding{
				CheckID:     rule.CheckID,
				Category:    domain.CategoryVulnerability,
				Severity:    rule.Severity,
				Title:       rule.Title,
				Description: rule.Description,
				Evidence: map[string]any{
					"detected_os":   target.OSType,
					"check_rule":    rule.CheckID,
					"severity_tier": rule.Severity,
				},
				Recommendation:     rule.Remediation,
				RemediationCommand: rule.RemediationCmd,
			})
		}
	}

	if target.TelemetryData != nil && target.TelemetryData.OS != "" {
		findings = append(findings, domain.NormalizedFinding{
			CheckID:     "vuln-kernel-security-advisory",
			Category:    domain.CategoryVulnerability,
			Severity:    domain.SeverityInfo,
			Title:       fmt.Sprintf("Informasi Kernel Host: %s", target.TelemetryData.OS),
			Description: "Pastikan pembaruan livepatch kernel Linux diaktifkan untuk perlindungan tanpa downtime.",
			Evidence: map[string]any{
				"kernel_os": target.TelemetryData.OS,
			},
			Recommendation:     "Gunakan Canonical Livepatch atau ksplice untuk patching kernel tanpa restart.",
			RemediationCommand: "uname -a",
		})
	}

	return findings, nil
}
