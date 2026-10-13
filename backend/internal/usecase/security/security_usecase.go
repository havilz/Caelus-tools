package security

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/havilz/caelus-cloud/backend/internal/domain"
	"github.com/havilz/caelus-cloud/backend/internal/sentinel"
	"github.com/havilz/caelus-cloud/backend/internal/usecase/actionqueue"
	"github.com/havilz/caelus-cloud/backend/internal/usecase/network"
	"github.com/havilz/caelus-cloud/backend/pkg/logger"
)

type SecurityUsecase interface {
	TriggerScan(ctx context.Context, orgID uuid.UUID, serverID *uuid.UUID, scanType domain.ScanType) (*domain.SecurityScan, error)
	GetScan(ctx context.Context, orgID, scanID uuid.UUID) (*domain.SecurityScan, error)
	ListScans(ctx context.Context, orgID uuid.UUID, serverID *uuid.UUID, page, limit int) ([]domain.SecurityScan, int, error)
	ListFindings(ctx context.Context, orgID uuid.UUID, serverID *uuid.UUID, category *domain.FindingCategory, severity *domain.FindingSeverity, status *domain.FindingStatus, page, limit int) ([]domain.SecurityFinding, int, error)
	GetFinding(ctx context.Context, orgID, findingID uuid.UUID) (*domain.SecurityFinding, error)
	UpdateFindingStatus(ctx context.Context, orgID, findingID uuid.UUID, status domain.FindingStatus) error
	RemediateFinding(ctx context.Context, orgID, findingID uuid.UUID) error
	ReopenFinding(ctx context.Context, orgID, findingID uuid.UUID) error
	ReverifyFinding(ctx context.Context, orgID, findingID uuid.UUID) (*domain.SecurityFinding, error)
	GetPostureOverview(ctx context.Context, orgID uuid.UUID) (*domain.SecurityPostureOverview, error)
	CreateIncident(ctx context.Context, orgID uuid.UUID, title, summary string, severity domain.FindingSeverity, findingIDs []uuid.UUID) (*domain.SecurityIncident, error)
	ListIncidents(ctx context.Context, orgID uuid.UUID, status *domain.IncidentStatus, page, limit int) ([]domain.SecurityIncident, int, error)
	UpdateIncidentStatus(ctx context.Context, orgID, incidentID uuid.UUID, status domain.IncidentStatus, notes string) error
}

type securityUsecase struct {
	securityRepo   domain.SecurityRepository
	serverRepo     domain.ServerRepository
	metricRepo     domain.MetricRepository
	orchestrator   *sentinel.Orchestrator
	networkUsecase *network.UseCase
	actionQueue    actionqueue.ActionQueue
}

// NewSecurityUsecase initializes the security usecase with repository, sentinel orchestrator, and remediation dependencies.
func NewSecurityUsecase(
	securityRepo domain.SecurityRepository,
	serverRepo domain.ServerRepository,
	metricRepo domain.MetricRepository,
	orchestrator *sentinel.Orchestrator,
	networkUsecase *network.UseCase,
	actionQueue actionqueue.ActionQueue,
) SecurityUsecase {
	return &securityUsecase{
		securityRepo:   securityRepo,
		serverRepo:     serverRepo,
		metricRepo:     metricRepo,
		orchestrator:   orchestrator,
		networkUsecase: networkUsecase,
		actionQueue:    actionQueue,
	}
}

func (u *securityUsecase) TriggerScan(ctx context.Context, orgID uuid.UUID, serverID *uuid.UUID, scanType domain.ScanType) (*domain.SecurityScan, error) {
	if scanType == "" {
		scanType = domain.ScanTypeFull
	}

	target := domain.ScanTarget{
		OrganizationID: orgID,
		ServerID:       serverID,
	}

	if serverID != nil && *serverID != uuid.Nil {
		srv, err := u.serverRepo.GetByID(ctx, *serverID)
		if err != nil {
			return nil, fmt.Errorf("server tidak ditemukan: %w", err)
		}
		if srv.OrganizationID != orgID {
			return nil, domain.ErrForbidden
		}

		target.ServerName = srv.Name
		if srv.IPAddress != nil {
			target.IPAddress = *srv.IPAddress
		}
		if srv.Hostname != nil {
			target.Hostname = *srv.Hostname
		}
		target.OSType = srv.OSType

		latestMetric, err := u.metricRepo.GetLatestByServerID(ctx, srv.ID)
		if err == nil && latestMetric != nil {
			target.TelemetryData = &domain.HostMetricsPayload{
				CPUUsagePct:    latestMetric.CPUUsagePct,
				MemoryUsagePct: latestMetric.MemoryUsagePct,
				MemoryUsedMB:   uint64(latestMetric.MemoryUsedMB),
				MemoryTotalMB:  uint64(latestMetric.MemoryTotalMB),
				DiskUsagePct:   latestMetric.DiskUsagePct,
				DiskUsedGB:     latestMetric.DiskUsedGB,
				DiskTotalGB:    latestMetric.DiskTotalGB,
				UptimeSeconds:  uint64(latestMetric.UptimeSeconds),
				Platform:       srv.OSType,
				Hostname:       target.Hostname,
			}
		}

		if target.TelemetryData == nil {
			target.TelemetryData = &domain.HostMetricsPayload{
				Platform: srv.OSType,
				Hostname: target.Hostname,
			}
		}

		if hardened, hErr := u.serverRepo.GetSSHHardened(ctx, srv.ID); hErr == nil {
			target.TelemetryData.SSHHardened = hardened
		}

		if latestMetric != nil && latestMetric.ContainersJSON != "" {
			var containers []domain.ContainerMetricPayload
			if err := json.Unmarshal([]byte(latestMetric.ContainersJSON), &containers); err == nil {
				for _, c := range containers {
					for _, vm := range c.VolumeMounts {
						if strings.Contains(vm.Source, "docker.sock") || strings.Contains(vm.Destination, "docker.sock") {
							target.HasDockerSocketMount = true
							break
						}
					}
				}
			}
		}
	} else {
		target.ServerName = "All Organization Servers"
		target.IPAddress = "127.0.0.1"
	}

	scan := &domain.SecurityScan{
		ID:             uuid.New(),
		OrganizationID: orgID,
		ServerID:       serverID,
		ServerName:     target.ServerName,
		ScanType:       scanType,
		Status:         domain.ScanStatusPending,
		Score:          100,
	}

	if err := u.securityRepo.CreateScan(ctx, scan); err != nil {
		return nil, fmt.Errorf("gagal membuat sesi scan: %w", err)
	}

	go func(s *domain.SecurityScan, t domain.ScanTarget) {
		bgCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		if _, err := u.orchestrator.ExecuteScan(bgCtx, s, t); err != nil {
			logger.Error("Sentinel scan execution failed", "scan_id", s.ID, "error", err)
		}
	}(scan, target)

	return scan, nil
}

func (u *securityUsecase) GetScan(ctx context.Context, orgID, scanID uuid.UUID) (*domain.SecurityScan, error) {
	return u.securityRepo.GetScanByID(ctx, orgID, scanID)
}

func (u *securityUsecase) ListScans(ctx context.Context, orgID uuid.UUID, serverID *uuid.UUID, page, limit int) ([]domain.SecurityScan, int, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	return u.securityRepo.ListScans(ctx, orgID, serverID, page, limit)
}

func (u *securityUsecase) ListFindings(
	ctx context.Context,
	orgID uuid.UUID,
	serverID *uuid.UUID,
	category *domain.FindingCategory,
	severity *domain.FindingSeverity,
	status *domain.FindingStatus,
	page, limit int,
) ([]domain.SecurityFinding, int, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	return u.securityRepo.ListFindings(ctx, orgID, serverID, category, severity, status, page, limit)
}

func (u *securityUsecase) GetFinding(ctx context.Context, orgID, findingID uuid.UUID) (*domain.SecurityFinding, error) {
	return u.securityRepo.GetFindingByID(ctx, orgID, findingID)
}

func (u *securityUsecase) UpdateFindingStatus(ctx context.Context, orgID, findingID uuid.UUID, status domain.FindingStatus) error {
	return u.securityRepo.UpdateFindingStatus(ctx, orgID, findingID, status)
}

// RemediateFinding applies automated remediation for a security finding by enforcing firewall rules or host hardening.
func (u *securityUsecase) RemediateFinding(ctx context.Context, orgID, findingID uuid.UUID) error {
	finding, err := u.securityRepo.GetFindingByID(ctx, orgID, findingID)
	if err != nil {
		return fmt.Errorf("temuan keamanan tidak ditemukan: %w", err)
	}

	if finding.Status == domain.FindingStatusResolved {
		return nil
	}

	isOpenPort := finding.Category == domain.CategoryNetwork || strings.HasPrefix(finding.Fingerprint, "port-") || strings.Contains(strings.ToLower(finding.Title), "port")
	if isOpenPort && u.networkUsecase != nil {
		portStr := ""
		if len(finding.Evidence) > 0 {
			var evData map[string]any
			if err := json.Unmarshal(finding.Evidence, &evData); err == nil {
				if p, ok := evData["port"]; ok {
					portStr = fmt.Sprintf("%v", p)
				}
			}
		}
		if portStr == "" {
			parts := strings.Fields(finding.Title)
			for _, part := range parts {
				part = strings.Trim(part, ":,()")
				if _, parseErr := strconv.Atoi(part); parseErr == nil {
					portStr = part
					break
				}
			}
		}
		if portStr != "" {
			ruleReq := domain.CreateFirewallRuleRequest{
				ServerID:  finding.ServerID,
				Name:      fmt.Sprintf("Auto-Remediate: Close Port %s", portStr),
				Direction: "inbound",
				Protocol:  "tcp",
				PortRange: portStr,
				Source:    "0.0.0.0/0",
				Action:    "deny",
			}
			if _, fwErr := u.networkUsecase.CreateFirewallRule(ctx, orgID, ruleReq); fwErr != nil {
				return fmt.Errorf("gagal membuat aturan firewall remediasi: %w", fwErr)
			}
		}
	}

	isSSHHardening := finding.Category == domain.CategoryHostConfig && (strings.Contains(strings.ToLower(finding.Title), "ssh") || strings.Contains(strings.ToLower(finding.Description), "ssh"))
	if isSSHHardening && finding.ServerID != nil && u.actionQueue != nil {
		u.actionQueue.Enqueue(*finding.ServerID, domain.AgentAction{
			ID:      uuid.New().String(),
			Type:    "HARDEN_SSH",
			Target:  "sshd_config",
			Payload: "PermitRootLogin=no,PasswordAuthentication=no",
		})
	}

	if err := u.securityRepo.UpdateFindingStatus(ctx, orgID, findingID, domain.FindingStatusResolved); err != nil {
		return fmt.Errorf("gagal memperbarui status temuan: %w", err)
	}

	return nil
}

func (u *securityUsecase) GetPostureOverview(ctx context.Context, orgID uuid.UUID) (*domain.SecurityPostureOverview, error) {
	return u.securityRepo.GetPostureOverview(ctx, orgID)
}

func (u *securityUsecase) CreateIncident(ctx context.Context, orgID uuid.UUID, title, summary string, severity domain.FindingSeverity, findingIDs []uuid.UUID) (*domain.SecurityIncident, error) {
	if severity == "" {
		severity = domain.SeverityHigh
	}
	incident := &domain.SecurityIncident{
		OrganizationID: orgID,
		Title:          title,
		Summary:        summary,
		Severity:       severity,
		Status:         domain.IncidentStatusOpen,
		FindingIDs:     findingIDs,
	}
	if err := u.securityRepo.CreateIncident(ctx, incident); err != nil {
		return nil, err
	}
	return incident, nil
}

func (u *securityUsecase) ListIncidents(ctx context.Context, orgID uuid.UUID, status *domain.IncidentStatus, page, limit int) ([]domain.SecurityIncident, int, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	return u.securityRepo.ListIncidents(ctx, orgID, status, page, limit)
}

func (u *securityUsecase) UpdateIncidentStatus(ctx context.Context, orgID, incidentID uuid.UUID, status domain.IncidentStatus, notes string) error {
	return u.securityRepo.UpdateIncidentStatus(ctx, orgID, incidentID, status, notes)
}

func (u *securityUsecase) ReopenFinding(ctx context.Context, orgID, findingID uuid.UUID) error {
	return u.securityRepo.ReopenFinding(ctx, orgID, findingID)
}

func (u *securityUsecase) ReverifyFinding(ctx context.Context, orgID, findingID uuid.UUID) (*domain.SecurityFinding, error) {
	finding, err := u.securityRepo.GetFindingByID(ctx, orgID, findingID)
	if err != nil {
		return nil, err
	}

	if finding.ServerID != nil {
		scanType := domain.ScanTypeHostConfig
		switch finding.Category {
		case domain.CategoryNetwork:
			scanType = domain.ScanTypePort
		case domain.CategoryVulnerability:
			scanType = domain.ScanTypeVuln
		case domain.CategoryTLS:
			scanType = domain.ScanTypeTLS
		case domain.CategoryHTTPHeaders:
			scanType = domain.ScanTypeHeaders
		}
		_, _ = u.TriggerScan(ctx, orgID, finding.ServerID, scanType)
	}

	return u.securityRepo.GetFindingByID(ctx, orgID, findingID)
}
