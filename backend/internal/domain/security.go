package domain

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type ScanType string

const (
	ScanTypeFull       ScanType = "full"
	ScanTypePort       ScanType = "port"
	ScanTypeTLS        ScanType = "tls"
	ScanTypeHeaders    ScanType = "headers"
	ScanTypeHostConfig ScanType = "host_config"
	ScanTypeVuln       ScanType = "vuln"
)

type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "pending"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
)

type FindingSeverity string

const (
	SeverityCritical FindingSeverity = "critical"
	SeverityHigh     FindingSeverity = "high"
	SeverityMedium   FindingSeverity = "medium"
	SeverityLow      FindingSeverity = "low"
	SeverityInfo     FindingSeverity = "info"
)

type FindingCategory string

const (
	CategoryNetwork       FindingCategory = "network"
	CategoryTLS           FindingCategory = "tls"
	CategoryHTTPHeaders   FindingCategory = "http_headers"
	CategoryHostConfig    FindingCategory = "host_config"
	CategoryVulnerability FindingCategory = "vulnerability"
)

type FindingStatus string

const (
	FindingStatusOpen          FindingStatus = "open"
	FindingStatusAcknowledged  FindingStatus = "acknowledged"
	FindingStatusResolved      FindingStatus = "resolved"
	FindingStatusFalsePositive FindingStatus = "false_positive"
)

type IncidentStatus string

const (
	IncidentStatusOpen          IncidentStatus = "open"
	IncidentStatusInvestigating IncidentStatus = "investigating"
	IncidentStatusMitigated     IncidentStatus = "mitigated"
	IncidentStatusClosed        IncidentStatus = "closed"
)

type SecurityScan struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	ServerID       *uuid.UUID `json:"server_id,omitempty"`
	ServerName     string     `json:"server_name,omitempty"`
	ScanType       ScanType   `json:"scan_type"`
	Status         ScanStatus `json:"status"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
	TotalFindings  int        `json:"total_findings"`
	CriticalCount  int        `json:"critical_count"`
	HighCount      int        `json:"high_count"`
	MediumCount    int        `json:"medium_count"`
	LowCount       int        `json:"low_count"`
	Score          int        `json:"score"`
	ErrorMessage   string     `json:"error_message,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type SecurityFinding struct {
	ID                 uuid.UUID       `json:"id"`
	OrganizationID     uuid.UUID       `json:"organization_id"`
	ServerID           *uuid.UUID      `json:"server_id,omitempty"`
	ServerName         string          `json:"server_name,omitempty"`
	ScanID             *uuid.UUID      `json:"scan_id,omitempty"`
	Fingerprint        string          `json:"fingerprint"`
	Category           FindingCategory `json:"category"`
	Severity           FindingSeverity `json:"severity"`
	Title              string          `json:"title"`
	Description        string          `json:"description"`
	Evidence           json.RawMessage `json:"evidence,omitempty"`
	Recommendation     string          `json:"recommendation,omitempty"`
	RemediationCommand string          `json:"remediation_command,omitempty"`
	Status             FindingStatus   `json:"status"`
	ResolvedAt         *time.Time      `json:"resolved_at,omitempty"`
	FirstDetectedAt    time.Time       `json:"first_detected_at"`
	LastDetectedAt     time.Time       `json:"last_detected_at"`
}

type SecurityIncident struct {
	ID              uuid.UUID       `json:"id"`
	OrganizationID  uuid.UUID       `json:"organization_id"`
	Title           string          `json:"title"`
	Severity        FindingSeverity `json:"severity"`
	Status          IncidentStatus  `json:"status"`
	FindingIDs      []uuid.UUID     `json:"finding_ids"`
	Summary         string          `json:"summary,omitempty"`
	MitigationNotes string          `json:"mitigation_notes,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

type SecurityPostureOverview struct {
	OverallScore    int                     `json:"overall_score"`
	Grade           string                  `json:"grade"`
	TotalScans      int                     `json:"total_scans"`
	OpenFindings    int                     `json:"open_findings"`
	CriticalCount   int                     `json:"critical_count"`
	HighCount       int                     `json:"high_count"`
	MediumCount     int                     `json:"medium_count"`
	LowCount        int                     `json:"low_count"`
	ResolvedCount   int                     `json:"resolved_count"`
	LastScanAt      *time.Time              `json:"last_scan_at,omitempty"`
	CategorySummary map[FindingCategory]int `json:"category_summary"`
}

type NormalizedFinding struct {
	CheckID            string          `json:"check_id"`
	Category           FindingCategory `json:"category"`
	Severity           FindingSeverity `json:"severity"`
	Title              string          `json:"title"`
	Description        string          `json:"description"`
	Evidence           any             `json:"evidence,omitempty"`
	Recommendation     string          `json:"recommendation,omitempty"`
	RemediationCommand string          `json:"remediation_command,omitempty"`
}

type ScanTarget struct {
	ServerID       *uuid.UUID
	OrganizationID uuid.UUID
	ServerName     string
	IPAddress      string
	Hostname       string
	OSType         string
	TelemetryData        *HostMetricsPayload
	HasDockerSocketMount bool
}

type SecurityRepository interface {
	CreateScan(ctx context.Context, scan *SecurityScan) error

	UpdateScan(ctx context.Context, scan *SecurityScan) error

	GetScanByID(ctx context.Context, orgID, scanID uuid.UUID) (*SecurityScan, error)

	ListScans(ctx context.Context, orgID uuid.UUID, serverID *uuid.UUID, page, limit int) ([]SecurityScan, int, error)

	UpsertFinding(ctx context.Context, finding *SecurityFinding) error

	GetFindingByID(ctx context.Context, orgID, findingID uuid.UUID) (*SecurityFinding, error)

	ListFindings(ctx context.Context, orgID uuid.UUID, serverID *uuid.UUID, category *FindingCategory, severity *FindingSeverity, status *FindingStatus, page, limit int) ([]SecurityFinding, int, error)

	UpdateFindingStatus(ctx context.Context, orgID, findingID uuid.UUID, status FindingStatus) error

	ReopenFinding(ctx context.Context, orgID, findingID uuid.UUID) error

	GetPostureOverview(ctx context.Context, orgID uuid.UUID) (*SecurityPostureOverview, error)

	CreateIncident(ctx context.Context, incident *SecurityIncident) error

	ListIncidents(ctx context.Context, orgID uuid.UUID, status *IncidentStatus, page, limit int) ([]SecurityIncident, int, error)

	UpdateIncidentStatus(ctx context.Context, orgID, incidentID uuid.UUID, status IncidentStatus, notes string) error
}
