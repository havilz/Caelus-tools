package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/havilz/caelus-cloud/backend/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SecurityRepository struct {
	pool *pgxpool.Pool
}

func NewSecurityRepository(pool *pgxpool.Pool) *SecurityRepository {
	return &SecurityRepository{pool: pool}
}

func (r *SecurityRepository) CreateScan(ctx context.Context, scan *domain.SecurityScan) error {
	query := `
		INSERT INTO security_scans (id, organization_id, server_id, scan_type, status, started_at, completed_at, total_findings, critical_count, high_count, medium_count, low_count, score, error_message, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		RETURNING id, created_at, updated_at;
	`
	if scan.ID == uuid.Nil {
		scan.ID = uuid.New()
	}
	now := time.Now().UTC()
	scan.CreatedAt = now
	scan.UpdatedAt = now

	return r.pool.QueryRow(
		ctx,
		query,
		scan.ID,
		scan.OrganizationID,
		scan.ServerID,
		scan.ScanType,
		scan.Status,
		scan.StartedAt,
		scan.CompletedAt,
		scan.TotalFindings,
		scan.CriticalCount,
		scan.HighCount,
		scan.MediumCount,
		scan.LowCount,
		scan.Score,
		scan.ErrorMessage,
		scan.CreatedAt,
		scan.UpdatedAt,
	).Scan(&scan.ID, &scan.CreatedAt, &scan.UpdatedAt)
}

func (r *SecurityRepository) UpdateScan(ctx context.Context, scan *domain.SecurityScan) error {
	query := `
		UPDATE security_scans
		SET status = $3, started_at = $4, completed_at = $5, total_findings = $6,
		    critical_count = $7, high_count = $8, medium_count = $9, low_count = $10,
		    score = $11, error_message = $12, updated_at = NOW()
		WHERE id = $1 AND organization_id = $2;
	`
	cmd, err := r.pool.Exec(
		ctx,
		query,
		scan.ID,
		scan.OrganizationID,
		scan.Status,
		scan.StartedAt,
		scan.CompletedAt,
		scan.TotalFindings,
		scan.CriticalCount,
		scan.HighCount,
		scan.MediumCount,
		scan.LowCount,
		scan.Score,
		scan.ErrorMessage,
	)
	if err != nil {
		return fmt.Errorf("gagal memperbarui data scan: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *SecurityRepository) GetScanByID(ctx context.Context, orgID, scanID uuid.UUID) (*domain.SecurityScan, error) {
	query := `
		SELECT s.id, s.organization_id, s.server_id, COALESCE(srv.name, 'All Servers'),
		       s.scan_type, s.status, s.started_at, s.completed_at, s.total_findings,
		       s.critical_count, s.high_count, s.medium_count, s.low_count, s.score,
		       COALESCE(s.error_message, ''), s.created_at, s.updated_at
		FROM security_scans s
		LEFT JOIN servers srv ON s.server_id = srv.id
		WHERE s.id = $1 AND s.organization_id = $2;
	`
	var scan domain.SecurityScan
	err := r.pool.QueryRow(ctx, query, scanID, orgID).Scan(
		&scan.ID,
		&scan.OrganizationID,
		&scan.ServerID,
		&scan.ServerName,
		&scan.ScanType,
		&scan.Status,
		&scan.StartedAt,
		&scan.CompletedAt,
		&scan.TotalFindings,
		&scan.CriticalCount,
		&scan.HighCount,
		&scan.MediumCount,
		&scan.LowCount,
		&scan.Score,
		&scan.ErrorMessage,
		&scan.CreatedAt,
		&scan.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("gagal query scan by id: %w", err)
	}
	return &scan, nil
}

func (r *SecurityRepository) ListScans(ctx context.Context, orgID uuid.UUID, serverID *uuid.UUID, page, limit int) ([]domain.SecurityScan, int, error) {
	offset := (page - 1) * limit

	countQuery := `SELECT COUNT(*) FROM security_scans WHERE organization_id = $1 AND ($2::uuid IS NULL OR server_id = $2);`
	var total int
	if err := r.pool.QueryRow(ctx, countQuery, orgID, serverID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("gagal menghitung total scan: %w", err)
	}

	query := `
		SELECT s.id, s.organization_id, s.server_id, COALESCE(srv.name, 'All Servers'),
		       s.scan_type, s.status, s.started_at, s.completed_at, s.total_findings,
		       s.critical_count, s.high_count, s.medium_count, s.low_count, s.score,
		       COALESCE(s.error_message, ''), s.created_at, s.updated_at
		FROM security_scans s
		LEFT JOIN servers srv ON s.server_id = srv.id
		WHERE s.organization_id = $1 AND ($2::uuid IS NULL OR s.server_id = $2)
		ORDER BY s.created_at DESC
		LIMIT $3 OFFSET $4;
	`
	rows, err := r.pool.Query(ctx, query, orgID, serverID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("gagal query list scans: %w", err)
	}
	defer rows.Close()

	var scans []domain.SecurityScan
	for rows.Next() {
		var s domain.SecurityScan
		if err := rows.Scan(
			&s.ID,
			&s.OrganizationID,
			&s.ServerID,
			&s.ServerName,
			&s.ScanType,
			&s.Status,
			&s.StartedAt,
			&s.CompletedAt,
			&s.TotalFindings,
			&s.CriticalCount,
			&s.HighCount,
			&s.MediumCount,
			&s.LowCount,
			&s.Score,
			&s.ErrorMessage,
			&s.CreatedAt,
			&s.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("gagal scan baris scan: %w", err)
		}
		scans = append(scans, s)
	}
	return scans, total, nil
}

func (r *SecurityRepository) UpsertFinding(ctx context.Context, f *domain.SecurityFinding) error {
	query := `
		INSERT INTO security_findings (
			id, organization_id, server_id, scan_id, fingerprint, category, severity,
			title, description, evidence, recommendation, remediation_command, status,
			first_detected_at, last_detected_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT (organization_id, server_id, fingerprint)
		DO UPDATE SET
			scan_id = EXCLUDED.scan_id,
			severity = EXCLUDED.severity,
			title = EXCLUDED.title,
			description = EXCLUDED.description,
			evidence = EXCLUDED.evidence,
			recommendation = EXCLUDED.recommendation,
			remediation_command = EXCLUDED.remediation_command,
			last_detected_at = EXCLUDED.last_detected_at,
			status = CASE 
				WHEN security_findings.status = 'resolved' THEN 'resolved'
				WHEN security_findings.status = 'false_positive' THEN 'false_positive'
				ELSE EXCLUDED.status
			END;
	`
	if f.ID == uuid.Nil {
		f.ID = uuid.New()
	}
	now := time.Now().UTC()
	if f.FirstDetectedAt.IsZero() {
		f.FirstDetectedAt = now
	}
	f.LastDetectedAt = now

	_, err := r.pool.Exec(
		ctx,
		query,
		f.ID,
		f.OrganizationID,
		f.ServerID,
		f.ScanID,
		f.Fingerprint,
		f.Category,
		f.Severity,
		f.Title,
		f.Description,
		f.Evidence,
		f.Recommendation,
		f.RemediationCommand,
		f.Status,
		f.FirstDetectedAt,
		f.LastDetectedAt,
	)
	if err != nil {
		return fmt.Errorf("gagal upsert security finding: %w", err)
	}
	return nil
}

func (r *SecurityRepository) GetFindingByID(ctx context.Context, orgID, findingID uuid.UUID) (*domain.SecurityFinding, error) {
	query := `
		SELECT f.id, f.organization_id, f.server_id, COALESCE(srv.name, 'N/A'), f.scan_id,
		       f.fingerprint, f.category, f.severity, f.title, f.description, f.evidence,
		       COALESCE(f.recommendation, ''), COALESCE(f.remediation_command, ''),
		       f.status, f.resolved_at, f.first_detected_at, f.last_detected_at
		FROM security_findings f
		LEFT JOIN servers srv ON f.server_id = srv.id
		WHERE f.id = $1 AND f.organization_id = $2;
	`
	var f domain.SecurityFinding
	err := r.pool.QueryRow(ctx, query, findingID, orgID).Scan(
		&f.ID,
		&f.OrganizationID,
		&f.ServerID,
		&f.ServerName,
		&f.ScanID,
		&f.Fingerprint,
		&f.Category,
		&f.Severity,
		&f.Title,
		&f.Description,
		&f.Evidence,
		&f.Recommendation,
		&f.RemediationCommand,
		&f.Status,
		&f.ResolvedAt,
		&f.FirstDetectedAt,
		&f.LastDetectedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("gagal query finding by id: %w", err)
	}
	return &f, nil
}

func (r *SecurityRepository) ListFindings(
	ctx context.Context,
	orgID uuid.UUID,
	serverID *uuid.UUID,
	category *domain.FindingCategory,
	severity *domain.FindingSeverity,
	status *domain.FindingStatus,
	page, limit int,
) ([]domain.SecurityFinding, int, error) {
	offset := (page - 1) * limit

	countQuery := `
		SELECT COUNT(*)
		FROM security_findings
		WHERE organization_id = $1
		  AND ($2::uuid IS NULL OR server_id = $2)
		  AND ($3::varchar IS NULL OR category = $3)
		  AND ($4::varchar IS NULL OR severity = $4)
		  AND ($5::varchar IS NULL OR status = $5);
	`
	var total int
	if err := r.pool.QueryRow(ctx, countQuery, orgID, serverID, category, severity, status).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("gagal menghitung total findings: %w", err)
	}

	query := `
		SELECT f.id, f.organization_id, f.server_id, COALESCE(srv.name, 'N/A'), f.scan_id,
		       f.fingerprint, f.category, f.severity, f.title, f.description, f.evidence,
		       COALESCE(f.recommendation, ''), COALESCE(f.remediation_command, ''),
		       f.status, f.resolved_at, f.first_detected_at, f.last_detected_at
		FROM security_findings f
		LEFT JOIN servers srv ON f.server_id = srv.id
		WHERE f.organization_id = $1
		  AND ($2::uuid IS NULL OR f.server_id = $2)
		  AND ($3::varchar IS NULL OR f.category = $3)
		  AND ($4::varchar IS NULL OR f.severity = $4)
		  AND ($5::varchar IS NULL OR f.status = $5)
		ORDER BY
			CASE f.severity
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
				ELSE 5
			END,
			f.last_detected_at DESC
		LIMIT $6 OFFSET $7;
	`
	rows, err := r.pool.Query(ctx, query, orgID, serverID, category, severity, status, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("gagal query list findings: %w", err)
	}
	defer rows.Close()

	var findings []domain.SecurityFinding
	for rows.Next() {
		var f domain.SecurityFinding
		if err := rows.Scan(
			&f.ID,
			&f.OrganizationID,
			&f.ServerID,
			&f.ServerName,
			&f.ScanID,
			&f.Fingerprint,
			&f.Category,
			&f.Severity,
			&f.Title,
			&f.Description,
			&f.Evidence,
			&f.Recommendation,
			&f.RemediationCommand,
			&f.Status,
			&f.ResolvedAt,
			&f.FirstDetectedAt,
			&f.LastDetectedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("gagal scan baris finding: %w", err)
		}
		findings = append(findings, f)
	}
	return findings, total, nil
}

func (r *SecurityRepository) UpdateFindingStatus(ctx context.Context, orgID, findingID uuid.UUID, status domain.FindingStatus) error {
	var resolvedAt *time.Time
	if status == domain.FindingStatusResolved {
		now := time.Now().UTC()
		resolvedAt = &now
	}

	query := `
		UPDATE security_findings
		SET status = $3, resolved_at = $4
		WHERE id = $1 AND organization_id = $2;
	`
	cmd, err := r.pool.Exec(ctx, query, findingID, orgID, status, resolvedAt)
	if err != nil {
		return fmt.Errorf("gagal update status finding: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// ReopenFinding resets a finding back to open status.
func (r *SecurityRepository) ReopenFinding(ctx context.Context, orgID, findingID uuid.UUID) error {
	query := `
		UPDATE security_findings
		SET status = 'open', resolved_at = NULL, last_detected_at = CURRENT_TIMESTAMP
		WHERE id = $1 AND organization_id = $2;
	`
	cmd, err := r.pool.Exec(ctx, query, findingID, orgID)
	if err != nil {
		return fmt.Errorf("gagal membuka kembali status finding: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *SecurityRepository) GetPostureOverview(ctx context.Context, orgID uuid.UUID) (*domain.SecurityPostureOverview, error) {
	overview := &domain.SecurityPostureOverview{
		OverallScore:    100,
		Grade:           "A",
		CategorySummary: make(map[domain.FindingCategory]int),
	}

	_ = r.pool.QueryRow(ctx, `SELECT COUNT(*), MAX(created_at) FROM security_scans WHERE organization_id = $1`, orgID).
		Scan(&overview.TotalScans, &overview.LastScanAt)

	query := `
		SELECT severity, COUNT(*)
		FROM security_findings
		WHERE organization_id = $1 AND status IN ('open', 'acknowledged')
		GROUP BY severity;
	`
	rows, err := r.pool.Query(ctx, query, orgID)
	if err != nil {
		return overview, nil
	}
	defer rows.Close()

	score := 100
	for rows.Next() {
		var sev domain.FindingSeverity
		var count int
		if err := rows.Scan(&sev, &count); err == nil {
			switch sev {
			case domain.SeverityCritical:
				overview.CriticalCount = count
				score -= count * 20
			case domain.SeverityHigh:
				overview.HighCount = count
				score -= count * 10
			case domain.SeverityMedium:
				overview.MediumCount = count
				score -= count * 5
			case domain.SeverityLow:
				overview.LowCount = count
				score -= count * 2
			}
			overview.OpenFindings += count
		}
	}

	if score < 0 {
		score = 0
	}
	overview.OverallScore = score

	switch {
	case score >= 90:
		overview.Grade = "A"
	case score >= 80:
		overview.Grade = "B"
	case score >= 70:
		overview.Grade = "C"
	case score >= 50:
		overview.Grade = "D"
	default:
		overview.Grade = "F"
	}

	_ = r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM security_findings WHERE organization_id = $1 AND status = 'resolved'`, orgID).
		Scan(&overview.ResolvedCount)

	catRows, err := r.pool.Query(ctx, `SELECT category, COUNT(*) FROM security_findings WHERE organization_id = $1 AND status IN ('open', 'acknowledged') GROUP BY category`, orgID)
	if err == nil {
		defer catRows.Close()
		for catRows.Next() {
			var cat domain.FindingCategory
			var count int
			if err := catRows.Scan(&cat, &count); err == nil {
				overview.CategorySummary[cat] = count
			}
		}
	}

	return overview, nil
}

func (r *SecurityRepository) CreateIncident(ctx context.Context, inc *domain.SecurityIncident) error {
	query := `
		INSERT INTO security_incidents (id, organization_id, title, severity, status, finding_ids, summary, mitigation_notes, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, created_at, updated_at;
	`
	if inc.ID == uuid.Nil {
		inc.ID = uuid.New()
	}
	now := time.Now().UTC()
	inc.CreatedAt = now
	inc.UpdatedAt = now

	return r.pool.QueryRow(
		ctx,
		query,
		inc.ID,
		inc.OrganizationID,
		inc.Title,
		inc.Severity,
		inc.Status,
		inc.FindingIDs,
		inc.Summary,
		inc.MitigationNotes,
		inc.CreatedAt,
		inc.UpdatedAt,
	).Scan(&inc.ID, &inc.CreatedAt, &inc.UpdatedAt)
}

func (r *SecurityRepository) ListIncidents(ctx context.Context, orgID uuid.UUID, status *domain.IncidentStatus, page, limit int) ([]domain.SecurityIncident, int, error) {
	offset := (page - 1) * limit
	countQuery := `SELECT COUNT(*) FROM security_incidents WHERE organization_id = $1 AND ($2::varchar IS NULL OR status = $2);`
	var total int
	if err := r.pool.QueryRow(ctx, countQuery, orgID, status).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("gagal menghitung insiden: %w", err)
	}

	query := `
		SELECT id, organization_id, title, severity, status, finding_ids, summary, mitigation_notes, created_at, updated_at
		FROM security_incidents
		WHERE organization_id = $1 AND ($2::varchar IS NULL OR status = $2)
		ORDER BY created_at DESC
		LIMIT $3 OFFSET $4;
	`
	rows, err := r.pool.Query(ctx, query, orgID, status, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("gagal query incidents: %w", err)
	}
	defer rows.Close()

	var incidents []domain.SecurityIncident
	for rows.Next() {
		var inc domain.SecurityIncident
		if err := rows.Scan(
			&inc.ID,
			&inc.OrganizationID,
			&inc.Title,
			&inc.Severity,
			&inc.Status,
			&inc.FindingIDs,
			&inc.Summary,
			&inc.MitigationNotes,
			&inc.CreatedAt,
			&inc.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("gagal scan baris incident: %w", err)
		}
		incidents = append(incidents, inc)
	}
	return incidents, total, nil
}

func (r *SecurityRepository) UpdateIncidentStatus(ctx context.Context, orgID, incidentID uuid.UUID, status domain.IncidentStatus, notes string) error {
	query := `
		UPDATE security_incidents
		SET status = $3, mitigation_notes = COALESCE(NULLIF($4, ''), mitigation_notes), updated_at = NOW()
		WHERE id = $1 AND organization_id = $2;
	`
	cmd, err := r.pool.Exec(ctx, query, incidentID, orgID, status, notes)
	if err != nil {
		return fmt.Errorf("gagal update status incident: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}
