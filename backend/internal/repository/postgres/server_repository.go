package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/havilz/caelus-cloud/backend/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ServerRepository struct {
	pool *pgxpool.Pool
}

func NewServerRepository(pool *pgxpool.Pool) *ServerRepository {
	return &ServerRepository{pool: pool}
}

func (r *ServerRepository) Create(ctx context.Context, server *domain.Server) error {
	query := `
		INSERT INTO servers (id, organization_id, credential_id, provider_id, external_server_id, name, hostname, ip_address, status, os_type, cpu_cores, memory_mb, disk_gb, region, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		RETURNING id, created_at, updated_at;
	`

	if server.ID == uuid.Nil {
		server.ID = uuid.New()
	}

	return r.pool.QueryRow(
		ctx,
		query,
		server.ID,
		server.OrganizationID,
		server.CredentialID,
		server.ProviderID,
		server.ExternalServerID,
		server.Name,
		server.Hostname,
		server.IPAddress,
		server.Status,
		server.OSType,
		server.CPUCores,
		server.MemoryMB,
		server.DiskGB,
		server.Region,
		server.CreatedAt,
		server.UpdatedAt,
	).Scan(&server.ID, &server.CreatedAt, &server.UpdatedAt)
}

func (r *ServerRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Server, error) {
	query := `
		SELECT s.id, s.organization_id, s.credential_id, s.provider_id, s.external_server_id, s.name, s.hostname, s.ip_address, s.status, s.os_type, s.cpu_cores, s.memory_mb, s.disk_gb, s.region, s.created_at, s.updated_at,
		       p.id, p.name, p.slug, p.is_active, p.created_at
		FROM servers s
		INNER JOIN providers p ON s.provider_id = p.id
		WHERE s.id = $1;
	`

	var s domain.Server
	var p domain.Provider

	err := r.pool.QueryRow(ctx, query, id).Scan(
		&s.ID,
		&s.OrganizationID,
		&s.CredentialID,
		&s.ProviderID,
		&s.ExternalServerID,
		&s.Name,
		&s.Hostname,
		&s.IPAddress,
		&s.Status,
		&s.OSType,
		&s.CPUCores,
		&s.MemoryMB,
		&s.DiskGB,
		&s.Region,
		&s.CreatedAt,
		&s.UpdatedAt,
		&p.ID,
		&p.Name,
		&p.Slug,
		&p.IsActive,
		&p.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("gagal mengambil server berdasarkan id: %w", err)
	}

	s.Provider = &p
	return &s, nil
}

func (r *ServerRepository) ListByOrg(ctx context.Context, orgID uuid.UUID, page, limit int) ([]domain.Server, int64, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	offset := (page - 1) * limit

	countQuery := `SELECT COUNT(*) FROM servers WHERE organization_id = $1;`
	var total int64
	if err := r.pool.QueryRow(ctx, countQuery, orgID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("gagal menghitung total server: %w", err)
	}

	selectQuery := `
		SELECT s.id, s.organization_id, s.credential_id, s.provider_id, s.external_server_id, s.name, s.hostname, s.ip_address, s.status, s.os_type, s.cpu_cores, s.memory_mb, s.disk_gb, s.region, s.created_at, s.updated_at,
		       p.id, p.name, p.slug, p.is_active, p.created_at
		FROM servers s
		INNER JOIN providers p ON s.provider_id = p.id
		WHERE s.organization_id = $1
		ORDER BY s.created_at DESC
		LIMIT $2 OFFSET $3;
	`

	rows, err := r.pool.Query(ctx, selectQuery, orgID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("gagal mengambil daftar server: %w", err)
	}
	defer rows.Close()

	var servers []domain.Server
	for rows.Next() {
		var s domain.Server
		var p domain.Provider
		if err := rows.Scan(
			&s.ID,
			&s.OrganizationID,
			&s.CredentialID,
			&s.ProviderID,
			&s.ExternalServerID,
			&s.Name,
			&s.Hostname,
			&s.IPAddress,
			&s.Status,
			&s.OSType,
			&s.CPUCores,
			&s.MemoryMB,
			&s.DiskGB,
			&s.Region,
			&s.CreatedAt,
			&s.UpdatedAt,
			&p.ID,
			&p.Name,
			&p.Slug,
			&p.IsActive,
			&p.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("gagal memindai baris server: %w", err)
		}
		s.Provider = &p
		servers = append(servers, s)
	}

	return servers, total, nil
}

func (r *ServerRepository) Update(ctx context.Context, server *domain.Server) error {
	query := `
		UPDATE servers
		SET name = $2, hostname = $3, ip_address = $4, status = $5, cpu_cores = $6, memory_mb = $7, disk_gb = $8
		WHERE id = $1;
	`

	cmdTag, err := r.pool.Exec(ctx, query, server.ID, server.Name, server.Hostname, server.IPAddress, server.Status, server.CPUCores, server.MemoryMB, server.DiskGB)
	if err != nil {
		return fmt.Errorf("gagal memperbarui data server: %w", err)
	}

	if cmdTag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	return nil
}

func (r *ServerRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status domain.ServerStatus) error {
	query := `UPDATE servers SET status = $2 WHERE id = $1;`

	cmdTag, err := r.pool.Exec(ctx, query, id, status)
	if err != nil {
		return fmt.Errorf("gagal memperbarui status server: %w", err)
	}

	if cmdTag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	return nil
}

func (r *ServerRepository) ListAllRunning(ctx context.Context) ([]domain.Server, error) {
	query := `
		SELECT s.id, s.organization_id, s.credential_id, s.provider_id, s.external_server_id, s.name, s.hostname, s.ip_address, s.status, s.os_type, s.cpu_cores, s.memory_mb, s.disk_gb, s.region, s.created_at, s.updated_at
		FROM servers s
		WHERE s.status = 'running';
	`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("gagal query server running: %w", err)
	}
	defer rows.Close()

	var servers []domain.Server
	for rows.Next() {
		var s domain.Server
		if err := rows.Scan(
			&s.ID,
			&s.OrganizationID,
			&s.CredentialID,
			&s.ProviderID,
			&s.ExternalServerID,
			&s.Name,
			&s.Hostname,
			&s.IPAddress,
			&s.Status,
			&s.OSType,
			&s.CPUCores,
			&s.MemoryMB,
			&s.DiskGB,
			&s.Region,
			&s.CreatedAt,
			&s.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("gagal scan server: %w", err)
		}
		servers = append(servers, s)
	}

	return servers, nil
}

func (r *ServerRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM servers WHERE id = $1;`

	cmdTag, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("gagal menghapus server: %w", err)
	}

	if cmdTag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	return nil
}

func (r *ServerRepository) SetAgentSecret(ctx context.Context, serverID uuid.UUID, secretHash, secretPrefix string) error {
	query := `
		UPDATE servers
		SET agent_secret_hash = $2, agent_secret_prefix = $3, updated_at = NOW()
		WHERE id = $1;
	`

	cmdTag, err := r.pool.Exec(ctx, query, serverID, secretHash, secretPrefix)
	if err != nil {
		return fmt.Errorf("gagal menyimpan agent secret hash: %w", err)
	}

	if cmdTag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	return nil
}

func (r *ServerRepository) GetByIDWithSecret(ctx context.Context, id uuid.UUID) (*domain.Server, error) {
	query := `
		SELECT id, organization_id, credential_id, provider_id, external_server_id,
		       name, hostname, ip_address, status, os_type, cpu_cores, memory_mb, disk_gb, region,
		       agent_secret_hash, agent_secret_prefix, created_at, updated_at
		FROM servers
		WHERE id = $1;
	`

	var s domain.Server
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&s.ID,
		&s.OrganizationID,
		&s.CredentialID,
		&s.ProviderID,
		&s.ExternalServerID,
		&s.Name,
		&s.Hostname,
		&s.IPAddress,
		&s.Status,
		&s.OSType,
		&s.CPUCores,
		&s.MemoryMB,
		&s.DiskGB,
		&s.Region,
		&s.AgentSecretHash,
		&s.AgentSecretPrefix,
		&s.CreatedAt,
		&s.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("gagal mengambil server dengan secret: %w", err)
	}

	return &s, nil
}

// UpdateSSHHardened updates the SSH hardening security flag for a server.
func (r *ServerRepository) UpdateSSHHardened(ctx context.Context, id uuid.UUID, hardened bool) error {
	query := `UPDATE servers SET ssh_hardened = $2 WHERE id = $1;`
	_, err := r.pool.Exec(ctx, query, id, hardened)
	return err
}

// GetSSHHardened retrieves the SSH hardening state for a server.
func (r *ServerRepository) GetSSHHardened(ctx context.Context, id uuid.UUID) (bool, error) {
	query := `SELECT ssh_hardened FROM servers WHERE id = $1;`
	var hardened bool
	err := r.pool.QueryRow(ctx, query, id).Scan(&hardened)
	if err != nil {
		return false, err
	}
	return hardened, nil
}
