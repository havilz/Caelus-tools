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

type NetworkRepository struct {
	pool *pgxpool.Pool
}

func NewNetworkRepository(pool *pgxpool.Pool) *NetworkRepository {
	return &NetworkRepository{pool: pool}
}

func (r *NetworkRepository) CreateNetwork(ctx context.Context, net *domain.Network) error {
	query := `
		INSERT INTO networks (
			id, organization_id, name, type, cidr, gateway, region, driver, status, attached_servers, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		) RETURNING created_at, updated_at;
	`
	if net.ID == uuid.Nil {
		net.ID = uuid.New()
	}
	now := time.Now().UTC()
	net.CreatedAt = now
	net.UpdatedAt = now

	return r.pool.QueryRow(
		ctx,
		query,
		net.ID,
		net.OrganizationID,
		net.Name,
		net.Type,
		net.CIDR,
		net.Gateway,
		net.Region,
		net.Driver,
		net.Status,
		net.AttachedServers,
		net.CreatedAt,
		net.UpdatedAt,
	).Scan(&net.CreatedAt, &net.UpdatedAt)
}

func (r *NetworkRepository) GetNetworkByID(ctx context.Context, id uuid.UUID) (*domain.Network, error) {
	query := `
		SELECT id, organization_id, name, type, cidr, gateway, region, driver, status, attached_servers, created_at, updated_at
		FROM networks
		WHERE id = $1;
	`
	var net domain.Network
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&net.ID,
		&net.OrganizationID,
		&net.Name,
		&net.Type,
		&net.CIDR,
		&net.Gateway,
		&net.Region,
		&net.Driver,
		&net.Status,
		&net.AttachedServers,
		&net.CreatedAt,
		&net.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("network not found: %w", domain.ErrNotFound)
		}
		return nil, err
	}
	return &net, nil
}

func (r *NetworkRepository) ListNetworksByOrg(ctx context.Context, orgID uuid.UUID) ([]domain.Network, error) {
	query := `
		SELECT id, organization_id, name, type, cidr, gateway, region, driver, status, attached_servers, created_at, updated_at
		FROM networks
		WHERE organization_id = $1
		ORDER BY created_at DESC;
	`
	rows, err := r.pool.Query(ctx, query, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []domain.Network
	for rows.Next() {
		var net domain.Network
		if err := rows.Scan(
			&net.ID,
			&net.OrganizationID,
			&net.Name,
			&net.Type,
			&net.CIDR,
			&net.Gateway,
			&net.Region,
			&net.Driver,
			&net.Status,
			&net.AttachedServers,
			&net.CreatedAt,
			&net.UpdatedAt,
		); err != nil {
			return nil, err
		}
		list = append(list, net)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return list, nil
}

func (r *NetworkRepository) DeleteNetwork(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM networks WHERE id = $1;`
	_, err := r.pool.Exec(ctx, query, id)
	return err
}

func (r *NetworkRepository) CreateFirewallRule(ctx context.Context, rule *domain.FirewallRule) error {
	query := `
		INSERT INTO firewall_rules (
			id, organization_id, network_id, server_id, name, direction, protocol, port_range, source, action, status, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		) RETURNING created_at, updated_at;
	`
	if rule.ID == uuid.Nil {
		rule.ID = uuid.New()
	}
	now := time.Now().UTC()
	rule.CreatedAt = now
	rule.UpdatedAt = now

	return r.pool.QueryRow(
		ctx,
		query,
		rule.ID,
		rule.OrganizationID,
		rule.NetworkID,
		rule.ServerID,
		rule.Name,
		rule.Direction,
		rule.Protocol,
		rule.PortRange,
		rule.Source,
		rule.Action,
		rule.Status,
		rule.CreatedAt,
		rule.UpdatedAt,
	).Scan(&rule.CreatedAt, &rule.UpdatedAt)
}

func (r *NetworkRepository) GetFirewallRuleByID(ctx context.Context, id uuid.UUID) (*domain.FirewallRule, error) {
	query := `
		SELECT id, organization_id, network_id, server_id, name, direction, protocol, port_range, source, action, status, created_at, updated_at
		FROM firewall_rules
		WHERE id = $1;
	`
	var rule domain.FirewallRule
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&rule.ID,
		&rule.OrganizationID,
		&rule.NetworkID,
		&rule.ServerID,
		&rule.Name,
		&rule.Direction,
		&rule.Protocol,
		&rule.PortRange,
		&rule.Source,
		&rule.Action,
		&rule.Status,
		&rule.CreatedAt,
		&rule.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("firewall rule not found: %w", domain.ErrNotFound)
		}
		return nil, err
	}
	return &rule, nil
}

func (r *NetworkRepository) ListFirewallRulesByOrg(ctx context.Context, orgID uuid.UUID) ([]domain.FirewallRule, error) {
	query := `
		SELECT id, organization_id, network_id, server_id, name, direction, protocol, port_range, source, action, status, created_at, updated_at
		FROM firewall_rules
		WHERE organization_id = $1
		ORDER BY created_at DESC;
	`
	rows, err := r.pool.Query(ctx, query, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []domain.FirewallRule
	for rows.Next() {
		var rule domain.FirewallRule
		if err := rows.Scan(
			&rule.ID,
			&rule.OrganizationID,
			&rule.NetworkID,
			&rule.ServerID,
			&rule.Name,
			&rule.Direction,
			&rule.Protocol,
			&rule.PortRange,
			&rule.Source,
			&rule.Action,
			&rule.Status,
			&rule.CreatedAt,
			&rule.UpdatedAt,
		); err != nil {
			return nil, err
		}
		list = append(list, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return list, nil
}

func (r *NetworkRepository) DeleteFirewallRule(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM firewall_rules WHERE id = $1;`
	_, err := r.pool.Exec(ctx, query, id)
	return err
}
