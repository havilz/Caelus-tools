package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type ServerStatus string

const (
	ServerStatusPending    ServerStatus = "pending"
	ServerStatusRunning    ServerStatus = "running"
	ServerStatusStopped    ServerStatus = "stopped"
	ServerStatusRestarting ServerStatus = "restarting"
	ServerStatusError      ServerStatus = "error"
	ServerStatusTerminated ServerStatus = "terminated"
)

type Server struct {
	ID               uuid.UUID    `json:"id"`
	OrganizationID   uuid.UUID    `json:"organization_id"`
	CredentialID     *uuid.UUID   `json:"credential_id,omitempty"`
	ProviderID       uuid.UUID    `json:"provider_id"`
	ExternalServerID *string      `json:"external_server_id,omitempty"`
	Name             string       `json:"name"`
	Hostname         *string      `json:"hostname,omitempty"`
	IPAddress        *string      `json:"ip_address,omitempty"`
	Status           ServerStatus `json:"status"`
	OSType           string       `json:"os_type"`
	CPUCores         int          `json:"cpu_cores"`
	MemoryMB         int          `json:"memory_mb"`
	DiskGB           int          `json:"disk_gb"`
	Region           string       `json:"region"`

	AgentSecretHash *string `json:"-"`

	AgentSecretPrefix *string   `json:"agent_secret_prefix,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	Provider          *Provider `json:"provider,omitempty"`
}

type ServerRepository interface {
	Create(ctx context.Context, server *Server) error
	GetByID(ctx context.Context, id uuid.UUID) (*Server, error)
	ListByOrg(ctx context.Context, orgID uuid.UUID, page, limit int) ([]Server, int64, error)
	ListAllRunning(ctx context.Context) ([]Server, error)
	Update(ctx context.Context, server *Server) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status ServerStatus) error
	Delete(ctx context.Context, id uuid.UUID) error

	SetAgentSecret(ctx context.Context, serverID uuid.UUID, secretHash, secretPrefix string) error

	GetByIDWithSecret(ctx context.Context, id uuid.UUID) (*Server, error)

	UpdateSSHHardened(ctx context.Context, id uuid.UUID, hardened bool) error

	GetSSHHardened(ctx context.Context, id uuid.UUID) (bool, error)
}
