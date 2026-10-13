package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type NetworkType string

const (
	NetworkTypeVPC     NetworkType = "vpc"
	NetworkTypeBridge  NetworkType = "bridge"
	NetworkTypeOverlay NetworkType = "overlay"
)

type NetworkStatus string

const (
	NetworkStatusActive       NetworkStatus = "active"
	NetworkStatusProvisioning NetworkStatus = "provisioning"
	NetworkStatusIdle         NetworkStatus = "idle"
	NetworkStatusError        NetworkStatus = "error"
)

type Network struct {
	ID              uuid.UUID     `json:"id"`
	OrganizationID  uuid.UUID     `json:"organization_id"`
	Name            string        `json:"name"`
	Type            NetworkType   `json:"type"`
	CIDR            string        `json:"cidr"`
	Gateway         string        `json:"gateway"`
	Region          string        `json:"region"`
	Driver          string        `json:"driver"`
	Status          NetworkStatus `json:"status"`
	AttachedServers int           `json:"attached_servers"`
	CreatedAt       time.Time     `json:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at"`
}

type CreateNetworkRequest struct {
	Name    string      `json:"name" validate:"required,min=3,max=50"`
	Type    NetworkType `json:"type" validate:"required,oneof=vpc bridge overlay"`
	CIDR    string      `json:"cidr" validate:"required,cidrv4"`
	Gateway string      `json:"gateway"`
	Region  string      `json:"region" validate:"required"`
	Driver  string      `json:"driver"`
}

type FirewallRule struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	NetworkID      *uuid.UUID `json:"network_id,omitempty"`
	ServerID       *uuid.UUID `json:"server_id,omitempty"`
	Name           string     `json:"name"`
	Direction      string     `json:"direction"`
	Protocol       string     `json:"protocol"`
	PortRange      string     `json:"port_range"`
	Source         string     `json:"source"`
	Action         string     `json:"action"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type CreateFirewallRuleRequest struct {
	NetworkID *uuid.UUID `json:"network_id,omitempty"`
	ServerID  *uuid.UUID `json:"server_id,omitempty"`
	Name      string     `json:"name" validate:"required,min=2,max=100"`
	Direction string     `json:"direction" validate:"required,oneof=inbound outbound"`
	Protocol  string     `json:"protocol" validate:"required,oneof=tcp udp icmp all"`
	PortRange string     `json:"port_range" validate:"required"`
	Source    string     `json:"source" validate:"required"`
	Action    string     `json:"action" validate:"required,oneof=allow deny"`
}

type NetworkRepository interface {
	CreateNetwork(ctx context.Context, net *Network) error
	GetNetworkByID(ctx context.Context, id uuid.UUID) (*Network, error)
	ListNetworksByOrg(ctx context.Context, orgID uuid.UUID) ([]Network, error)
	DeleteNetwork(ctx context.Context, id uuid.UUID) error

	CreateFirewallRule(ctx context.Context, rule *FirewallRule) error
	GetFirewallRuleByID(ctx context.Context, id uuid.UUID) (*FirewallRule, error)
	ListFirewallRulesByOrg(ctx context.Context, orgID uuid.UUID) ([]FirewallRule, error)
	DeleteFirewallRule(ctx context.Context, id uuid.UUID) error
}
