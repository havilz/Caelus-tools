package firewall

import (
	"context"
	"errors"
	"os/exec"
)

type Direction string

const (
	DirectionInbound  Direction = "inbound"
	DirectionOutbound Direction = "outbound"
)

type Protocol string

const (
	ProtocolTCP  Protocol = "tcp"
	ProtocolUDP  Protocol = "udp"
	ProtocolICMP Protocol = "icmp"
	ProtocolAll  Protocol = "all"
)

type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

type FirewallType string

const (
	FirewallTypeUFW      FirewallType = "ufw"
	FirewallTypeIPTables FirewallType = "iptables"
	FirewallTypeNone     FirewallType = "none"
)

var (
	ErrAntiLockoutProtected = errors.New("operation rejected: blocking inbound SSH traffic from all sources would cause host lockout")
	ErrUnsupportedFirewall  = errors.New("no supported firewall utility (ufw or iptables) found on host")
	ErrInvalidRule          = errors.New("invalid firewall rule parameters")
)

type Rule struct {
	ID        string    `json:"id,omitempty"`
	Name      string    `json:"name,omitempty"`
	Direction Direction `json:"direction"`
	Protocol  Protocol  `json:"protocol"`
	PortRange string    `json:"port_range"`
	Source    string    `json:"source"`
	Action    Action    `json:"action"`
}

type CommandRunner interface {
	LookPath(file string) (string, error)
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type osCommandRunner struct{}

func NewOSCommandRunner() CommandRunner {
	return &osCommandRunner{}
}

func (r *osCommandRunner) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

func (r *osCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

type Engine interface {
	Type() FirewallType
	Initialize(ctx context.Context) error
	ApplyRule(ctx context.Context, rule Rule) error
	RemoveRule(ctx context.Context, rule Rule) error
	FlushRules(ctx context.Context) error
}
