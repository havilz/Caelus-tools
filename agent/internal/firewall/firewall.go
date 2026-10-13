package firewall

import (
	"context"
	"strings"
)

type noopEngine struct{}

func (n *noopEngine) Type() FirewallType {
	return FirewallTypeNone
}

func (n *noopEngine) Initialize(_ context.Context) error {
	return nil
}

func (n *noopEngine) ApplyRule(_ context.Context, _ Rule) error {
	return ErrUnsupportedFirewall
}

func (n *noopEngine) RemoveRule(_ context.Context, _ Rule) error {
	return ErrUnsupportedFirewall
}

func (n *noopEngine) FlushRules(_ context.Context) error {
	return nil
}

// DetectFirewallType inspects host binaries and daemon status to select the active firewall subsystem.
func DetectFirewallType(runner CommandRunner) FirewallType {
	if _, err := runner.LookPath("ufw"); err == nil {
		out, runErr := runner.Run(context.Background(), "ufw", "status")
		if runErr == nil && strings.Contains(string(out), "Status: active") {
			return FirewallTypeUFW
		}
	}

	if _, err := runner.LookPath("iptables"); err == nil {
		return FirewallTypeIPTables
	}

	return FirewallTypeNone
}

// NewEngine creates a dynamic firewall engine based on host auto-detection.
func NewEngine(customRunner ...CommandRunner) Engine {
	var runner CommandRunner
	if len(customRunner) > 0 && customRunner[0] != nil {
		runner = customRunner[0]
	} else {
		runner = NewOSCommandRunner()
	}

	detected := DetectFirewallType(runner)
	switch detected {
	case FirewallTypeUFW:
		return NewUFWEngine(runner)
	case FirewallTypeIPTables:
		return NewIPTablesEngine(runner)
	default:
		return &noopEngine{}
	}
}
