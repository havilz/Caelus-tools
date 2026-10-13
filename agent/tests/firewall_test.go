package tests

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/havilz/caelus-cloud/agent/internal/firewall"
)

type mockRunner struct {
	mu           sync.Mutex
	commandsRun  [][]string
	lookPathFunc func(file string) (string, error)
	runFunc      func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func (m *mockRunner) LookPath(file string) (string, error) {
	if m.lookPathFunc != nil {
		return m.lookPathFunc(file)
	}
	return "/usr/sbin/" + file, nil
}

func (m *mockRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	m.mu.Lock()
	fullCmd := append([]string{name}, args...)
	m.commandsRun = append(m.commandsRun, fullCmd)
	m.mu.Unlock()

	if m.runFunc != nil {
		return m.runFunc(ctx, name, args...)
	}
	return []byte(""), nil
}

func (m *mockRunner) getCommands() [][]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := make([][]string, len(m.commandsRun))
	copy(copied, m.commandsRun)
	return copied
}

func (m *mockRunner) hasCommandWith(parts ...string) bool {
	cmds := m.getCommands()
	for _, cmd := range cmds {
		cmdStr := strings.Join(cmd, " ")
		match := true
		for _, part := range parts {
			if !strings.Contains(cmdStr, part) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func TestDetectFirewallType_UFWActive(t *testing.T) {
	runner := &mockRunner{
		lookPathFunc: func(file string) (string, error) {
			if file == "ufw" {
				return "/usr/sbin/ufw", nil
			}
			return "", errors.New("not found")
		},
		runFunc: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "ufw" && len(args) > 0 && args[0] == "status" {
				return []byte("Status: active\nTo                         Action      From\n"), nil
			}
			return nil, nil
		},
	}

	fwType := firewall.DetectFirewallType(runner)
	if fwType != firewall.FirewallTypeUFW {
		t.Errorf("expected FirewallTypeUFW, got %s", fwType)
	}
}

func TestDetectFirewallType_UFWInactive_IPTablesFallback(t *testing.T) {
	runner := &mockRunner{
		lookPathFunc: func(file string) (string, error) {
			if file == "ufw" {
				return "/usr/sbin/ufw", nil
			}
			if file == "iptables" {
				return "/sbin/iptables", nil
			}
			return "", errors.New("not found")
		},
		runFunc: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "ufw" && len(args) > 0 && args[0] == "status" {
				return []byte("Status: inactive\n"), nil
			}
			return nil, nil
		},
	}

	fwType := firewall.DetectFirewallType(runner)
	if fwType != firewall.FirewallTypeIPTables {
		t.Errorf("expected FirewallTypeIPTables, got %s", fwType)
	}
}

func TestDetectFirewallType_None(t *testing.T) {
	runner := &mockRunner{
		lookPathFunc: func(_ string) (string, error) {
			return "", errors.New("binary not found")
		},
	}

	fwType := firewall.DetectFirewallType(runner)
	if fwType != firewall.FirewallTypeNone {
		t.Errorf("expected FirewallTypeNone, got %s", fwType)
	}
}

func TestIPTablesEngine_Initialize(t *testing.T) {
	runner := &mockRunner{
		runFunc: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "-C" {
				return nil, errors.New("rule does not exist")
			}
			if len(args) > 1 && args[0] == "-L" && args[1] == "CAELUS-FIREWALL" {
				return nil, errors.New("chain does not exist")
			}
			return []byte(""), nil
		},
	}

	engine := firewall.NewIPTablesEngine(runner, 22)
	ctx := context.Background()

	if err := engine.Initialize(ctx); err != nil {
		t.Fatalf("expected successful initialization, got: %v", err)
	}

	if !runner.hasCommandWith("iptables", "-N", "CAELUS-FIREWALL") {
		t.Error("expected chain creation command iptables -N CAELUS-FIREWALL")
	}

	if !runner.hasCommandWith("iptables", "-I", "INPUT", "1", "-j", "CAELUS-FIREWALL") {
		t.Error("expected jump hook iptables -I INPUT 1 -j CAELUS-FIREWALL")
	}

	if !runner.hasCommandWith("ESTABLISHED,RELATED", "ACCEPT") {
		t.Error("expected conntrack preservation rule")
	}

	if !runner.hasCommandWith("-i", "lo", "ACCEPT") {
		t.Error("expected loopback allow rule")
	}
}

func TestIPTablesEngine_ApplyRule_Allow(t *testing.T) {
	runner := &mockRunner{
		runFunc: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "-C" {
				return nil, errors.New("rule does not exist")
			}
			return []byte(""), nil
		},
	}

	engine := firewall.NewIPTablesEngine(runner, 22)
	ctx := context.Background()

	rule := firewall.Rule{
		Name:      "Allow-Web",
		Direction: firewall.DirectionInbound,
		Protocol:  firewall.ProtocolTCP,
		PortRange: "80",
		Source:    "0.0.0.0/0",
		Action:    firewall.ActionAllow,
	}

	if err := engine.ApplyRule(ctx, rule); err != nil {
		t.Fatalf("failed to apply rule: %v", err)
	}

	if !runner.hasCommandWith("iptables", "-A", "CAELUS-FIREWALL", "-p", "tcp", "--dport", "80", "-j", "ACCEPT") {
		t.Errorf("expected append command for port 80 allow, got commands: %v", runner.getCommands())
	}
}

func TestIPTablesEngine_ApplyRule_Deny(t *testing.T) {
	runner := &mockRunner{
		runFunc: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "-C" {
				return nil, errors.New("rule does not exist")
			}
			return []byte(""), nil
		},
	}

	engine := firewall.NewIPTablesEngine(runner, 22)
	ctx := context.Background()

	rule := firewall.Rule{
		Name:      "Block-MySQL",
		Direction: firewall.DirectionInbound,
		Protocol:  firewall.ProtocolTCP,
		PortRange: "3306",
		Source:    "10.0.0.0/8",
		Action:    firewall.ActionDeny,
	}

	if err := engine.ApplyRule(ctx, rule); err != nil {
		t.Fatalf("failed to apply deny rule: %v", err)
	}

	if !runner.hasCommandWith("iptables", "-A", "CAELUS-FIREWALL", "-p", "tcp", "-s", "10.0.0.0/8", "--dport", "3306", "-j", "DROP") {
		t.Errorf("expected append command for port 3306 drop, got commands: %v", runner.getCommands())
	}
}

func TestIPTablesEngine_ApplyRule_PortRange(t *testing.T) {
	runner := &mockRunner{
		runFunc: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "-C" {
				return nil, errors.New("rule does not exist")
			}
			return []byte(""), nil
		},
	}

	engine := firewall.NewIPTablesEngine(runner, 22)
	ctx := context.Background()

	rule := firewall.Rule{
		Name:      "Allow-NodePorts",
		Direction: firewall.DirectionInbound,
		Protocol:  firewall.ProtocolTCP,
		PortRange: "30000-32767",
		Source:    "192.168.1.0/24",
		Action:    firewall.ActionAllow,
	}

	if err := engine.ApplyRule(ctx, rule); err != nil {
		t.Fatalf("failed to apply port range rule: %v", err)
	}

	if !runner.hasCommandWith("iptables", "-A", "CAELUS-FIREWALL", "-p", "tcp", "-s", "192.168.1.0/24", "--dport", "30000:32767", "-j", "ACCEPT") {
		t.Errorf("expected formatted range 30000:32767, got commands: %v", runner.getCommands())
	}
}

func TestIPTablesEngine_ApplyRule_Idempotent(t *testing.T) {
	runner := &mockRunner{
		runFunc: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "-C" {
				return []byte(""), nil
			}
			return []byte(""), nil
		},
	}

	engine := firewall.NewIPTablesEngine(runner, 22)
	ctx := context.Background()

	rule := firewall.Rule{
		Name:      "Existing-Rule",
		Direction: firewall.DirectionInbound,
		Protocol:  firewall.ProtocolTCP,
		PortRange: "443",
		Source:    "0.0.0.0/0",
		Action:    firewall.ActionAllow,
	}

	if err := engine.ApplyRule(ctx, rule); err != nil {
		t.Fatalf("expected nil error on idempotent apply, got: %v", err)
	}

	if runner.hasCommandWith("iptables", "-A") {
		t.Error("expected no -A command when rule already exists (-C succeeded)")
	}
}

func TestIPTablesEngine_RemoveRule(t *testing.T) {
	runner := &mockRunner{
		runFunc: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "-C" {
				return []byte(""), nil
			}
			return []byte(""), nil
		},
	}

	engine := firewall.NewIPTablesEngine(runner, 22)
	ctx := context.Background()

	rule := firewall.Rule{
		Name:      "Delete-HTTP",
		Direction: firewall.DirectionInbound,
		Protocol:  firewall.ProtocolTCP,
		PortRange: "80",
		Source:    "0.0.0.0/0",
		Action:    firewall.ActionAllow,
	}

	if err := engine.RemoveRule(ctx, rule); err != nil {
		t.Fatalf("expected clean delete, got: %v", err)
	}

	if !runner.hasCommandWith("iptables", "-D", "CAELUS-FIREWALL", "-p", "tcp", "--dport", "80", "-j", "ACCEPT") {
		t.Errorf("expected delete command -D, got commands: %v", runner.getCommands())
	}
}

func TestIPTablesEngine_FlushRules(t *testing.T) {
	runner := &mockRunner{}
	engine := firewall.NewIPTablesEngine(runner, 22)
	ctx := context.Background()

	if err := engine.FlushRules(ctx); err != nil {
		t.Fatalf("failed to flush rules: %v", err)
	}

	if !runner.hasCommandWith("iptables", "-F", "CAELUS-FIREWALL") {
		t.Error("expected flush command iptables -F CAELUS-FIREWALL")
	}
}

func TestUFWEngine_ApplyAndRemove(t *testing.T) {
	runner := &mockRunner{}
	engine := firewall.NewUFWEngine(runner, 22)
	ctx := context.Background()

	rule := firewall.Rule{
		Name:      "Allow-HTTPS",
		Direction: firewall.DirectionInbound,
		Protocol:  firewall.ProtocolTCP,
		PortRange: "443",
		Source:    "192.168.1.0/24",
		Action:    firewall.ActionAllow,
	}

	if err := engine.ApplyRule(ctx, rule); err != nil {
		t.Fatalf("failed to apply ufw rule: %v", err)
	}

	if !runner.hasCommandWith("ufw", "allow", "proto", "tcp", "from", "192.168.1.0/24", "to", "any", "port", "443") {
		t.Errorf("expected ufw allow command, got commands: %v", runner.getCommands())
	}

	if err := engine.RemoveRule(ctx, rule); err != nil {
		t.Fatalf("failed to remove ufw rule: %v", err)
	}

	if !runner.hasCommandWith("ufw", "delete", "allow", "proto", "tcp", "from", "192.168.1.0/24", "to", "any", "port", "443") {
		t.Errorf("expected ufw delete command, got commands: %v", runner.getCommands())
	}
}

func TestAntiLockout_Protection(t *testing.T) {
	runner := &mockRunner{}
	engine := firewall.NewIPTablesEngine(runner, 22, 2222)
	ctx := context.Background()

	lockoutCases := []struct {
		desc string
		rule firewall.Rule
	}{
		{
			desc: "Direct deny port 22",
			rule: firewall.Rule{
				Direction: firewall.DirectionInbound,
				Protocol:  firewall.ProtocolTCP,
				PortRange: "22",
				Source:    "0.0.0.0/0",
				Action:    firewall.ActionDeny,
			},
		},
		{
			desc: "Direct deny custom SSH port 2222",
			rule: firewall.Rule{
				Direction: firewall.DirectionInbound,
				Protocol:  firewall.ProtocolTCP,
				PortRange: "2222",
				Source:    "",
				Action:    firewall.ActionDeny,
			},
		},
		{
			desc: "Deny port range containing 22 (20-25)",
			rule: firewall.Rule{
				Direction: firewall.DirectionInbound,
				Protocol:  firewall.ProtocolTCP,
				PortRange: "20-25",
				Source:    "any",
				Action:    firewall.ActionDeny,
			},
		},
		{
			desc: "Deny all ports (1-65535)",
			rule: firewall.Rule{
				Direction: firewall.DirectionInbound,
				Protocol:  firewall.ProtocolTCP,
				PortRange: "1-65535",
				Source:    "0.0.0.0/0",
				Action:    firewall.ActionDeny,
			},
		},
		{
			desc: "Deny wildcard all ports",
			rule: firewall.Rule{
				Direction: firewall.DirectionInbound,
				Protocol:  firewall.ProtocolAll,
				PortRange: "all",
				Source:    "0.0.0.0/0",
				Action:    firewall.ActionDeny,
			},
		},
	}

	for _, tc := range lockoutCases {
		t.Run(tc.desc, func(t *testing.T) {
			err := engine.ApplyRule(ctx, tc.rule)
			if !errors.Is(err, firewall.ErrAntiLockoutProtected) {
				t.Errorf("expected ErrAntiLockoutProtected, got: %v", err)
			}
		})
	}

	allowedCases := []struct {
		desc string
		rule firewall.Rule
	}{
		{
			desc: "Allow port 22 is permitted",
			rule: firewall.Rule{
				Direction: firewall.DirectionInbound,
				Protocol:  firewall.ProtocolTCP,
				PortRange: "22",
				Source:    "0.0.0.0/0",
				Action:    firewall.ActionAllow,
			},
		},
		{
			desc: "Deny port 80 (HTTP) is permitted",
			rule: firewall.Rule{
				Direction: firewall.DirectionInbound,
				Protocol:  firewall.ProtocolTCP,
				PortRange: "80",
				Source:    "0.0.0.0/0",
				Action:    firewall.ActionDeny,
			},
		},
		{
			desc: "Deny port 22 from specific IP (not universal 0.0.0.0/0) is permitted",
			rule: firewall.Rule{
				Direction: firewall.DirectionInbound,
				Protocol:  firewall.ProtocolTCP,
				PortRange: "22",
				Source:    "192.168.1.50/32",
				Action:    firewall.ActionDeny,
			},
		},
		{
			desc: "Deny outbound port 22 is permitted",
			rule: firewall.Rule{
				Direction: firewall.DirectionOutbound,
				Protocol:  firewall.ProtocolTCP,
				PortRange: "22",
				Source:    "0.0.0.0/0",
				Action:    firewall.ActionDeny,
			},
		},
	}

	for _, tc := range allowedCases {
		t.Run(tc.desc, func(t *testing.T) {
			err := engine.ApplyRule(ctx, tc.rule)
			if errors.Is(err, firewall.ErrAntiLockoutProtected) {
				t.Errorf("expected rule to be permitted, but got ErrAntiLockoutProtected: %v", err)
			}
		})
	}
}
