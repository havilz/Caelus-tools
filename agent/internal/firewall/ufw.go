package firewall

import (
	"context"
	"fmt"
	"strings"
)

type ufwEngine struct {
	runner   CommandRunner
	sshPorts []int
}

// NewUFWEngine creates an Uncomplicated Firewall (UFW) execution engine.
func NewUFWEngine(runner CommandRunner, sshPorts ...int) Engine {
	if len(sshPorts) == 0 {
		sshPorts = DetectSSHPorts()
	}
	return &ufwEngine{
		runner:   runner,
		sshPorts: sshPorts,
	}
}

// Type returns the firewall provider type.
func (e *ufwEngine) Type() FirewallType {
	return FirewallTypeUFW
}

// Initialize validates that UFW is installed and functioning on the host.
func (e *ufwEngine) Initialize(ctx context.Context) error {
	out, err := e.runner.Run(ctx, "ufw", "status")
	if err != nil {
		return fmt.Errorf("failed to probe ufw status: %s (%w)", string(out), err)
	}
	return nil
}

// ApplyRule translates the rule into a UFW directive and applies it.
func (e *ufwEngine) ApplyRule(ctx context.Context, rule Rule) error {
	if err := ValidateAntiLockout(rule, e.sshPorts); err != nil {
		return err
	}

	args := e.buildArgs(rule)
	out, err := e.runner.Run(ctx, "ufw", args...)
	if err != nil {
		return fmt.Errorf("failed to apply ufw rule: %s (%w)", string(out), err)
	}

	return nil
}

// RemoveRule removes the corresponding rule directive from UFW.
func (e *ufwEngine) RemoveRule(ctx context.Context, rule Rule) error {
	args := append([]string{"delete"}, e.buildArgs(rule)...)
	out, err := e.runner.Run(ctx, "ufw", args...)
	if err != nil {
		return fmt.Errorf("failed to delete ufw rule: %s (%w)", string(out), err)
	}

	return nil
}

// FlushRules disables active rules on UFW.
func (e *ufwEngine) FlushRules(ctx context.Context) error {
	out, err := e.runner.Run(ctx, "ufw", "--force", "reset")
	if err != nil {
		return fmt.Errorf("failed to reset ufw rules: %s (%w)", string(out), err)
	}
	return nil
}

func (e *ufwEngine) buildArgs(rule Rule) []string {
	action := strings.ToLower(string(rule.Action))
	args := []string{action}

	if rule.Direction == DirectionOutbound {
		args = append(args, "out")
	}

	proto := strings.ToLower(string(rule.Protocol))
	if proto != "" && proto != string(ProtocolAll) {
		args = append(args, "proto", proto)
	}

	src := strings.TrimSpace(rule.Source)
	if src != "" && src != "0.0.0.0/0" && !strings.EqualFold(src, "any") {
		args = append(args, "from", src)
	}

	port := strings.TrimSpace(rule.PortRange)
	if port != "" && !strings.EqualFold(port, "all") {
		formattedPort := strings.ReplaceAll(port, "-", ":")
		args = append(args, "to", "any", "port", formattedPort)
	}

	return args
}
