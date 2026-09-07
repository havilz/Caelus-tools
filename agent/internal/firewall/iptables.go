package firewall

import (
	"context"
	"fmt"
	"strings"
)

const defaultIPTablesChain = "CAELUS-FIREWALL"

type iptablesEngine struct {
	runner   CommandRunner
	chain    string
	sshPorts []int
}

// NewIPTablesEngine creates an iptables firewall engine managing an isolated rule chain.
func NewIPTablesEngine(runner CommandRunner, sshPorts ...int) Engine {
	if len(sshPorts) == 0 {
		sshPorts = DetectSSHPorts()
	}
	return &iptablesEngine{
		runner:   runner,
		chain:    defaultIPTablesChain,
		sshPorts: sshPorts,
	}
}

// Type returns the firewall provider type.
func (e *iptablesEngine) Type() FirewallType {
	return FirewallTypeIPTables
}

// Initialize ensures the isolated Caelus chain exists and is hooked into the INPUT chain with safe defaults.
func (e *iptablesEngine) Initialize(ctx context.Context) error {
	_, err := e.runner.Run(ctx, "iptables", "-L", e.chain, "-n")
	if err != nil {
		if out, createErr := e.runner.Run(ctx, "iptables", "-N", e.chain); createErr != nil {
			return fmt.Errorf("failed to create iptables chain %s: %s (%w)", e.chain, string(out), createErr)
		}
	}

	_, checkJumpErr := e.runner.Run(ctx, "iptables", "-C", "INPUT", "-j", e.chain)
	if checkJumpErr != nil {
		if out, insertErr := e.runner.Run(ctx, "iptables", "-I", "INPUT", "1", "-j", e.chain); insertErr != nil {
			return fmt.Errorf("failed to link %s into INPUT chain: %s (%w)", e.chain, string(out), insertErr)
		}
	}

	_, checkEstErr := e.runner.Run(ctx, "iptables", "-C", e.chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	if checkEstErr != nil {
		_, _ = e.runner.Run(ctx, "iptables", "-I", e.chain, "1", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	}

	_, checkLoErr := e.runner.Run(ctx, "iptables", "-C", e.chain, "-i", "lo", "-j", "ACCEPT")
	if checkLoErr != nil {
		_, _ = e.runner.Run(ctx, "iptables", "-I", e.chain, "2", "-i", "lo", "-j", "ACCEPT")
	}

	_, checkDockerUser := e.runner.Run(ctx, "iptables", "-L", "DOCKER-USER", "-n")
	if checkDockerUser == nil {
		_, checkDockerJump := e.runner.Run(ctx, "iptables", "-C", "DOCKER-USER", "-j", e.chain)
		if checkDockerJump != nil {
			_, _ = e.runner.Run(ctx, "iptables", "-I", "DOCKER-USER", "1", "-j", e.chain)
		}
	}

	return nil
}

// ApplyRule evaluates safety constraints and inserts or updates a firewall rule within the isolated chain.
func (e *iptablesEngine) ApplyRule(ctx context.Context, rule Rule) error {
	if err := ValidateAntiLockout(rule, e.sshPorts); err != nil {
		return err
	}

	checkArgs := e.buildArgs(rule, "-C")
	if _, checkErr := e.runner.Run(ctx, "iptables", checkArgs...); checkErr == nil {
		return nil
	}

	appendArgs := e.buildArgs(rule, "-A")
	out, err := e.runner.Run(ctx, "iptables", appendArgs...)
	if err != nil {
		return fmt.Errorf("failed to apply iptables rule: %s (%w)", string(out), err)
	}

	return nil
}

// RemoveRule deletes a matching firewall rule from the isolated chain if it exists.
func (e *iptablesEngine) RemoveRule(ctx context.Context, rule Rule) error {
	checkArgs := e.buildArgs(rule, "-C")
	if _, checkErr := e.runner.Run(ctx, "iptables", checkArgs...); checkErr != nil {
		return nil
	}

	deleteArgs := e.buildArgs(rule, "-D")
	out, err := e.runner.Run(ctx, "iptables", deleteArgs...)
	if err != nil {
		return fmt.Errorf("failed to delete iptables rule: %s (%w)", string(out), err)
	}

	return nil
}

// FlushRules purges all rules inside the isolated Caelus chain and restores basic safety rules.
func (e *iptablesEngine) FlushRules(ctx context.Context) error {
	if out, err := e.runner.Run(ctx, "iptables", "-F", e.chain); err != nil {
		return fmt.Errorf("failed to flush iptables chain %s: %s (%w)", e.chain, string(out), err)
	}

	_, _ = e.runner.Run(ctx, "iptables", "-A", e.chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	_, _ = e.runner.Run(ctx, "iptables", "-A", e.chain, "-i", "lo", "-j", "ACCEPT")
	return nil
}

func (e *iptablesEngine) buildArgs(rule Rule, opFlag string) []string {
	args := []string{opFlag, e.chain}

	proto := strings.ToLower(string(rule.Protocol))
	if proto != "" && proto != string(ProtocolAll) {
		args = append(args, "-p", proto)
	}

	src := strings.TrimSpace(rule.Source)
	if src != "" && src != "0.0.0.0/0" && !strings.EqualFold(src, "any") {
		args = append(args, "-s", src)
	}

	port := strings.TrimSpace(rule.PortRange)
	if (proto == string(ProtocolTCP) || proto == string(ProtocolUDP)) && port != "" && !strings.EqualFold(port, "all") {
		formattedPort := strings.ReplaceAll(port, "-", ":")
		args = append(args, "--dport", formattedPort)
	}

	if rule.Action == ActionAllow {
		args = append(args, "-j", "ACCEPT")
	} else {
		args = append(args, "-j", "DROP")
	}

	return args
}
