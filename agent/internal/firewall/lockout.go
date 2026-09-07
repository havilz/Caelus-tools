package firewall

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// DetectSSHPorts inspects system configuration files to discover configured SSH daemon ports, defaulting to port 22.
func DetectSSHPorts() []int {
	ports := []int{22}
	file, err := os.Open("/etc/ssh/sshd_config")
	if err != nil {
		return ports
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 && strings.EqualFold(parts[0], "Port") {
			if p, parseErr := strconv.Atoi(parts[1]); parseErr == nil && p > 0 && p <= 65535 {
				if p != 22 {
					ports = append(ports, p)
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return ports
	}
	return ports
}

// ValidateAntiLockout enforces safety checks against rules that would sever remote administrative SSH access.
func ValidateAntiLockout(rule Rule, sshPorts []int) error {
	if rule.Direction != DirectionInbound || rule.Action != ActionDeny {
		return nil
	}

	proto := strings.ToLower(string(rule.Protocol))
	if proto != "" && proto != string(ProtocolTCP) && proto != string(ProtocolAll) {
		return nil
	}

	src := strings.TrimSpace(rule.Source)
	isUniversalSource := src == "" || src == "0.0.0.0/0" || src == "any" || src == "::/0" || src == "0.0.0.0"
	if !isUniversalSource {
		return nil
	}

	if len(sshPorts) == 0 {
		sshPorts = []int{22}
	}

	portStr := strings.TrimSpace(rule.PortRange)
	if portStr == "" || strings.EqualFold(portStr, "all") || portStr == "*" || portStr == "1-65535" || portStr == "1:65535" {
		return ErrAntiLockoutProtected
	}

	for _, sshPort := range sshPorts {
		if strings.Contains(portStr, "-") || strings.Contains(portStr, ":") {
			sep := "-"
			if strings.Contains(portStr, ":") {
				sep = ":"
			}
			bounds := strings.Split(portStr, sep)
			if len(bounds) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
				if err1 == nil && err2 == nil && start <= sshPort && sshPort <= end {
					return ErrAntiLockoutProtected
				}
			}
		} else {
			p, err := strconv.Atoi(portStr)
			if err == nil && p == sshPort {
				return ErrAntiLockoutProtected
			}
		}
	}

	return nil
}
