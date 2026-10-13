package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/havilz/caelus-cloud/agent/internal/collector"
	"github.com/havilz/caelus-cloud/agent/internal/config"
	"github.com/havilz/caelus-cloud/agent/internal/docker"
	"github.com/havilz/caelus-cloud/agent/internal/firewall"
	"github.com/havilz/caelus-cloud/agent/internal/transport"
	"github.com/havilz/caelus-cloud/agent/pkg/logger"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		slog.Error("failed to load agent configuration", "error", err)
		os.Exit(1)
	}

	appLogger := logger.NewLogger(cfg.LogLevel)
	slog.SetDefault(appLogger)

	slog.Info("starting caelus-agent daemon",
		"server_id", cfg.ServerID,
		"api_endpoint", cfg.APIEndpoint,
		"interval_sec", cfg.CollectionIntervalSec,
		"docker_socket", cfg.DockerSocketPath,
		"tls_skip_verify", cfg.TLSSkipVerify,
	)

	if cfg.TLSSkipVerify {
		slog.Warn("SECURITY WARNING: TLS verification is disabled (TLSSkipVerify=true). HTTPS transport is vulnerable to Man-In-The-Middle (MITM) attacks!")
	}

	sysCollector := collector.NewCollector()
	dockerInspector := docker.NewInspector(cfg.DockerSocketPath)
	fwEngine := firewall.NewEngine()
	transportClient := transport.NewHTTPClient(cfg.APIEndpoint, cfg.ServerID, cfg.AgentSecret, cfg.TLSSkipVerify)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	if err := fwEngine.Initialize(ctx); err != nil {
		slog.Warn("failed to initialize host firewall engine", "type", fwEngine.Type(), "error", err)
	} else {
		slog.Info("initialized host firewall engine", "type", fwEngine.Type())
	}

	runCollectionCycle(ctx, sysCollector, dockerInspector, fwEngine, transportClient, cfg)

	ticker := time.NewTicker(time.Duration(cfg.CollectionIntervalSec) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("shutting down caelus-agent gracefully")
			return
		case <-ticker.C:
			runCollectionCycle(ctx, sysCollector, dockerInspector, fwEngine, transportClient, cfg)
		}
	}
}

func runCollectionCycle(
	ctx context.Context,
	sysCollector collector.Collector,
	dockerInspector docker.Inspector,
	fwEngine firewall.Engine,
	transportClient transport.Client,
	cfg *config.Config,
) {
	start := time.Now()

	hostMetrics, err := sysCollector.Collect(ctx)
	if err != nil {
		slog.Error("failed to collect host metrics", "error", err)
		return
	}

	dockerAvail := dockerInspector.IsAvailable(ctx)
	var containers []transport.ContainerMetrics
	var networks []transport.DiscoveredNetwork
	var volumes []transport.DiscoveredVolume

	if dockerAvail {
		containers, err = dockerInspector.InspectContainers(ctx)
		if err != nil {
			slog.Warn("failed to inspect docker containers", "error", err)
		}

		networks, err = dockerInspector.InspectNetworks(ctx)
		if err != nil {
			slog.Warn("failed to inspect docker networks", "error", err)
		}

		volumes, err = dockerInspector.InspectVolumes(ctx)
		if err != nil {
			slog.Warn("failed to inspect docker volumes", "error", err)
		}
	}

	payload := &transport.AgentReportPayload{
		ServerID:        cfg.ServerID,
		Timestamp:       time.Now().UTC(),
		Host:            *hostMetrics,
		Containers:      containers,
		Networks:        networks,
		Volumes:         volumes,
		DockerAvailable: dockerAvail,
	}

	sendCtx, sendCancel := context.WithTimeout(ctx, 15*time.Second)
	defer sendCancel()

	actions, err := transportClient.SendReport(sendCtx, payload)
	if err != nil {
		slog.Error("failed to send telemetry report to api", "error", err)
		return
	}

	if len(actions) > 0 {
		for _, act := range actions {
			slog.Info("received remote action from control plane", "action_id", act.ID, "type", act.Type, "target", act.Target)
			switch act.Type {
			case "CREATE_VOLUME":
				if err := dockerInspector.CreateVolume(ctx, act.Target); err != nil {
					slog.Error("failed to execute CREATE_VOLUME", "target", act.Target, "error", err)
				} else {
					slog.Info("successfully created volume on host", "target", act.Target)
				}
			case "DELETE_VOLUME":
				if err := dockerInspector.RemoveVolume(ctx, act.Target); err != nil {
					slog.Error("failed to execute DELETE_VOLUME", "target", act.Target, "error", err)
				} else {
					slog.Info("successfully removed volume from host", "target", act.Target)
				}
			case "DEPLOY_CONTAINER":
				var payload transport.ContainerDeployPayload
				if act.Payload != "" {
					if err := json.Unmarshal([]byte(act.Payload), &payload); err != nil {
						slog.Error("failed to unmarshal DEPLOY_CONTAINER payload", "error", err)
						continue
					}
				}
				if payload.Name == "" {
					payload.Name = act.Target
				}
				if err := dockerInspector.DeployContainer(ctx, payload); err != nil {
					slog.Error("failed to execute DEPLOY_CONTAINER", "target", act.Target, "error", err)
				} else {
					slog.Info("successfully deployed container on host", "target", act.Target, "image", payload.Image)
				}
			case "DELETE_CONTAINER":
				if err := dockerInspector.RemoveContainer(ctx, act.Target); err != nil {
					slog.Error("failed to execute DELETE_CONTAINER", "target", act.Target, "error", err)
				} else {
					slog.Info("successfully removed container from host", "target", act.Target)
				}
			case "START_CONTAINER":
				if err := dockerInspector.StartContainer(ctx, act.Target); err != nil {
					slog.Error("failed to execute START_CONTAINER", "target", act.Target, "error", err)
				} else {
					slog.Info("successfully started container on host", "target", act.Target)
				}
			case "STOP_CONTAINER":
				if err := dockerInspector.StopContainer(ctx, act.Target); err != nil {
					slog.Error("failed to execute STOP_CONTAINER", "target", act.Target, "error", err)
				} else {
					slog.Info("successfully stopped container on host", "target", act.Target)
				}
			case "RESTART_CONTAINER":
				if err := dockerInspector.RestartContainer(ctx, act.Target); err != nil {
					slog.Error("failed to execute RESTART_CONTAINER", "target", act.Target, "error", err)
				} else {
					slog.Info("successfully restarted container on host", "target", act.Target)
				}
			case "APPLY_FIREWALL_RULE":
				var rule firewall.Rule
				if act.Payload != "" {
					if err := json.Unmarshal([]byte(act.Payload), &rule); err != nil {
						slog.Error("failed to unmarshal APPLY_FIREWALL_RULE payload", "error", err)
						continue
					}
				}
				if rule.Name == "" {
					rule.Name = act.Target
				}
				if err := fwEngine.ApplyRule(ctx, rule); err != nil {
					slog.Error("failed to execute APPLY_FIREWALL_RULE", "target", act.Target, "error", err)
				} else {
					slog.Info("successfully applied firewall rule on host", "name", rule.Name, "port", rule.PortRange, "action", rule.Action)
				}
			case "REMOVE_FIREWALL_RULE":
				var rule firewall.Rule
				if act.Payload != "" {
					if err := json.Unmarshal([]byte(act.Payload), &rule); err != nil {
						slog.Error("failed to unmarshal REMOVE_FIREWALL_RULE payload", "error", err)
						continue
					}
				}
				if rule.Name == "" {
					rule.Name = act.Target
				}
				if err := fwEngine.RemoveRule(ctx, rule); err != nil {
					slog.Error("failed to execute REMOVE_FIREWALL_RULE", "target", act.Target, "error", err)
				} else {
					slog.Info("successfully removed firewall rule from host", "name", rule.Name, "port", rule.PortRange, "action", rule.Action)
				}
			case "HARDEN_SSH":
				hardenCmd := exec.CommandContext(ctx, "sh", "-c", "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && (systemctl reload ssh || systemctl reload sshd || service ssh reload || true)")
				if out, err := hardenCmd.CombinedOutput(); err != nil {
					slog.Error("failed to execute HARDEN_SSH", "error", err, "output", string(out))
				} else {
					slog.Info("successfully applied CIS SSH hardening on host")
				}
			}
		}
	}

	slog.Info("telemetry report dispatched successfully",
		"duration_ms", time.Since(start).Milliseconds(),
		"cpu_pct", hostMetrics.CPUUsagePct,
		"mem_pct", hostMetrics.MemoryUsagePct,
		"disk_pct", hostMetrics.DiskUsagePct,
		"containers_count", len(containers),
		"networks_count", len(networks),
		"volumes_count", len(volumes),
		"docker_active", dockerAvail,
	)
}
