package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/havilz/caelus-cloud/backend/internal/domain"
	"github.com/havilz/caelus-cloud/backend/internal/usecase/actionqueue"
)

type MonitoringUsecase interface {
	IngestTelemetry(ctx context.Context, payload *domain.TelemetryReportPayload) error
	GetPendingActions(serverID uuid.UUID) []domain.AgentAction
	GetServerLiveMetrics(ctx context.Context, serverID uuid.UUID) (*domain.ServerMetric, error)
	GetServerMetricHistory(ctx context.Context, serverID uuid.UUID, duration time.Duration) ([]domain.ServerMetric, error)
	ListAlerts(ctx context.Context, orgID uuid.UUID, status *domain.AlertStatus, page, limit int) ([]domain.Alert, int64, error)
	AcknowledgeAlert(ctx context.Context, alertID, userID uuid.UUID) error
	ResolveAlert(ctx context.Context, alertID, userID uuid.UUID) error
	CreateAlertRule(ctx context.Context, rule *domain.AlertRule) error
	ListAlertRules(ctx context.Context, orgID uuid.UUID) ([]domain.AlertRule, error)
	DeleteAlertRule(ctx context.Context, ruleID uuid.UUID) error
	SetDiscoveryRepos(deploymentRepo domain.DeploymentRepository, networkRepo domain.NetworkRepository, volumeRepo domain.VolumeRepository)
}

type monitoringUsecase struct {
	metricRepo     domain.MetricRepository
	alertRepo      domain.AlertRepository
	serverRepo     domain.ServerRepository
	deploymentRepo domain.DeploymentRepository
	networkRepo    domain.NetworkRepository
	volumeRepo     domain.VolumeRepository
	evaluator      *AlertEvaluator
	broadcaster    domain.TelemetryBroadcaster
	promAdapter    domain.MetricsQueryAdapter
	lokiAdapter    domain.LogQueryAdapter
	actionQueue    actionqueue.ActionQueue
}

func NewMonitoringUsecase(
	metricRepo domain.MetricRepository,
	alertRepo domain.AlertRepository,
	serverRepo domain.ServerRepository,
	evaluator *AlertEvaluator,
	broadcaster domain.TelemetryBroadcaster,
	promAdapter domain.MetricsQueryAdapter,
	lokiAdapter domain.LogQueryAdapter,
	actionQueue actionqueue.ActionQueue,
) MonitoringUsecase {
	return &monitoringUsecase{
		metricRepo:  metricRepo,
		alertRepo:   alertRepo,
		serverRepo:  serverRepo,
		evaluator:   evaluator,
		broadcaster: broadcaster,
		promAdapter: promAdapter,
		lokiAdapter: lokiAdapter,
		actionQueue: actionQueue,
	}
}

func (u *monitoringUsecase) SetDiscoveryRepos(
	deploymentRepo domain.DeploymentRepository,
	networkRepo domain.NetworkRepository,
	volumeRepo domain.VolumeRepository,
) {
	u.deploymentRepo = deploymentRepo
	u.networkRepo = networkRepo
	u.volumeRepo = volumeRepo
}

func (u *monitoringUsecase) IngestTelemetry(ctx context.Context, payload *domain.TelemetryReportPayload) error {
	server, err := u.serverRepo.GetByID(ctx, payload.ServerID)
	if err != nil {
		return fmt.Errorf("server not found for telemetry ingestion: %w", err)
	}

	for i := range payload.Containers {
		for j := range payload.Containers[i].Logs {
			payload.Containers[i].Logs[j] = strings.ReplaceAll(payload.Containers[i].Logs[j], "\x00", "")
			payload.Containers[i].Logs[j] = strings.ReplaceAll(payload.Containers[i].Logs[j], "\\u0000", "")
		}
	}

	containersJSONBytes, _ := json.Marshal(payload.Containers)

	containersJSONStr := string(containersJSONBytes)
	containersJSONStr = strings.ReplaceAll(containersJSONStr, "\\u0000", "")
	containersJSONStr = strings.ReplaceAll(containersJSONStr, "\x00", "")

	metric := &domain.ServerMetric{
		ServerID:           payload.ServerID,
		CPUUsagePct:        payload.Host.CPUUsagePct,
		MemoryUsedMB:       int64(payload.Host.MemoryUsedMB),
		MemoryTotalMB:      int64(payload.Host.MemoryTotalMB),
		MemoryUsagePct:     payload.Host.MemoryUsagePct,
		DiskUsedGB:         payload.Host.DiskUsedGB,
		DiskTotalGB:        payload.Host.DiskTotalGB,
		DiskUsagePct:       payload.Host.DiskUsagePct,
		NetworkInKB:        int64(payload.Host.NetworkInKB),
		NetworkOutKB:       int64(payload.Host.NetworkOutKB),
		NetworkInRateKBps:  payload.Host.NetworkInRateKBps,
		NetworkOutRateKBps: payload.Host.NetworkOutRateKBps,
		UptimeSeconds:      int64(payload.Host.UptimeSeconds),
		ContainersCount:    len(payload.Containers),
		DockerAvailable:    payload.DockerAvailable,
		ContainersJSON:     containersJSONStr,
		RecordedAt:         payload.Timestamp,
	}

	if err := u.metricRepo.Create(ctx, metric); err != nil {
		return fmt.Errorf("failed to persist server metric: %w", err)
	}

	needsUpdate := false
	if server.Status != domain.ServerStatusRunning {
		server.Status = domain.ServerStatusRunning
		needsUpdate = true
	}
	if payload.Host.CPUCores > 0 && server.CPUCores != payload.Host.CPUCores {
		server.CPUCores = payload.Host.CPUCores
		needsUpdate = true
	}
	if payload.Host.MemoryTotalMB > 0 && server.MemoryMB != int(payload.Host.MemoryTotalMB) {
		server.MemoryMB = int(payload.Host.MemoryTotalMB)
		needsUpdate = true
	}
	if payload.Host.DiskTotalGB > 0 && server.DiskGB != int(payload.Host.DiskTotalGB) {
		server.DiskGB = int(payload.Host.DiskTotalGB)
		needsUpdate = true
	}
	if payload.Host.Platform != "" && server.OSType != payload.Host.Platform {
		server.OSType = payload.Host.Platform
		needsUpdate = true
	}
	if payload.Host.Hostname != "" && (server.Hostname == nil || *server.Hostname != payload.Host.Hostname) {
		h := payload.Host.Hostname
		server.Hostname = &h
		needsUpdate = true
	}
	if needsUpdate {
		_ = u.serverRepo.Update(ctx, server)
	}

	if payload.Host.SSHHardened {
		_ = u.serverRepo.UpdateSSHHardened(ctx, payload.ServerID, true)
	}

	u.syncDiscoveredInfrastructure(ctx, server, payload)

	if u.evaluator != nil {
		_ = u.evaluator.EvaluateMetrics(ctx, server, metric)
	}

	if u.broadcaster != nil {
		u.broadcaster.BroadcastToServer(server.ID, "metrics.updated", metric)
		u.broadcaster.BroadcastToOrg(server.OrganizationID, "server.telemetry", map[string]any{
			"server_id":   server.ID,
			"cpu_pct":     metric.CPUUsagePct,
			"mem_pct":     metric.MemoryUsagePct,
			"disk_pct":    metric.DiskUsagePct,
			"recorded_at": metric.RecordedAt,
		})
	}

	return nil
}

func (u *monitoringUsecase) syncDiscoveredInfrastructure(ctx context.Context, server *domain.Server, payload *domain.TelemetryReportPayload) {

	if u.deploymentRepo != nil && len(payload.Containers) > 0 {
		existingDeps, _ := u.deploymentRepo.ListDeploymentsByServer(ctx, server.ID)
		depMap := make(map[string]*domain.Deployment)
		for i := range existingDeps {
			depMap[existingDeps[i].ContainerName] = &existingDeps[i]
		}

		discoveredNames := make(map[string]bool)
		for _, c := range payload.Containers {

			if strings.HasPrefix(c.Image, "sha256:") {
				continue
			}

			containerName := ""
			if len(c.Names) > 0 {
				containerName = strings.TrimPrefix(c.Names[0], "/")
			}
			if containerName == "" {
				containerName = c.ID
				if len(containerName) > 12 {
					containerName = containerName[:12]
				}
			}

			discoveredNames[containerName] = true

			status := domain.DeploymentStatusRunning
			switch c.State {
			case "exited", "stopped":
				status = domain.DeploymentStatusStopped
			case "restarting":
				status = domain.DeploymentStatusDeploying
			}

			var targetDepID uuid.UUID
			if existing, exists := depMap[containerName]; exists {
				targetDepID = existing.ID
				if existing.Status != status {
					_ = u.deploymentRepo.UpdateDeploymentStatus(ctx, existing.ID, status, "", nil)
				}
			} else {
				var ports []domain.PortBinding
				for _, p := range c.PortBindings {
					ports = append(ports, domain.PortBinding{
						HostPort:      p.HostPort,
						ContainerPort: p.ContainerPort,
						Protocol:      p.Protocol,
					})
				}

				var volumeBindings []domain.VolumeBinding
				for _, v := range c.VolumeMounts {
					volumeBindings = append(volumeBindings, domain.VolumeBinding{
						HostPath:      v.Source,
						ContainerPath: v.Destination,
						Mode:          v.Mode,
					})
				}

				networkName := ""
				if len(c.Networks) > 0 {
					networkName = c.Networks[0]
				}

				createdAt := time.Now()
				if c.Created > 0 {
					createdAt = time.Unix(c.Created, 0)
				}

				newDep := &domain.Deployment{
					ID:                   uuid.New(),
					OrganizationID:       server.OrganizationID,
					ServerID:             &server.ID,
					AppName:              containerName,
					ImageTag:             c.Image,
					ContainerName:        containerName,
					EnvironmentVariables: c.EnvironmentVariables,
					PortBindings:         ports,
					VolumeBindings:       volumeBindings,
					RestartPolicy:        c.RestartPolicy,
					NetworkName:          networkName,
					Status:               status,
					CreatedAt:            createdAt,
					UpdatedAt:            time.Now(),
				}
				_ = u.deploymentRepo.CreateDeployment(ctx, newDep)
				targetDepID = newDep.ID
			}

			if targetDepID != uuid.Nil && len(c.Logs) > 0 {
				existingLogs, _ := u.deploymentRepo.GetLogsByDeployment(ctx, targetDepID, 30)
				existingMsgs := make(map[string]bool)
				for _, el := range existingLogs {
					existingMsgs[el.Message] = true
				}
				for _, logLine := range c.Logs {
					cleanLog := strings.ReplaceAll(strings.ReplaceAll(logLine, "\x00", ""), "\\u0000", "")
					if cleanLog != "" && !existingMsgs[cleanLog] {
						_ = u.deploymentRepo.AppendLog(ctx, &domain.DeploymentLog{
							DeploymentID: targetDepID,
							Timestamp:    time.Now().UTC(),
							Stream:       "stdout",
							Message:      cleanLog,
						})
					}
				}
			}
		}

		for name, dep := range depMap {
			if !discoveredNames[name] {
				_ = u.deploymentRepo.DeleteDeployment(ctx, dep.ID)
			}
		}
	}

	if u.networkRepo != nil && len(payload.Networks) > 0 {
		existingNets, _ := u.networkRepo.ListNetworksByOrg(ctx, server.OrganizationID)
		netMap := make(map[string]bool)
		for _, n := range existingNets {
			netMap[n.Name] = true
		}

		for _, n := range payload.Networks {
			if n.Name == "host" || n.Name == "none" {
				continue
			}
			if !netMap[n.Name] {
				netType := domain.NetworkTypeBridge
				if n.Driver == "overlay" {
					netType = domain.NetworkTypeOverlay
				}
				newNet := &domain.Network{
					ID:              uuid.New(),
					OrganizationID:  server.OrganizationID,
					Name:            n.Name,
					Type:            netType,
					CIDR:            n.SubnetCIDR,
					Gateway:         n.Gateway,
					Driver:          n.Driver,
					Region:          "local",
					Status:          domain.NetworkStatusActive,
					AttachedServers: 1,
					CreatedAt:       time.Now(),
					UpdatedAt:       time.Now(),
				}
				_ = u.networkRepo.CreateNetwork(ctx, newNet)
				netMap[n.Name] = true
			}
		}
	}

	if u.volumeRepo != nil && len(payload.Volumes) > 0 {
		existingVols, _ := u.volumeRepo.ListVolumesByOrg(ctx, server.OrganizationID)
		volMap := make(map[string]bool)
		for _, v := range existingVols {
			volMap[v.Name] = true
			volMap["caelus-"+v.Name] = true
			volMap[strings.TrimPrefix(v.Name, "caelus-")] = true
		}

		for _, v := range payload.Volumes {

			if u.actionQueue != nil && (u.actionQueue.HasPendingAction(server.ID, "DELETE_VOLUME", v.Name) || u.actionQueue.HasPendingAction(server.ID, "DELETE_VOLUME", strings.TrimPrefix(v.Name, "caelus-"))) {
				continue
			}

			normalized := strings.TrimPrefix(v.Name, "caelus-")
			if !volMap[v.Name] && !volMap[normalized] {
				sizeGB := int(v.SizeGB)
				if sizeGB <= 0 {
					sizeGB = 1
				}

				volStatus := domain.VolumeStatusAvailable
				for _, c := range payload.Containers {
					for _, m := range c.VolumeMounts {
						if m.Name == v.Name || m.Name == normalized || m.Source == v.Name || m.Source == normalized {
							volStatus = domain.VolumeStatusInUse
							break
						}
					}
					if volStatus == domain.VolumeStatusInUse {
						break
					}
				}

				newVol := &domain.Volume{
					ID:             uuid.New(),
					OrganizationID: server.OrganizationID,
					ServerID:       &server.ID,
					Name:           v.Name,
					SizeGB:         sizeGB,
					Type:           domain.VolumeTypeDockerVolume,
					FSType:         domain.FileSystemExt4,
					MountPath:      v.Mountpoint,
					Status:         volStatus,
					CreatedAt:      time.Now(),
					UpdatedAt:      time.Now(),
				}
				_ = u.volumeRepo.CreateVolume(ctx, newVol)
				volMap[v.Name] = true
				volMap[normalized] = true
			}
		}
	}
}

func (u *monitoringUsecase) GetPendingActions(serverID uuid.UUID) []domain.AgentAction {
	if u.actionQueue == nil {
		return nil
	}
	return u.actionQueue.PopAll(serverID)
}

func (u *monitoringUsecase) GetServerLiveMetrics(ctx context.Context, serverID uuid.UUID) (*domain.ServerMetric, error) {
	return u.metricRepo.GetLatestByServerID(ctx, serverID)
}

func (u *monitoringUsecase) GetServerMetricHistory(ctx context.Context, serverID uuid.UUID, duration time.Duration) ([]domain.ServerMetric, error) {
	to := time.Now().UTC()
	from := to.Add(-duration)
	return u.metricRepo.GetHistoryByServerID(ctx, serverID, from, to, 100)
}

func (u *monitoringUsecase) ListAlerts(ctx context.Context, orgID uuid.UUID, status *domain.AlertStatus, page, limit int) ([]domain.Alert, int64, error) {
	if limit <= 0 {
		limit = 20
	}
	if page <= 0 {
		page = 1
	}
	return u.alertRepo.ListAlertsByOrg(ctx, orgID, status, page, limit)
}

func (u *monitoringUsecase) AcknowledgeAlert(ctx context.Context, alertID, userID uuid.UUID) error {
	now := time.Now().UTC()
	return u.alertRepo.UpdateAlertStatus(ctx, alertID, domain.AlertStatusAcknowledged, &userID, &now)
}

func (u *monitoringUsecase) ResolveAlert(ctx context.Context, alertID, userID uuid.UUID) error {
	now := time.Now().UTC()
	return u.alertRepo.UpdateAlertStatus(ctx, alertID, domain.AlertStatusResolved, &userID, &now)
}

func (u *monitoringUsecase) CreateAlertRule(ctx context.Context, rule *domain.AlertRule) error {
	if rule.ID == uuid.Nil {
		rule.ID = uuid.New()
	}
	now := time.Now().UTC()
	rule.CreatedAt = now
	rule.UpdatedAt = now
	return u.alertRepo.CreateRule(ctx, rule)
}

func (u *monitoringUsecase) ListAlertRules(ctx context.Context, orgID uuid.UUID) ([]domain.AlertRule, error) {
	return u.alertRepo.ListRulesByOrg(ctx, orgID)
}

func (u *monitoringUsecase) DeleteAlertRule(ctx context.Context, ruleID uuid.UUID) error {
	return u.alertRepo.DeleteRule(ctx, ruleID)
}
