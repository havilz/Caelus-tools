package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type ServerMetric struct {
	ID                 int64     `json:"id"`
	ServerID           uuid.UUID `json:"server_id"`
	CPUUsagePct        float64   `json:"cpu_usage_pct"`
	MemoryUsedMB       int64     `json:"memory_used_mb"`
	MemoryTotalMB      int64     `json:"memory_total_mb"`
	MemoryUsagePct     float64   `json:"memory_usage_pct"`
	DiskUsedGB         float64   `json:"disk_used_gb"`
	DiskTotalGB        float64   `json:"disk_total_gb"`
	DiskUsagePct       float64   `json:"disk_usage_pct"`
	NetworkInKB        int64     `json:"network_in_kb"`
	NetworkOutKB       int64     `json:"network_out_kb"`
	NetworkInRateKBps  float64   `json:"network_in_rate_kbps"`
	NetworkOutRateKBps float64   `json:"network_out_rate_kbps"`
	UptimeSeconds      int64     `json:"uptime_seconds"`
	ContainersCount    int       `json:"containers_count"`
	DockerAvailable    bool      `json:"docker_available"`
	ContainersJSON     string    `json:"containers_json,omitempty"`
	RecordedAt         time.Time `json:"recorded_at"`
}

type HostMetricsPayload struct {
	CPUUsagePct        float64 `json:"cpu_usage_pct"`
	CPUCores           int     `json:"cpu_cores"`
	LoadAvg1m          float64 `json:"load_avg_1m"`
	LoadAvg5m          float64 `json:"load_avg_5m"`
	LoadAvg15m         float64 `json:"load_avg_15m"`
	MemoryTotalMB      uint64  `json:"memory_total_mb"`
	MemoryUsedMB       uint64  `json:"memory_used_mb"`
	MemoryFreeMB       uint64  `json:"memory_free_mb"`
	MemoryAvailableMB  uint64  `json:"memory_available_mb"`
	MemoryUsagePct     float64 `json:"memory_usage_pct"`
	DiskTotalGB        float64 `json:"disk_total_gb"`
	DiskUsedGB         float64 `json:"disk_used_gb"`
	DiskFreeGB         float64 `json:"disk_free_gb"`
	DiskUsagePct       float64 `json:"disk_usage_pct"`
	NetworkInKB        uint64  `json:"network_in_kb"`
	NetworkOutKB       uint64  `json:"network_out_kb"`
	NetworkInRateKBps  float64 `json:"network_in_rate_kbps"`
	NetworkOutRateKBps float64 `json:"network_out_rate_kbps"`
	UptimeSeconds      uint64  `json:"uptime_seconds"`
	OS                 string  `json:"os"`
	Platform           string  `json:"platform"`
	Hostname           string  `json:"hostname"`
	SSHHardened        bool    `json:"ssh_hardened"`
}

type PortBindingPayload struct {
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
	Protocol      string `json:"protocol"`
	HostIP        string `json:"host_ip,omitempty"`
}

type VolumeMountPayload struct {
	Name        string `json:"name,omitempty"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Mode        string `json:"mode"`
	Type        string `json:"type"`
}

type ContainerMetricPayload struct {
	ID                   string               `json:"id"`
	Names                []string             `json:"names"`
	Image                string               `json:"image"`
	State                string               `json:"state"`
	Status               string               `json:"status"`
	Created              int64                `json:"created"`
	CPUUsagePct          float64              `json:"cpu_usage_pct"`
	MemoryUsageMB        float64              `json:"memory_usage_mb"`
	MemoryLimitMB        float64              `json:"memory_limit_mb"`
	PortBindings         []PortBindingPayload `json:"port_bindings,omitempty"`
	VolumeMounts         []VolumeMountPayload `json:"volume_mounts,omitempty"`
	Networks             []string             `json:"networks,omitempty"`
	IPAddress            string               `json:"ip_address,omitempty"`
	RestartPolicy        string               `json:"restart_policy,omitempty"`
	EnvironmentVariables map[string]string    `json:"environment_variables,omitempty"`
	Logs                 []string             `json:"logs,omitempty"`
}

type DiscoveredNetworkPayload struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Driver     string `json:"driver"`
	Scope      string `json:"scope"`
	SubnetCIDR string `json:"subnet_cidr"`
	Gateway    string `json:"gateway"`
	Internal   bool   `json:"internal"`
}

type DiscoveredVolumePayload struct {
	Name       string  `json:"name"`
	Driver     string  `json:"driver"`
	Mountpoint string  `json:"mountpoint"`
	SizeGB     float64 `json:"size_gb"`
	CreatedAt  string  `json:"created_at,omitempty"`
	InUse      bool    `json:"in_use"`
}

type TelemetryReportPayload struct {
	ServerID        uuid.UUID                  `json:"server_id"`
	Timestamp       time.Time                  `json:"timestamp"`
	Host            HostMetricsPayload         `json:"host"`
	Containers      []ContainerMetricPayload   `json:"containers"`
	Networks        []DiscoveredNetworkPayload `json:"networks,omitempty"`
	Volumes         []DiscoveredVolumePayload  `json:"volumes,omitempty"`
	DockerAvailable bool                       `json:"docker_available"`
}

type MetricRepository interface {
	Create(ctx context.Context, metric *ServerMetric) error
	GetLatestByServerID(ctx context.Context, serverID uuid.UUID) (*ServerMetric, error)
	GetHistoryByServerID(ctx context.Context, serverID uuid.UUID, from, to time.Time, limit int) ([]ServerMetric, error)
}

type TelemetryBroadcaster interface {
	BroadcastToServer(serverID uuid.UUID, event string, data any)
	BroadcastToOrg(orgID uuid.UUID, event string, data any)
}
