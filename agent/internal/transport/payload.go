package transport

import (
	"time"

	"github.com/google/uuid"
)

type HostMetrics struct {
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

type PortBindingInfo struct {
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
	Protocol      string `json:"protocol"`
	HostIP        string `json:"host_ip,omitempty"`
}

type VolumeMountInfo struct {
	Name        string `json:"name,omitempty"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Mode        string `json:"mode"`
	Type        string `json:"type"`
}

type ContainerMetrics struct {
	ID                   string            `json:"id"`
	Names                []string          `json:"names"`
	Image                string            `json:"image"`
	State                string            `json:"state"`
	Status               string            `json:"status"`
	Created              int64             `json:"created"`
	CPUUsagePct          float64           `json:"cpu_usage_pct"`
	MemoryUsageMB        float64           `json:"memory_usage_mb"`
	MemoryLimitMB        float64           `json:"memory_limit_mb"`
	PortBindings         []PortBindingInfo `json:"port_bindings,omitempty"`
	VolumeMounts         []VolumeMountInfo `json:"volume_mounts,omitempty"`
	Networks             []string          `json:"networks,omitempty"`
	IPAddress            string            `json:"ip_address,omitempty"`
	RestartPolicy        string            `json:"restart_policy,omitempty"`
	EnvironmentVariables map[string]string `json:"environment_variables,omitempty"`
	Logs                 []string          `json:"logs,omitempty"`
}

type DiscoveredNetwork struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Driver     string `json:"driver"`
	Scope      string `json:"scope"`
	SubnetCIDR string `json:"subnet_cidr"`
	Gateway    string `json:"gateway"`
	Internal   bool   `json:"internal"`
}

type DiscoveredVolume struct {
	Name       string  `json:"name"`
	Driver     string  `json:"driver"`
	Mountpoint string  `json:"mountpoint"`
	SizeGB     float64 `json:"size_gb"`
	CreatedAt  string  `json:"created_at,omitempty"`
	InUse      bool    `json:"in_use"`
}

type AgentAction struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Target  string `json:"target"`
	Payload string `json:"payload,omitempty"`
}

type ContainerDeployPayload struct {
	Name          string            `json:"name"`
	Image         string            `json:"image"`
	Ports         []string          `json:"ports,omitempty"`
	Environment   map[string]string `json:"environment,omitempty"`
	Volumes       []string          `json:"volumes,omitempty"`
	RestartPolicy string            `json:"restart_policy,omitempty"`
}

type AgentReportResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    struct {
		ServerID   string        `json:"server_id"`
		RecordedAt string        `json:"recorded_at"`
		Actions    []AgentAction `json:"actions,omitempty"`
	} `json:"data"`
}

type AgentReportPayload struct {
	ServerID        uuid.UUID           `json:"server_id"`
	Timestamp       time.Time           `json:"timestamp"`
	Host            HostMetrics         `json:"host"`
	Containers      []ContainerMetrics  `json:"containers"`
	Networks        []DiscoveredNetwork `json:"networks,omitempty"`
	Volumes         []DiscoveredVolume  `json:"volumes,omitempty"`
	DockerAvailable bool                `json:"docker_available"`
}
