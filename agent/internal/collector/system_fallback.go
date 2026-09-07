//go:build !linux

package collector

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/havilz/caelus-cloud/agent/internal/transport"
)

type FallbackCollector struct{}

func NewCollector() Collector {
	return &FallbackCollector{}
}

func (c *FallbackCollector) Collect(_ context.Context) (*transport.HostMetrics, error) {
	hostname, _ := os.Hostname()

	return &transport.HostMetrics{
		CPUUsagePct:        0.0,
		CPUCores:           runtime.NumCPU(),
		LoadAvg1m:          0.0,
		LoadAvg5m:          0.0,
		LoadAvg15m:         0.0,
		MemoryTotalMB:      1024,
		MemoryUsedMB:       512,
		MemoryFreeMB:       512,
		MemoryAvailableMB:  512,
		MemoryUsagePct:     50.0,
		DiskTotalGB:        20.0,
		DiskUsedGB:         10.0,
		DiskFreeGB:         10.0,
		DiskUsagePct:       50.0,
		NetworkInKB:        0,
		NetworkOutKB:       0,
		NetworkInRateKBps:  0.0,
		NetworkOutRateKBps: 0.0,
		UptimeSeconds:      0,
		OS:                 runtime.GOOS,
		Platform:           fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		Hostname:           hostname,
		SSHHardened:        false,
	}, nil
}
