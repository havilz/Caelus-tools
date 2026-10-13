//go:build linux

package collector

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/havilz/caelus-cloud/agent/internal/transport"
)

type LinuxCollector struct {
	mu          sync.Mutex
	prevCPUTot  uint64
	prevCPUIdle uint64
	prevNetRx   uint64
	prevNetTx   uint64
	prevNetTime time.Time
}

func NewCollector() Collector {
	c := &LinuxCollector{
		prevNetTime: time.Now(),
	}
	_ = c.initCPUTicks()
	_ = c.initNetCounters()
	return c
}

func (c *LinuxCollector) Collect(_ context.Context) (*transport.HostMetrics, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	hostname, _ := os.Hostname()
	cpuUsage := c.readCPUUsage()
	load1, load5, load15 := c.readLoadAvg()
	memTotal, memUsed, memFree, memAvail, memPct := c.readMemory()
	diskTotal, diskUsed, diskFree, diskPct := c.readDisk()
	netRx, netTx, rateRx, rateTx := c.readNetwork()
	uptime := c.readUptime()

	return &transport.HostMetrics{
		CPUUsagePct:        math.Round(cpuUsage*100) / 100,
		CPUCores:           runtime.NumCPU(),
		LoadAvg1m:          load1,
		LoadAvg5m:          load5,
		LoadAvg15m:         load15,
		MemoryTotalMB:      memTotal,
		MemoryUsedMB:       memUsed,
		MemoryFreeMB:       memFree,
		MemoryAvailableMB:  memAvail,
		MemoryUsagePct:     math.Round(memPct*100) / 100,
		DiskTotalGB:        math.Round(diskTotal*100) / 100,
		DiskUsedGB:         math.Round(diskUsed*100) / 100,
		DiskFreeGB:         math.Round(diskFree*100) / 100,
		DiskUsagePct:       math.Round(diskPct*100) / 100,
		NetworkInKB:        netRx / 1024,
		NetworkOutKB:       netTx / 1024,
		NetworkInRateKBps:  math.Round(rateRx*100) / 100,
		NetworkOutRateKBps: math.Round(rateTx*100) / 100,
		UptimeSeconds:      uptime,
		OS:                 runtime.GOOS,
		Platform:           fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		Hostname:           hostname,
		SSHHardened:        c.checkSSHHardening(),
	}, nil
}

func (c *LinuxCollector) initCPUTicks() error {
	tot, idle, err := c.parseCPUTicks()
	if err != nil {
		return err
	}
	c.prevCPUTot = tot
	c.prevCPUIdle = idle
	return nil
}

func (c *LinuxCollector) parseCPUTicks() (uint64, uint64, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 5 && fields[0] == "cpu" {
			var total uint64
			var idle uint64
			for i := 1; i < len(fields); i++ {
				val, _ := strconv.ParseUint(fields[i], 10, 64)
				total += val
				if i == 4 || i == 5 {
					idle += val
				}
			}
			return total, idle, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	return 0, 0, fmt.Errorf("invalid /proc/stat format")
}

func (c *LinuxCollector) readCPUUsage() float64 {
	tot, idle, err := c.parseCPUTicks()
	if err != nil || c.prevCPUTot == 0 {
		return 0.0
	}

	deltaTot := tot - c.prevCPUTot
	deltaIdle := idle - c.prevCPUIdle
	c.prevCPUTot = tot
	c.prevCPUIdle = idle

	if deltaTot == 0 {
		return 0.0
	}

	usage := float64(deltaTot-deltaIdle) / float64(deltaTot) * 100.0
	if usage < 0 {
		return 0.0
	}
	if usage > 100 {
		return 100.0
	}
	return usage
}

func (c *LinuxCollector) readLoadAvg() (float64, float64, float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0
	}
	l1, _ := strconv.ParseFloat(fields[0], 64)
	l5, _ := strconv.ParseFloat(fields[1], 64)
	l15, _ := strconv.ParseFloat(fields[2], 64)
	return l1, l5, l15
}

func (c *LinuxCollector) readMemory() (uint64, uint64, uint64, uint64, float64) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, 0, 0, 0
	}
	defer file.Close()

	var memTotal, memFree, memAvail uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		valFields := strings.Fields(strings.TrimSpace(parts[1]))
		if len(valFields) == 0 {
			continue
		}
		valKB, _ := strconv.ParseUint(valFields[0], 10, 64)

		switch key {
		case "MemTotal":
			memTotal = valKB / 1024
		case "MemFree":
			memFree = valKB / 1024
		case "MemAvailable":
			memAvail = valKB / 1024
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, 0, 0, 0
	}

	if memAvail == 0 && memFree > 0 {
		memAvail = memFree
	}

	var memUsed uint64
	var memPct float64
	if memTotal > 0 {
		if memTotal >= memAvail {
			memUsed = memTotal - memAvail
		}
		memPct = (float64(memUsed) / float64(memTotal)) * 100.0
	}

	return memTotal, memUsed, memFree, memAvail, memPct
}

func (c *LinuxCollector) readDisk() (float64, float64, float64, float64) {
	var stat syscall.Statfs_t
	err := syscall.Statfs("/", &stat)
	if err != nil {
		return 0, 0, 0, 0
	}

	totalBytes := stat.Blocks * uint64(stat.Bsize)
	freeBytes := stat.Bavail * uint64(stat.Bsize)
	var usedBytes uint64
	if totalBytes >= freeBytes {
		usedBytes = totalBytes - freeBytes
	}

	totalGB := float64(totalBytes) / (1024 * 1024 * 1024)
	usedGB := float64(usedBytes) / (1024 * 1024 * 1024)
	freeGB := float64(freeBytes) / (1024 * 1024 * 1024)

	var usagePct float64
	if totalGB > 0 {
		usagePct = (usedGB / totalGB) * 100.0
	}

	return totalGB, usedGB, freeGB, usagePct
}

func (c *LinuxCollector) initNetCounters() error {
	rx, tx, err := c.parseNetDev()
	if err != nil {
		return err
	}
	c.prevNetRx = rx
	c.prevNetTx = tx
	c.prevNetTime = time.Now()
	return nil
}

func (c *LinuxCollector) parseNetDev() (uint64, uint64, error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	var totalRx, totalTx uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.Contains(line, ":") || strings.HasPrefix(line, "lo:") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) >= 9 {
			rx, _ := strconv.ParseUint(fields[0], 10, 64)
			tx, _ := strconv.ParseUint(fields[8], 10, 64)
			totalRx += rx
			totalTx += tx
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	return totalRx, totalTx, nil
}

func (c *LinuxCollector) readNetwork() (uint64, uint64, float64, float64) {
	now := time.Now()
	rx, tx, err := c.parseNetDev()
	if err != nil {
		return 0, 0, 0, 0
	}

	elapsed := now.Sub(c.prevNetTime).Seconds()
	var rateRx, rateTx float64
	if elapsed > 0 && c.prevNetRx > 0 {
		if rx >= c.prevNetRx {
			rateRx = float64(rx-c.prevNetRx) / 1024.0 / elapsed
		}
		if tx >= c.prevNetTx {
			rateTx = float64(tx-c.prevNetTx) / 1024.0 / elapsed
		}
	}

	c.prevNetRx = rx
	c.prevNetTx = tx
	c.prevNetTime = now

	return rx, tx, rateRx, rateTx
}

func (c *LinuxCollector) readUptime() uint64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	val, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return uint64(val)
}

func (c *LinuxCollector) checkSSHHardening() bool {
	configPaths := []string{"/etc/ssh/sshd_config"}
	if entries, err := os.ReadDir("/etc/ssh/sshd_config.d"); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
				configPaths = append(configPaths, "/etc/ssh/sshd_config.d/"+e.Name())
			}
		}
	}

	permitRootNo := false
	passwordAuthNo := false

	for _, path := range configPaths {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				key := strings.ToLower(fields[0])
				val := strings.ToLower(fields[1])
				if key == "permitrootlogin" && val == "no" {
					permitRootNo = true
				}
				if key == "passwordauthentication" && val == "no" {
					passwordAuthNo = true
				}
			}
		}
		_ = scanner.Err()
		_ = file.Close()
	}

	return permitRootNo && passwordAuthNo
}
