package reporter

import (
	"errors"
	"fmt"

	"github.com/satsetops/agent/internal/api"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
)

func Collect() (api.Metrics, error) {
	cpuPercentages, err := cpu.Percent(0, false)
	if err != nil {
		return api.Metrics{}, fmt.Errorf("collect CPU usage: %w", err)
	}
	if len(cpuPercentages) == 0 {
		return api.Metrics{}, errors.New("collect CPU usage: no samples")
	}
	memory, err := mem.VirtualMemory()
	if err != nil {
		return api.Metrics{}, fmt.Errorf("collect memory usage: %w", err)
	}
	diskUsage, err := disk.Usage("/")
	if err != nil {
		return api.Metrics{}, fmt.Errorf("collect disk usage: %w", err)
	}
	uptime, err := host.Uptime()
	if err != nil {
		return api.Metrics{}, fmt.Errorf("collect uptime: %w", err)
	}

	return api.Metrics{
		CPUPercent:    cpuPercentages[0],
		MemoryPercent: memory.UsedPercent,
		DiskPercent:   diskUsage.UsedPercent,
		UptimeSeconds: uptime,
	}, nil
}
