package reporter

import (
	"strconv"
	"strings"

	"github.com/satsetops/agent/internal/api"
	"github.com/satsetops/agent/internal/exec"
)

// CollectContainers runs `docker stats` against every currently-running
// container and returns per-container CPU/memory usage. Best-effort: if
// docker isn't installed or nothing is running, returns an empty slice
// rather than an error — this is an addition to the metrics payload, never
// a reason to fail the whole report. A single malformed output line is
// skipped rather than aborting the whole collection (same convention as
// CollectTraffic's log-line parsing).
func CollectContainers(runner exec.Runner) []api.ContainerMetric {
	output, err := runner.Run("docker", "stats", "--no-stream", "--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}")
	if err != nil || strings.TrimSpace(output) == "" {
		return []api.ContainerMetric{}
	}

	containers := []api.ContainerMetric{}

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			continue
		}

		cpuPercent, err := parsePercent(fields[1])
		if err != nil {
			continue
		}

		memUsageMB, err := parseMemUsageMB(fields[2])
		if err != nil {
			continue
		}

		memPercent, err := parsePercent(fields[3])
		if err != nil {
			continue
		}

		containers = append(containers, api.ContainerMetric{
			Name:       fields[0],
			Status:     "running",
			CPUPercent: cpuPercent,
			MemPercent: memPercent,
			MemUsageMB: memUsageMB,
		})
	}

	return containers
}

// parsePercent parses a docker stats percentage like "12.34%" into 12.34.
func parsePercent(s string) (float64, error) {
	return strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(s), "%"), 64)
}

var memUnitToMB = map[string]float64{
	"B":   1.0 / (1024 * 1024),
	"KB":  1.0 / 1024,
	"KIB": 1.0 / 1024,
	"MB":  1,
	"MIB": 1,
	"GB":  1024,
	"GIB": 1024,
}

// parseMemUsageMB parses the "used" side of docker stats' MemUsage column,
// e.g. "123.4MiB / 512MiB" -> 123.4. Handles B/KiB/MiB/GiB (and the
// non-binary KB/MB/GB Docker also emits on some platforms/versions).
func parseMemUsageMB(s string) (float64, error) {
	used := strings.TrimSpace(strings.SplitN(s, "/", 2)[0])

	i := 0
	for i < len(used) && (used[i] == '.' || (used[i] >= '0' && used[i] <= '9')) {
		i++
	}
	if i == 0 {
		return 0, strconv.ErrSyntax
	}

	value, err := strconv.ParseFloat(used[:i], 64)
	if err != nil {
		return 0, err
	}

	unit := strings.ToUpper(strings.TrimSpace(used[i:]))
	multiplier, ok := memUnitToMB[unit]
	if !ok {
		return 0, strconv.ErrSyntax
	}

	return value * multiplier, nil
}
