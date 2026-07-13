package reporter

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/satsetops/agent/internal/api"
	"github.com/satsetops/agent/internal/exec"
)

// dockerStatsTimeout bounds how long CollectContainers waits for `docker
// stats` before giving up. Without this, a hung/overloaded dockerd — exactly
// the condition most likely to coincide with real load — would block the
// shared metrics goroutine forever, since exec.Runner has no built-in
// timeout and every other metrics tick (including whole-VPS gopsutil stats)
// rides on the same loop. The collector goroutine below isn't forcibly
// killed on timeout (Go can't cancel an in-flight os/exec.Command without
// a context threaded through the Runner interface, which every other
// executor in this codebase also lacks) — it leaks until the underlying
// command eventually returns, but that only happens when docker stats is
// already hung, an abnormal condition to begin with, and it no longer
// blocks metrics reporting from proceeding.
const dockerStatsTimeout = 10 * time.Second

// CollectContainers runs `docker stats` against every currently-running
// container and returns per-container CPU/memory usage. Best-effort: if
// docker isn't installed, times out, or nothing is running, returns an
// empty slice rather than an error — this is an addition to the metrics
// payload, never a reason to fail the whole report. A single malformed
// output line is skipped (and logged) rather than aborting the whole
// collection (same skip convention as CollectTraffic's log-line parsing).
func CollectContainers(runner exec.Runner) []api.ContainerMetric {
	output, err := runDockerStats(runner, dockerStatsTimeout)
	if err != nil || strings.TrimSpace(output) == "" {
		if err != nil {
			log.Printf("collect containers: %v", err)
		}

		return []api.ContainerMetric{}
	}

	return parseDockerStatsOutput(output)
}

func runDockerStats(runner exec.Runner, timeout time.Duration) (string, error) {
	type result struct {
		output string
		err    error
	}
	done := make(chan result, 1)

	go func() {
		output, err := runner.Run("docker", "stats", "--no-stream", "--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}")
		done <- result{output, err}
	}()

	select {
	case r := <-done:
		return r.output, r.err
	case <-time.After(timeout):
		return "", fmt.Errorf("docker stats timed out after %s", timeout)
	}
}

func parseDockerStatsOutput(output string) []api.ContainerMetric {
	containers := []api.ContainerMetric{}

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			log.Printf("collect containers: skipping line with unexpected field count: %q", line)

			continue
		}

		cpuPercent, err := parsePercent(fields[1])
		if err != nil {
			log.Printf("collect containers: skipping %q, invalid cpu percent %q: %v", fields[0], fields[1], err)

			continue
		}

		memUsageMB, err := parseMemUsageMB(fields[2])
		if err != nil {
			log.Printf("collect containers: skipping %q, invalid mem usage %q: %v", fields[0], fields[2], err)

			continue
		}

		memPercent, err := parsePercent(fields[3])
		if err != nil {
			log.Printf("collect containers: skipping %q, invalid mem percent %q: %v", fields[0], fields[3], err)

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

const bytesPerMiB = 1024 * 1024

// memUnitToMB converts a docker stats memory unit to MiB (the unit this
// codebase calls "MB" everywhere else — see scan.go's total_ram_mb, which is
// also vm.Total/1024/1024). Binary units (KiB/MiB/GiB) and their decimal
// counterparts (KB/MB/GB, which some Docker builds/platforms emit) are NOT
// the same multiplier — KB is 1000 bytes, KiB is 1024 — so they're listed
// separately rather than aliased, unlike an earlier version of this file
// that incorrectly treated "MB" as identical to "MiB" (a ~5% understatement
// that grows to ~7%+ at GB scale).
var memUnitToMB = map[string]float64{
	"B":   1.0 / bytesPerMiB,
	"KIB": 1024.0 / bytesPerMiB,
	"MIB": 1,
	"GIB": 1024,
	"KB":  1000.0 / bytesPerMiB,
	"MB":  1_000_000.0 / bytesPerMiB,
	"GB":  1_000_000_000.0 / bytesPerMiB,
}

// parseMemUsageMB parses the "used" side of docker stats' MemUsage column,
// e.g. "123.4MiB / 512MiB" -> 123.4.
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
