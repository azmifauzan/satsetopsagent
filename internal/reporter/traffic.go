package reporter

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/satsetops/agent/internal/api"
	"github.com/satsetops/agent/internal/exec"
)

// Regex to parse standard Nginx access log line
// Example: 127.0.0.1 - - [26/Jun/2026:16:00:00 +0700] "GET /path HTTP/1.1" 200 1234
var nginxLogRegex = regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"[A-Z]+\s+(\S+)\s+[^"]+"\s+(\d{3})\s+(\d+|-).*`)

func CollectTraffic(runner exec.Runner) (api.TrafficSummary, error) {
	// Try reading native Nginx log first
	output, err := runner.Run("tail", "-n", "2000", "/var/log/nginx/access.log")
	if err != nil || len(strings.TrimSpace(output)) == 0 {
		// Fallback to docker logs
		output, err = runner.Run("docker", "logs", "--since", "1m", "nginx-certbot")
		if err != nil || len(strings.TrimSpace(output)) == 0 {
			output, err = runner.Run("docker", "logs", "--since", "1m", "nginx")
			if err != nil {
				// If everything fails, return empty summary rather than failing
				return api.TrafficSummary{
					TopPaths: []api.PathCount{},
					TopIPs:   []api.IPCount{},
				}, nil
			}
		}
	}

	lines := strings.Split(output, "\n")
	
	var totalRequests uint32
	var requests4xx uint32
	var requests5xx uint32
	var bandwidthBytes uint64
	
	pathCounts := make(map[string]uint32)
	ipCounts := make(map[string]uint32)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		matches := nginxLogRegex.FindStringSubmatch(line)
		if len(matches) < 5 {
			continue
		}
		
		ip := matches[1]
		path := matches[2]
		statusStr := matches[3]
		bytesStr := matches[4]
		
		// Strip query parameters from path for cleaner aggregation
		if idx := strings.Index(path, "?"); idx != -1 {
			path = path[:idx]
		}

		totalRequests++
		
		status, _ := strconv.Atoi(statusStr)
		if status >= 400 && status < 500 {
			requests4xx++
		} else if status >= 500 && status < 600 {
			requests5xx++
		}
		
		if bytesStr != "-" {
			bytes, _ := strconv.ParseUint(bytesStr, 10, 64)
			bandwidthBytes += bytes
		}
		
		pathCounts[path]++
		ipCounts[ip]++
	}

	// Sort and get Top 5 paths
	type kv struct {
		Key   string
		Value uint32
	}
	
	var paths []kv
	for k, v := range pathCounts {
		paths = append(paths, kv{k, v})
	}
	sort.Slice(paths, func(i, j int) bool {
		return paths[i].Value > paths[j].Value
	})
	
	var topPaths []api.PathCount
	for i := 0; i < len(paths) && i < 5; i++ {
		topPaths = append(topPaths, api.PathCount{
			Path:  paths[i].Key,
			Count: paths[i].Value,
		})
	}

	// Sort and get Top 5 IPs
	var ips []kv
	for k, v := range ipCounts {
		ips = append(ips, kv{k, v})
	}
	sort.Slice(ips, func(i, j int) bool {
		return ips[i].Value > ips[j].Value
	})
	
	var topIPs []api.IPCount
	for i := 0; i < len(ips) && i < 5; i++ {
		topIPs = append(topIPs, api.IPCount{
			IP:    ips[i].Key,
			Count: ips[i].Value,
		})
	}

	// Ensure topPaths/topIPs are not nil
	if topPaths == nil {
		topPaths = []api.PathCount{}
	}
	if topIPs == nil {
		topIPs = []api.IPCount{}
	}

	return api.TrafficSummary{
		TotalRequests:  totalRequests,
		Requests4xx:    requests4xx,
		Requests5xx:    requests5xx,
		TopPaths:       topPaths,
		TopIPs:         topIPs,
		BandwidthBytes: bandwidthBytes,
	}, nil
}
