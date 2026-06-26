package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var ErrUnauthorized = errors.New("unauthorized")

type Command struct {
	ID      int            `json:"id"`
	Type    string         `json:"type"`
	Payload map[string]any `json:"payload"`
}

type Metrics struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"mem_percent"`
	DiskPercent   float64 `json:"disk_percent"`
	UptimeSeconds uint64  `json:"uptime_seconds"`
}

type MetricsResponse struct {
	OK                  bool `json:"ok"`
	MetricsEnabled      bool `json:"metrics_enabled"`
	NextIntervalSeconds int  `json:"next_interval_seconds"`
}

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

func New(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) Register(oneTime string) (string, error) {
	var response struct {
		PermanentToken string `json:"permanent_token"`
	}
	if err := c.doJSON(http.MethodPost, "/api/agent/register", map[string]string{
		"token": oneTime,
	}, &response); err != nil {
		return "", fmt.Errorf("register agent: %w", err)
	}
	if response.PermanentToken == "" {
		return "", errors.New("register agent: empty permanent token")
	}
	return response.PermanentToken, nil
}

func (c *Client) Poll() ([]Command, error) {
	var commands []Command
	if err := c.doJSON(http.MethodGet, "/api/agent/commands", nil, &commands); err != nil {
		return nil, fmt.Errorf("poll commands: %w", err)
	}
	return commands, nil
}

func (c *Client) PostResult(id int, success bool, output string, exitCode int) error {
	payload := struct {
		Success  bool   `json:"success"`
		Output   string `json:"output"`
		ExitCode int    `json:"exit_code"`
	}{success, output, exitCode}

	if err := c.doJSON(http.MethodPost, fmt.Sprintf("/api/agent/commands/%d/result", id), payload, nil); err != nil {
		return fmt.Errorf("post command result: %w", err)
	}
	return nil
}

func (c *Client) PostMetrics(metrics Metrics) (MetricsResponse, error) {
	var response MetricsResponse
	if err := c.doJSON(http.MethodPost, "/api/agent/metrics", metrics, &response); err != nil {
		return MetricsResponse{}, fmt.Errorf("post metrics: %w", err)
	}
	return response, nil
}

type TrafficSummary struct {
	TotalRequests  uint32      `json:"total_requests"`
	Requests4xx    uint32      `json:"requests_4xx"`
	Requests5xx    uint32      `json:"requests_5xx"`
	TopPaths       []PathCount `json:"top_paths"`
	TopIPs         []IPCount   `json:"top_ips"`
	BandwidthBytes uint64      `json:"bandwidth_bytes"`
}

type PathCount struct {
	Path  string `json:"path"`
	Count uint32 `json:"count"`
}

type IPCount struct {
	IP    string `json:"ip"`
	Count uint32 `json:"count"`
}

type SecurityEvent struct {
	TotalAlerts     uint32           `json:"total_alerts"`
	ActiveBans      uint32           `json:"active_bans"`
	AttacksTimeline []AttackIncident `json:"attacks_timeline"`
	AttackTypes     []AttackType     `json:"attack_types"`
}

type AttackIncident struct {
	Time   string `json:"time"`
	Source string `json:"source"`
	Reason string `json:"reason"`
	IP     string `json:"ip"`
}

type AttackType struct {
	Type  string `json:"type"`
	Count uint32 `json:"count"`
}

func (c *Client) PostTraffic(traffic TrafficSummary) error {
	if err := c.doJSON(http.MethodPost, "/api/agent/traffic", traffic, nil); err != nil {
		return fmt.Errorf("post traffic: %w", err)
	}
	return nil
}

func (c *Client) PostSecurity(security SecurityEvent) error {
	if err := c.doJSON(http.MethodPost, "/api/agent/security", security, nil); err != nil {
		return fmt.Errorf("post security: %w", err)
	}
	return nil
}

func (c *Client) doJSON(method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}

	request, err := http.NewRequest(method, c.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}

	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusUnauthorized {
		return ErrUnauthorized
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("unexpected HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(message)))
	}
	if output == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(output); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
