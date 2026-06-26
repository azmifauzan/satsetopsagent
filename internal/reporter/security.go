package reporter

import (
	"encoding/json"
	"strings"

	"github.com/satsetops/agent/internal/api"
	"github.com/satsetops/agent/internal/exec"
)

type CrowdSecAlert struct {
	ID        int    `json:"id"`
	CreatedAt string `json:"created_at"`
	Scenario  string `json:"scenario"`
	Source    struct {
		IP string `json:"ip"`
		CN string `json:"cn"`
	} `json:"source"`
	Decisions []struct {
		Type     string `json:"type"`
		Duration string `json:"duration"`
		Value    string `json:"value"`
	} `json:"decisions"`
}

type CrowdSecDecision struct {
	ID       int    `json:"id"`
	Origin   string `json:"origin"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	Scope    string `json:"scope"`
	Duration string `json:"duration"`
	Scenario string `json:"scenario"`
}

func CollectSecurity(runner exec.Runner) (api.SecurityEvent, error) {
	// 1. Fetch active decisions (bans)
	decisionsJSON, err := runner.Run("cscli", "decisions", "list", "-o", "json")
	var decisions []CrowdSecDecision
	if err == nil && len(strings.TrimSpace(decisionsJSON)) > 0 && decisionsJSON != "null" {
		_ = json.Unmarshal([]byte(decisionsJSON), &decisions)
	}

	// 2. Fetch alerts from the last 1h
	alertsJSON, err := runner.Run("cscli", "alerts", "list", "--since", "1h", "-o", "json")
	var alerts []CrowdSecAlert
	if err == nil && len(strings.TrimSpace(alertsJSON)) > 0 && alertsJSON != "null" {
		_ = json.Unmarshal([]byte(alertsJSON), &alerts)
	}

	// Initialize empty slices so they don't serialize to null in JSON
	timeline := []api.AttackIncident{}
	typeCounts := make(map[string]uint32)

	// Populate timeline and type counts from alerts
	for _, alert := range alerts {
		// Clean up scenario name (e.g. crowdsecurity/ssh-bf -> ssh-bf)
		scenario := alert.Scenario
		if parts := strings.Split(scenario, "/"); len(parts) > 1 {
			scenario = parts[len(parts)-1]
		}

		typeCounts[scenario]++

		timeline = append(timeline, api.AttackIncident{
			Time:   alert.CreatedAt,
			Source: "crowdsec",
			Reason: scenario,
			IP:     alert.Source.IP,
		})
	}

	// Format attack types list
	attackTypes := []api.AttackType{}
	for k, v := range typeCounts {
		attackTypes = append(attackTypes, api.AttackType{
			Type:  k,
			Count: v,
		})
	}

	activeBans := uint32(len(decisions))
	// If decisions list failed but we have decisions inside alerts, use alert decision count as fallback
	if activeBans == 0 {
		for _, alert := range alerts {
			activeBans += uint32(len(alert.Decisions))
		}
	}

	return api.SecurityEvent{
		TotalAlerts:     uint32(len(alerts)),
		ActiveBans:      activeBans,
		AttacksTimeline: timeline,
		AttackTypes:     attackTypes,
	}, nil
}
