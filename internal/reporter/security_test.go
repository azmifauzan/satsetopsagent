package reporter

import (
	"errors"
	"testing"
)

func TestCollectSecurity_Success(t *testing.T) {
	fakeDecisions := `[
		{"id": 1, "origin": "crowdsec", "type": "ban", "value": "1.2.3.4", "scope": "Ip", "duration": "4h", "scenario": "crowdsecurity/ssh-bf"},
		{"id": 2, "origin": "crowdsec", "type": "ban", "value": "5.6.7.8", "scope": "Ip", "duration": "4h", "scenario": "crowdsecurity/http-crawl"}
	]`

	fakeAlerts := `[
		{
			"id": 101,
			"created_at": "2026-06-26T16:00:00Z",
			"scenario": "crowdsecurity/ssh-bf",
			"source": {"ip": "1.2.3.4", "cn": "ID"},
			"decisions": [{"type": "ban", "duration": "4h", "value": "1.2.3.4"}]
		},
		{
			"id": 102,
			"created_at": "2026-06-26T16:05:00Z",
			"scenario": "crowdsecurity/ssh-bf",
			"source": {"ip": "1.2.3.4", "cn": "ID"},
			"decisions": []
		}
	]`

	runner := &fakeRunner{
		runFunc: func(cmd string, args ...string) (string, error) {
			if cmd == "cscli" && args[0] == "decisions" && args[1] == "list" {
				return fakeDecisions, nil
			}
			if cmd == "cscli" && args[0] == "alerts" && args[1] == "list" {
				return fakeAlerts, nil
			}
			return "", errors.New("unexpected command")
		},
	}

	event, err := CollectSecurity(runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.TotalAlerts != 2 {
		t.Errorf("expected 2 alerts, got %d", event.TotalAlerts)
	}
	if event.ActiveBans != 2 {
		t.Errorf("expected 2 active bans, got %d", event.ActiveBans)
	}
	if len(event.AttacksTimeline) != 2 {
		t.Errorf("expected 2 timeline incidents, got %d", len(event.AttacksTimeline))
	}
	if event.AttacksTimeline[0].IP != "1.2.3.4" || event.AttacksTimeline[0].Reason != "ssh-bf" {
		t.Errorf("unexpected timeline incident content: %+v", event.AttacksTimeline[0])
	}
	if len(event.AttackTypes) != 1 || event.AttackTypes[0].Type != "ssh-bf" || event.AttackTypes[0].Count != 2 {
		t.Errorf("unexpected attack types: %+v", event.AttackTypes)
	}
}

func TestCollectSecurity_CommandNotFound(t *testing.T) {
	runner := &fakeRunner{
		runFunc: func(cmd string, args ...string) (string, error) {
			return "", errors.New("command not found")
		},
	}

	event, err := CollectSecurity(runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.TotalAlerts != 0 {
		t.Errorf("expected 0 alerts, got %d", event.TotalAlerts)
	}
	if event.ActiveBans != 0 {
		t.Errorf("expected 0 active bans, got %d", event.ActiveBans)
	}
}
