package reporter

import "testing"

func TestCollectReturnsSaneMetrics(t *testing.T) {
	metrics, err := Collect()
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	percentages := []float64{metrics.CPUPercent, metrics.MemoryPercent, metrics.DiskPercent}
	for _, percentage := range percentages {
		if percentage < 0 || percentage > 100 {
			t.Fatalf("invalid percentage %.2f", percentage)
		}
	}
	if metrics.UptimeSeconds == 0 {
		t.Fatal("uptime must be positive")
	}
}
