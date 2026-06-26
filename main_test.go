package main

import (
	"testing"
	"time"
)

func TestClampMetricsInterval(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want time.Duration
	}{
		{time.Second, 10 * time.Second},
		{time.Minute, time.Minute},
		{2 * time.Hour, time.Hour},
	}

	for _, tt := range tests {
		if got := clampMetricsInterval(tt.in); got != tt.want {
			t.Fatalf("clampMetricsInterval(%s) = %s, want %s", tt.in, got, tt.want)
		}
	}
}
