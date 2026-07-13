package reporter

import (
	"errors"
	"testing"
)

func TestCollectContainersParsesDockerStatsOutput(t *testing.T) {
	runner := &fakeRunner{
		runFunc: func(cmd string, args ...string) (string, error) {
			if cmd == "docker" && len(args) > 0 && args[0] == "stats" {
				return "my-app\t12.34%\t123.4MiB / 512MiB\t24.10%\n" +
					"nginx-certbot\t0.50%\t10MiB / 987MiB\t1.01%\n", nil
			}
			return "", errors.New("unexpected command")
		},
	}

	containers := CollectContainers(runner)

	if len(containers) != 2 {
		t.Fatalf("expected 2 containers, got %d: %+v", len(containers), containers)
	}
	if containers[0].Name != "my-app" || containers[0].Status != "running" {
		t.Errorf("unexpected first container: %+v", containers[0])
	}
	if containers[0].CPUPercent != 12.34 {
		t.Errorf("expected cpu_percent 12.34, got %v", containers[0].CPUPercent)
	}
	if containers[0].MemUsageMB != 123.4 {
		t.Errorf("expected mem_usage_mb 123.4, got %v", containers[0].MemUsageMB)
	}
	if containers[0].MemPercent != 24.10 {
		t.Errorf("expected mem_percent 24.10, got %v", containers[0].MemPercent)
	}
}

func TestCollectContainersHandlesGiB(t *testing.T) {
	runner := &fakeRunner{
		runFunc: func(cmd string, args ...string) (string, error) {
			return "big-app\t5.00%\t1.5GiB / 4GiB\t37.50%\n", nil
		},
	}

	containers := CollectContainers(runner)

	if len(containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(containers))
	}
	if containers[0].MemUsageMB != 1536 {
		t.Errorf("expected 1.5GiB = 1536MB, got %v", containers[0].MemUsageMB)
	}
}

func TestCollectContainersSkipsMalformedLines(t *testing.T) {
	runner := &fakeRunner{
		runFunc: func(cmd string, args ...string) (string, error) {
			return "good-app\t1.00%\t10MiB / 100MiB\t10.00%\n" +
				"broken-line-not-enough-fields\n" +
				"another-good\t2.00%\t20MiB / 100MiB\t20.00%\n", nil
		},
	}

	containers := CollectContainers(runner)

	if len(containers) != 2 {
		t.Fatalf("expected 2 containers (malformed line skipped), got %d: %+v", len(containers), containers)
	}
}

func TestCollectContainersReturnsEmptyWhenDockerUnavailable(t *testing.T) {
	runner := &fakeRunner{
		runFunc: func(cmd string, args ...string) (string, error) {
			return "", errors.New("docker: command not found")
		},
	}

	containers := CollectContainers(runner)

	if containers == nil {
		t.Fatal("expected empty slice, not nil, on failure")
	}
	if len(containers) != 0 {
		t.Fatalf("expected 0 containers, got %d", len(containers))
	}
}
