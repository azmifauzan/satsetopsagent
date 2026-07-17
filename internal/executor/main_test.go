package executor

import (
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	retryDelayOverride = time.Millisecond
	m.Run()
}
