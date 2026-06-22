package main

import (
	"fmt"

	"github.com/satsetops/agent/internal/version"
)

func main() {
	fmt.Printf("satsetopsagent %s\n", version.String())
}
