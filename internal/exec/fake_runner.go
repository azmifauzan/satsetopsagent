package exec

import (
	"strings"
)

// FakeRunner implements Runner for testing
type FakeRunner struct {
	Commands []string
	Outputs  map[string]string
	Errors   map[string]error
}

func NewFakeRunner() *FakeRunner {
	return &FakeRunner{
		Commands: make([]string, 0),
		Outputs:  make(map[string]string),
		Errors:   make(map[string]error),
	}
}

func (f *FakeRunner) Run(name string, args ...string) (string, error) {
	return f.run(name, args...)
}

func (f *FakeRunner) RunWithStdin(name string, stdin string, args ...string) (string, error) {
	return f.run(name, args...)
}

func (f *FakeRunner) run(name string, args ...string) (string, error) {
	cmdStr := name
	if len(args) > 0 {
		cmdStr += " " + strings.Join(args, " ")
	}
	f.Commands = append(f.Commands, cmdStr)

	if err, ok := f.Errors[cmdStr]; ok && err != nil {
		return "", err
	}

	// We can also match prefixes if exact match isn't found
	if out, ok := f.Outputs[cmdStr]; ok {
		return out, nil
	}

	for k, v := range f.Outputs {
		if strings.HasPrefix(cmdStr, k) {
			return v, nil
		}
	}

	for k, err := range f.Errors {
		if strings.HasPrefix(cmdStr, k) && err != nil {
			return "", err
		}
	}

	return "", nil
}

func (f *FakeRunner) HasCommand(expected string) bool {
	for _, cmd := range f.Commands {
		if cmd == expected {
			return true
		}
	}
	return false
}

func (f *FakeRunner) HasCommandWithPrefix(prefix string) bool {
	for _, cmd := range f.Commands {
		if strings.HasPrefix(cmd, prefix) {
			return true
		}
	}
	return false
}
