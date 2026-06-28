package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Policy structure matching .pipejack/policy.yaml
type Policy struct {
	Version               string   `yaml:"version"`
	Pipeline              string   `yaml:"pipeline"`
	AllowedBinaries       []string `yaml:"allowed_binaries"`
	BlockedBinaries       []string `yaml:"blocked_binaries"`
	SeverityThresholds    map[string]int `yaml:"severity_thresholds"`
	ActionsOnViolation    map[string]bool `yaml:"actions_on_violation"`
}

func main() {
	// Read policy file (located relative to the binary, or hardcoded)
	policyPath := ".pipejack/policy.yaml"
	data, err := os.ReadFile(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading policy: %v\n", err)
		os.Exit(1)
	}

	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing policy: %v\n", err)
		os.Exit(1)
	}

	// Build allowed set
	allowed := make(map[string]bool)
	for _, bin := range policy.AllowedBinaries {
		allowed[bin] = true
	}

	// Scan /proc
	violations := 0
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		if !p.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}

		exe, err := os.Readlink(filepath.Join("/proc", p.Name(), "exe"))
		if err != nil {
			// Process might be a kernel thread or permission denied
			continue
		}

		if !allowed[exe] {
			cmdline, _ := os.ReadFile(filepath.Join("/proc", p.Name(), "cmdline"))
			cmd := strings.ReplaceAll(string(cmdline), "\x00", " ")
			fmt.Printf("VIOLATION: PID %d (%s) cmd: %s\n", pid, exe, cmd)
			violations++
		}
	}

	fmt.Printf("\nScan complete. Violations: %d\n", violations)
	if violations > 0 {
		os.Exit(1) // Non-zero exit to fail the pipeline
	}
}
