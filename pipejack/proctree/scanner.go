package proctree

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Policy struct {
	AllowedBinaries []string `yaml:"allowed_binaries"`
}

func Run(policyPath string) (int, error) {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return 0, fmt.Errorf("reading policy: %w", err)
	}
	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return 0, fmt.Errorf("parsing policy: %w", err)
	}
	allowed := make(map[string]bool)
	for _, bin := range policy.AllowedBinaries {
		allowed[bin] = true
	}

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
			continue
		}
		if !allowed[exe] {
			cmdline, _ := os.ReadFile(filepath.Join("/proc", p.Name(), "cmdline"))
			cmd := strings.ReplaceAll(string(cmdline), "\x00", " ")
			fmt.Printf("VIOLATION: PID %d (%s) cmd: %s\n", pid, exe, cmd)
			violations++
		}
	}
	return violations, nil
}

// RunOnPID checks a single PID against the policy and returns 1 if violation.
func RunOnPID(pid int, policyPath string) (int, error) {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return 0, err
	}
	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return 0, err
	}
	allowed := make(map[string]bool)
	for _, bin := range policy.AllowedBinaries {
		allowed[bin] = true
	}
	exe, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return 0, nil
	}
	if !allowed[exe] {
		cmdline, _ := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
		cmd := strings.ReplaceAll(string(cmdline), "\x00", " ")
		fmt.Printf("VIOLATION: PID %d (%s) cmd: %s\n", pid, exe, cmd)
		return 1, nil
	}
	return 0, nil
}
