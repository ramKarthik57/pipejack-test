package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func main() {
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		if !p.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		cmdline, _ := os.ReadFile(filepath.Join("/proc", p.Name(), "cmdline"))
		exe, _ := os.Readlink(filepath.Join("/proc", p.Name(), "exe"))
		fmt.Printf("PID: %d\tExe: %s\tCmd: %s\n", pid, exe, strings.ReplaceAll(string(cmdline), "\x00", " "))
	}
}
