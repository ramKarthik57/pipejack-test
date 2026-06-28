package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ramKarthik57/pipejack-test/pipejack/ebpfctrl"
	"github.com/ramKarthik57/pipejack-test/pipejack/fschecker"
	"github.com/ramKarthik57/pipejack-test/pipejack/proctree"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: pipejackd <workspace_dir> <policy_path> [cgroup_path]\n")
		os.Exit(1)
	}
	workspace := os.Args[1]
	policyPath := os.Args[2]

	// --- cgroup path detection ---
	cgroupPath := ""
	if len(os.Args) >= 4 {
		cgroupPath = os.Args[3]
	} else {
		// Auto‑detect from the build container’s cgroup (via shared PID namespace)
		data, err := os.ReadFile("/proc/1/cgroup")
		if err == nil {
			line := strings.TrimSpace(string(data))
			// cgroup v2: "0::/system.slice/docker-xxxxx.scope"
			parts := strings.SplitN(line, "::", 2)
			if len(parts) == 2 && parts[1] != "" {
				cgroupPath = "/sys/fs/cgroup" + parts[1]
				cgroupPath = filepath.Clean(cgroupPath)
			}
		}
	}
	if cgroupPath == "" {
		// Fallback (will likely not work, but prevents crash)
		cgroupPath = "/sys/fs/cgroup/pipejack"
	}
	fmt.Printf("Using cgroup: %s\n", cgroupPath)

	// 1. File system pre‑snapshot
	ignore := []string{"node_modules/", ".git/", "package-lock.json", "package.json"}
	preRoot, preFiles, err := fschecker.BuildMerkleTree(workspace, ignore)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Pre‑snapshot error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Pre‑build Merkle root: %s\n", preRoot.Hash)

	// 2. Start eBPF exec tracepoint (pins ring buffer at /sys/fs/bpf/exec_events)
	execCleanup, execErr := ebpfctrl.StartExecTrace()
	if execErr == nil {
		defer execCleanup()
		fmt.Println("Exec tracepoint active.")
	} else {
		fmt.Fprintf(os.Stderr, "Exec trace error: %v (will use polling fallback)\n", execErr)
	}

	// 3. Start process monitoring (eBPF exec watcher with polling fallback)
	violations := 0
	pidCh := make(chan int, 100)
	stopWatch := make(chan struct{})

	go func() {
		if execErr == nil {
			// Use eBPF ring buffer from pinned map
			if err := proctree.WatchExecs(pidCh, stopWatch); err != nil {
				fmt.Fprintf(os.Stderr, "Exec watcher error: %v\n", err)
			}
		}
		// If exec trace failed or WatchExecs returned, fall back to polling
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopWatch:
				return
			case <-ticker.C:
				v, err := proctree.Run(policyPath)
				if err == nil {
					violations += v
					if v > 0 {
						fmt.Printf("Process violations so far: %d\n", violations)
					}
				}
			}
		}
	}()

	// Process incoming PIDs as they appear
	go func() {
		for pid := range pidCh {
			v, err := proctree.RunOnPID(pid, policyPath)
			if err == nil && v > 0 {
				violations++
				fmt.Printf("Process violation: PID %d\n", pid)
			}
		}
	}()

	// 4. Network interceptor
	allowedIPs := []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("93.184.215.14")}
	nc, err := ebpfctrl.NewNetworkController(cgroupPath, allowedIPs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Network controller error: %v\n", err)
		// Continue without network blocking if it fails
	} else {
		defer nc.Close()
		fmt.Println("Network interceptor active.")
	}

	// 5. Wait for build‑completion signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	fmt.Println("PipeJack daemon running... waiting for build completion signal (SIGTERM/INT).")
	<-sigCh

	// Signal exec watcher to stop
	close(stopWatch)
	time.Sleep(100 * time.Millisecond)

	// Final process scan after build completes
	v, err := proctree.Run(policyPath)
	if err == nil {
		violations += v
		if v > 0 {
			fmt.Printf("Final process violations: %d\n", v)
		}
	}

	// 6. Post‑build file snapshot
	postRoot, postFiles, err := fschecker.BuildMerkleTree(workspace, ignore)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Post‑snapshot error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Post‑build Merkle root: %s\n", postRoot.Hash)

	if preRoot.Hash != postRoot.Hash {
		fmt.Println("Filesystem integrity violated!")
		changes := fschecker.CompareSnapshots(preFiles, postFiles)
		for _, ch := range changes {
			fmt.Printf("  [%s] %s\n", ch.Type, ch.Path)
		}
		os.Exit(1)
	}

	if violations > 0 {
		fmt.Printf("Process violations detected: %d\n", violations)
		os.Exit(1)
	}

	fmt.Println("Build integrity verified. No violations.")
}
