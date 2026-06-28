package ebpfctrl

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// StartExecTrace loads the exec_trace.o program, attaches to sys_enter_execve,
// pins the ring buffer map at /sys/fs/bpf/exec_events, and returns a cleanup function.
func StartExecTrace() (func(), error) {
	spec, err := ebpf.LoadCollectionSpec("/app/exec_trace.o")
	if err != nil {
		return nil, fmt.Errorf("load exec_trace spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new collection: %w", err)
	}

	prog := coll.Programs["trace_execve"]
	_, err = link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach tracepoint: %w", err)
	}

	// Pin the ring buffer map
	rbMap := coll.Maps["exec_events"]
	if err := rbMap.Pin("/sys/fs/bpf/exec_events"); err != nil {
		coll.Close()
		return nil, fmt.Errorf("pin ringbuf: %w", err)
	}

	cleanup := func() {
		os.Remove("/sys/fs/bpf/exec_events")
		coll.Close()
	}

	// Keep the tracepoint attached until cleanup is called
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		cleanup()
	}()

	return cleanup, nil
}
