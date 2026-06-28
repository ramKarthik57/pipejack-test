package proctree

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type ExecEvent struct {
	Pid  uint32
	Comm [16]byte
}

func WatchExecs(pidCh chan<- int, stop <-chan struct{}) error {
	spec, err := ebpf.LoadCollectionSpec("/app/exec_trace.o")
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("new collection: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs["trace_execve"]
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint: %w", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(coll.Maps["exec_events"])
	if err != nil {
		return fmt.Errorf("ringbuf reader: %w", err)
	}
	defer rd.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)

	go func() {
		for {
			select {
			case <-stop:
				return
			case <-sig:
				return
			default:
			}

			record, err := rd.Read()
			if err != nil {
				continue
			}

			var evt ExecEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
				continue
			}

			pidCh <- int(evt.Pid)
		}
	}()

	<-stop
	return nil
}
