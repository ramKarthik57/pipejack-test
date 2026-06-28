package proctree

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
        "unsafe"
)

// WatchProcDir monitors /proc for new PIDs (inotify) and sends them to the channel.
func WatchProcDir(pidCh chan<- int, stop <-chan struct{}) error {
	inotifyFd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC)
	if err != nil {
		return fmt.Errorf("inotify_init: %w", err)
	}
	defer syscall.Close(inotifyFd)

	_, err = syscall.InotifyAddWatch(inotifyFd, "/proc", syscall.IN_CREATE|syscall.IN_ISDIR)
	if err != nil {
		return fmt.Errorf("inotify_add_watch: %w", err)
	}

	buf := make([]byte, 4096)
	for {
		select {
		case <-stop:
			return nil
		default:
			n, err := syscall.Read(inotifyFd, buf)
			if err != nil {
				// Temporary error, sleep a bit
				time.Sleep(10 * time.Millisecond)
				continue
			}
			if n == 0 {
				continue
			}
			// Parse inotify events (simplified: we just look for directory names that are numbers)
			raw := buf[:n]
			for i := 0; i < n; {
				// Each event is syscall.InotifyEvent
				event := (*syscall.InotifyEvent)(unsafe.Pointer(&raw[i]))
				nameBytes := raw[i+syscall.SizeofInotifyEvent : i+syscall.SizeofInotifyEvent+int(event.Len)]
				name := strings.TrimRight(string(nameBytes), "\x00")
				if name != "" {
					if pid, err := strconv.Atoi(name); err == nil {
						// Verify the directory still exists (process might be gone)
						if _, err := os.Stat(filepath.Join("/proc", name, "exe")); err == nil {
							select {
							case pidCh <- pid:
							default:
								// Channel full, skip (unlikely)
							}
						}
					}
				}
				i += syscall.SizeofInotifyEvent + int(event.Len)
			}
		}
	}
}
