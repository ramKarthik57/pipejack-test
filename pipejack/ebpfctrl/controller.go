package ebpfctrl

import (
	"fmt"
	"net"
	"os"
	"os/exec"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type NetworkController struct {
	cgroupPath string
	useEBPF    bool
	coll       *ebpf.Collection
	link       link.Link
	allowedIPs []net.IP
}

func NewNetworkController(cgroupPath string, allowedIPs []net.IP) (*NetworkController, error) {
	nc := &NetworkController{
		cgroupPath: cgroupPath,
		allowedIPs: allowedIPs,
	}
	// Try eBPF first
	err := nc.tryEBPF()
	if err == nil {
		nc.useEBPF = true
		return nc, nil
	}
	// Fallback to iptables
	fmt.Printf("eBPF unavailable (%v), using iptables fallback\n", err)
	err = nc.setupIptables()
	if err != nil {
		return nil, fmt.Errorf("iptables fallback failed: %w", err)
	}
	return nc, nil
}

func (nc *NetworkController) tryEBPF() error {
	spec, err := ebpf.LoadCollectionSpec("/app/net_block.o")
	if err != nil {
		return err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return err
	}
	ipMap := coll.Maps["allowed_ips"]
	for _, ip := range nc.allowedIPs {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		// Convert IP to 32-bit key in network byte order
		key := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
		val := uint8(1)
		if err := ipMap.Put(&key, &val); err != nil {
			coll.Close()
			return fmt.Errorf("put IP %s: %w", ip, err)
		}
	}
	cgroupFile, err := os.Open(nc.cgroupPath)
	if err != nil {
		coll.Close()
		return err
	}
	defer cgroupFile.Close()
	prog := coll.Programs["block_connect"]
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    nc.cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: prog,
	})
	if err != nil {
		coll.Close()
		return err
	}
	nc.coll = coll
	nc.link = l
	return nil
}

func (nc *NetworkController) setupIptables() error {
	// Add ACCEPT rules for each allowed IP
	for _, ip := range nc.allowedIPs {
		cmd := exec.Command("iptables", "-A", "OUTPUT", "-d", ip.String(), "-j", "ACCEPT")
		if err := cmd.Run(); err != nil {
			// Cleanup already added rules
			nc.cleanupIptables()
			return fmt.Errorf("iptables rule for %s: %w", ip, err)
		}
	}
	return nil
}

func (nc *NetworkController) cleanupIptables() {
	for _, ip := range nc.allowedIPs {
		exec.Command("iptables", "-D", "OUTPUT", "-d", ip.String(), "-j", "ACCEPT").Run()
	}
}

func (nc *NetworkController) Close() {
	if nc.useEBPF {
		if nc.link != nil {
			nc.link.Close()
		}
		if nc.coll != nil {
			nc.coll.Close()
		}
	} else {
		nc.cleanupIptables()
	}
}
