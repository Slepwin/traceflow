package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// attachProg attaches the ingress+egress programs to an interface and returns a
// detach closure. It prefers TCX (kernel >= 6.6); when TCX is unsupported it
// falls back to a classic clsact qdisc + cls_bpf filter via netlink, which works
// back to ~4.5. The eBPF bytecode is identical — only the attach mechanism
// differs — because the program touches only stable UAPI (__sk_buff and packet
// bytes), so no CO-RE relocations are needed for cross-kernel portability.
// attachIface attaches the observation program to an interface, choosing the
// XDP hook (for NICs in native/AF_XDP mode, where TC would miss XDP-redirected
// traffic) or the TC hook. Returns a detach closure.
func attachIface(objs *traceflowObjects, ifIndex int, xdp bool) (func(), error) {
	if xdp {
		return attachXDP(objs, ifIndex)
	}
	return attachProg(objs, ifIndex)
}

// attachXDP attaches the XDP program, preferring native (driver) mode and
// falling back to generic (SKB) mode, which works on any netdev (incl. veth).
// XDP is ingress-only — egress is not observed on this hook.
func attachXDP(objs *traceflowObjects, ifIndex int) (func(), error) {
	l, err := link.AttachXDP(link.XDPOptions{
		Program: objs.TraceflowXdp, Interface: ifIndex,
	})
	if err != nil {
		l, err = link.AttachXDP(link.XDPOptions{
			Program: objs.TraceflowXdp, Interface: ifIndex, Flags: link.XDPGenericMode,
		})
		if err != nil {
			return nil, fmt.Errorf("attach xdp: %w", err)
		}
		log.Printf("xdp: native unavailable, using generic (SKB) mode")
	}
	return func() { l.Close() }, nil
}

func attachProg(objs *traceflowObjects, ifIndex int) (func(), error) {
	// Testing knob: exercise the legacy path on a TCX-capable kernel.
	if os.Getenv("TRACEFLOW_FORCE_CLSACT") == "1" {
		log.Printf("TRACEFLOW_FORCE_CLSACT=1: using clsact/cls_bpf")
		return attachClsact(objs, ifIndex)
	}
	detach, err := attachTCX(objs, ifIndex)
	if err == nil {
		return detach, nil
	}
	if !tcxUnsupported(err) {
		return nil, err
	}
	log.Printf("TCX unavailable (%v); falling back to clsact/cls_bpf", err)
	return attachClsact(objs, ifIndex)
}

func tcxUnsupported(err error) bool {
	return errors.Is(err, ebpf.ErrNotSupported) ||
		errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL)
}

// --- TCX (kernel >= 6.6) ----------------------------------------------------

func attachTCX(objs *traceflowObjects, ifIndex int) (func(), error) {
	ingress, err := link.AttachTCX(link.TCXOptions{
		Interface: ifIndex, Program: objs.TraceflowIngress, Attach: ebpf.AttachTCXIngress,
	})
	if err != nil {
		return nil, fmt.Errorf("attach tcx ingress: %w", err)
	}
	egress, err := link.AttachTCX(link.TCXOptions{
		Interface: ifIndex, Program: objs.TraceflowEgress, Attach: ebpf.AttachTCXEgress,
	})
	if err != nil {
		ingress.Close()
		return nil, fmt.Errorf("attach tcx egress: %w", err)
	}
	return func() { egress.Close(); ingress.Close() }, nil
}

// --- classic clsact + cls_bpf (older kernels) -------------------------------

func attachClsact(objs *traceflowObjects, ifIndex int) (func(), error) {
	if err := ensureClsact(ifIndex); err != nil {
		return nil, fmt.Errorf("ensure clsact: %w", err)
	}
	if err := addBPFFilter(ifIndex, netlink.HANDLE_MIN_INGRESS, objs.TraceflowIngress, "traceflow_ig"); err != nil {
		return nil, fmt.Errorf("add ingress filter: %w", err)
	}
	if err := addBPFFilter(ifIndex, netlink.HANDLE_MIN_EGRESS, objs.TraceflowEgress, "traceflow_eg"); err != nil {
		delBPFFilter(ifIndex, netlink.HANDLE_MIN_INGRESS)
		return nil, fmt.Errorf("add egress filter: %w", err)
	}
	return func() {
		delBPFFilter(ifIndex, netlink.HANDLE_MIN_EGRESS)
		delBPFFilter(ifIndex, netlink.HANDLE_MIN_INGRESS)
		// Leave the clsact qdisc: it may be shared with other tools.
	}, nil
}

func ensureClsact(ifIndex int) error {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifIndex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	// Idempotent: replace is a no-op if it already exists.
	return netlink.QdiscReplace(qdisc)
}

// filterPriority is set explicitly so FilterDel matches on teardown (without it
// the kernel auto-assigns a pref that del would not find, leaking the filter).
const filterPriority = 1

func addBPFFilter(ifIndex int, parent uint32, prog *ebpf.Program, name string) error {
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifIndex,
			Parent:    parent,
			Handle:    netlink.MakeHandle(0, 1),
			Priority:  filterPriority,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           prog.FD(),
		Name:         name,
		DirectAction: true,
	}
	return netlink.FilterReplace(filter)
}

func delBPFFilter(ifIndex int, parent uint32) {
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifIndex,
			Parent:    parent,
			Handle:    netlink.MakeHandle(0, 1),
			Priority:  filterPriority,
			Protocol:  unix.ETH_P_ALL,
		},
	}
	if err := netlink.FilterDel(filter); err != nil {
		log.Printf("clsact: remove filter on parent %#x: %v", parent, err)
	}
}
