package main

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"github.com/traceflow/traceflow/internal/ovs"
)

// tapAttachment holds the cleanup for one attached tap: the eBPF detach closure
// and an optional per-VM responder.
type tapAttachment struct {
	detach func()
	resp   *responder
}

type tapManager struct {
	objs       *traceflowObjects
	ifType     uint8
	respond    bool
	tcpRespond bool
	hmacKey    []byte
	xdp        bool
	mu         sync.Mutex
	attached   map[string]*tapAttachment
}

func newTapManager(objs *traceflowObjects, ifType uint8, respond, tcpRespond bool, hmacKey []byte, xdp bool) *tapManager {
	return &tapManager{
		objs: objs, ifType: ifType, respond: respond, tcpRespond: tcpRespond, hmacKey: hmacKey, xdp: xdp,
		attached: map[string]*tapAttachment{},
	}
}

// reconcile attaches new taps and detaches vanished ones.
func (m *tapManager) reconcile(ports []ovs.Port) {
	m.mu.Lock()
	defer m.mu.Unlock()

	seen := make(map[string]bool, len(ports))
	for _, p := range ports {
		seen[p.Name] = true
		if _, ok := m.attached[p.Name]; ok {
			continue
		}
		if err := m.attachLocked(p); err != nil {
			log.Printf("watch: attach %s failed: %v", p.Name, err)
		}
	}
	for name := range m.attached {
		if !seen[name] {
			m.detachLocked(name)
		}
	}
	mtr.tapsWatched.Store(int64(len(m.attached)))
}

func (m *tapManager) attachLocked(p ovs.Port) error {
	iface, err := net.InterfaceByName(p.Name)
	if err != nil {
		return err
	}
	detach, err := attachIface(m.objs, iface.Index, m.xdp)
	if err != nil {
		return err
	}
	att := &tapAttachment{detach: detach}
	if m.respond && len(p.IPs) > 0 {
		r, err := newResponder(iface, m.ifType, p.IPs, m.tcpRespond, m.hmacKey)
		if err != nil {
			log.Printf("watch: responder for %s: %v", p.Name, err)
		} else {
			go r.Loop()
			att.resp = r
		}
	}
	m.attached[p.Name] = att
	log.Printf("watch: attached tap %s (ips=%v)", p.Name, p.IPs)
	return nil
}

func (m *tapManager) detachLocked(name string) {
	att := m.attached[name]
	if att == nil {
		return
	}
	if att.detach != nil {
		att.detach()
	}
	if att.resp != nil {
		att.resp.Close()
	}
	delete(m.attached, name)
	log.Printf("watch: detached tap %s", name)
}

func (m *tapManager) closeAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name := range m.attached {
		m.detachLocked(name)
	}
}

// runWatcher periodically re-scans OVS and reconciles attachments until stopped.
func runWatcher(stop <-chan struct{}, m *tapManager, interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	reconcileOnce(m)
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			reconcileOnce(m)
		}
	}
}

func reconcileOnce(m *tapManager) {
	ports, err := ovs.DiscoverPorts(context.Background())
	if err != nil {
		log.Printf("watch: discovery failed (is ovs-vsctl present?): %v", err)
		return
	}
	m.reconcile(ports)
}
