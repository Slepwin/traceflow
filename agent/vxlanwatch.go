package main

import (
	"log"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// vxlanManager attaches eBPF to per-tenant VXLAN netdevs and registers each
// device's VNI in the iface_vni map so observations off that device are tagged.
// Attach/detach is driven by netlink link events, so interfaces created or
// removed by OVN (or any external controller) are followed in real time.
type vxlanManager struct {
	objs     *traceflowObjects
	xdp      bool
	mu       sync.Mutex
	attached map[int]*vxlanAttach
}

type vxlanAttach struct {
	name   string
	detach func()
}

func newVXLANManager(objs *traceflowObjects, xdp bool) *vxlanManager {
	return &vxlanManager{objs: objs, xdp: xdp, attached: map[int]*vxlanAttach{}}
}

func (m *vxlanManager) attach(ifindex int, name string, vni uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.attached[ifindex]; ok {
		return // idempotent: RTM_NEWLINK also fires on up/down/changes
	}
	detach, err := attachIface(m.objs, ifindex, m.xdp)
	if err != nil {
		log.Printf("vxlan: attach %s failed: %v", name, err)
		return
	}
	if err := m.objs.IfaceVni.Put(uint32(ifindex), vni); err != nil {
		log.Printf("vxlan: register VNI for %s: %v", name, err)
	}
	m.attached[ifindex] = &vxlanAttach{name: name, detach: detach}
	mtr.vxlanWatched.Store(int64(len(m.attached)))
	log.Printf("vxlan: attached %s (ifindex=%d vni=%d)", name, ifindex, vni)
}

func (m *vxlanManager) detachIdx(ifindex int, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	att := m.attached[ifindex]
	if att == nil {
		return
	}
	att.detach()
	_ = m.objs.IfaceVni.Delete(uint32(ifindex))
	delete(m.attached, ifindex)
	mtr.vxlanWatched.Store(int64(len(m.attached)))
	log.Printf("vxlan: detached %s (ifindex=%d)", att.name, ifindex)
}

func (m *vxlanManager) closeAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for idx, att := range m.attached {
		att.detach()
		_ = m.objs.IfaceVni.Delete(uint32(idx))
	}
	m.attached = map[int]*vxlanAttach{}
	mtr.vxlanWatched.Store(0)
}

// runVXLANWatcher enumerates existing VXLAN netdevs, then follows netlink link
// events until stopped.
func runVXLANWatcher(stop <-chan struct{}, m *vxlanManager) {
	ch := make(chan netlink.LinkUpdate, 128)
	done := make(chan struct{})
	if err := netlink.LinkSubscribe(ch, done); err != nil {
		log.Printf("vxlan: netlink subscribe failed: %v", err)
		return
	}
	defer close(done)

	// Catch interfaces that already exist at startup.
	if links, err := netlink.LinkList(); err == nil {
		for _, l := range links {
			if isVXLAN(l) {
				a := l.Attrs()
				m.attach(a.Index, a.Name, vxlanVNI(l))
			}
		}
	} else {
		log.Printf("vxlan: initial link list failed: %v", err)
	}

	log.Printf("vxlan watcher up: following netlink link events")
	for {
		select {
		case <-stop:
			m.closeAll()
			return
		case u, ok := <-ch:
			if !ok {
				m.closeAll()
				return
			}
			if u.Link == nil || !isVXLAN(u.Link) {
				continue
			}
			a := u.Link.Attrs()
			if u.Header.Type == unix.RTM_DELLINK {
				m.detachIdx(a.Index, a.Name)
			} else { // RTM_NEWLINK (create or change)
				m.attach(a.Index, a.Name, vxlanVNI(u.Link))
			}
		}
	}
}

func isVXLAN(l netlink.Link) bool { return l.Type() == "vxlan" }

// vxlanVNI reads the fixed device VNI. External/collect_metadata vxlan devices
// carry the VNI per-packet (VxlanId 0 here) and are not covered.
func vxlanVNI(l netlink.Link) uint32 {
	if v, ok := l.(*netlink.Vxlan); ok {
		return uint32(v.VxlanId)
	}
	return 0
}
