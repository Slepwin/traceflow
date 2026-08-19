package ovs

import (
	"net"
	"testing"
)

func TestParseInterfaces(t *testing.T) {
	data := []byte(`{
	  "data": [
	    ["tap0aaa", ["map", [["attached-mac","52:54:00:aa:bb:01"],["iface-id","lsp-vm1"]]], "52:54:00:aa:bb:01"],
	    ["br-int",  ["map", []], ["set", []]],
	    ["tap0bbb", ["map", [["iface-id","lsp-vm2"]]], "52:54:00:aa:bb:02"]
	  ],
	  "headings": ["name","external_ids","mac_in_use"]
	}`)
	got, err := ParseInterfaces(data)
	if err != nil {
		t.Fatalf("ParseInterfaces: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d ifaces, want 2 (br-int must be skipped): %+v", len(got), got)
	}
	if got[0].Name != "tap0aaa" || got[0].IfaceID != "lsp-vm1" || got[0].MAC != "52:54:00:aa:bb:01" {
		t.Errorf("iface0 = %+v", got[0])
	}
	// tap0bbb has no attached-mac -> mac falls back to mac_in_use.
	if got[1].Name != "tap0bbb" || got[1].IfaceID != "lsp-vm2" || got[1].MAC != "52:54:00:aa:bb:02" {
		t.Errorf("iface1 = %+v", got[1])
	}
}

func TestParseNBAddressesSet(t *testing.T) {
	data := []byte(`{
	  "data": [[["set", ["52:54:00:aa:bb:01 10.0.0.5 fd00::5", "dynamic"]]]],
	  "headings": ["addresses"]
	}`)
	ips, err := ParseNBAddresses(data)
	if err != nil {
		t.Fatalf("ParseNBAddresses: %v", err)
	}
	want := []string{"10.0.0.5", "fd00::5"}
	if len(ips) != len(want) {
		t.Fatalf("got %d IPs, want %d: %v", len(ips), len(want), ips)
	}
	for i, w := range want {
		if !ips[i].Equal(net.ParseIP(w)) {
			t.Errorf("ip[%d] = %v, want %s", i, ips[i], w)
		}
	}
}

func TestParseNBAddressesBareString(t *testing.T) {
	data := []byte(`{"data": [["52:54:00:aa:bb:02 10.0.0.6"]], "headings": ["addresses"]}`)
	ips, err := ParseNBAddresses(data)
	if err != nil {
		t.Fatalf("ParseNBAddresses: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("10.0.0.6")) {
		t.Fatalf("got %v, want [10.0.0.6]", ips)
	}
}

func TestOVSMapAndScalar(t *testing.T) {
	m := ovsMap([]byte(`["map",[["a","1"],["b","2"]]]`))
	if m["a"] != "1" || m["b"] != "2" {
		t.Fatalf("ovsMap = %v", m)
	}
	if ovsScalar([]byte(`"tap0"`)) != "tap0" {
		t.Fatal("ovsScalar bare string")
	}
	if ovsScalar([]byte(`["set",[]]`)) != "" {
		t.Fatal("ovsScalar empty set should be empty")
	}
	if ovsScalar([]byte(`["set",["x"]]`)) != "x" {
		t.Fatal("ovsScalar single-element set")
	}
}
