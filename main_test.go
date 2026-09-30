//go:build linux

package main

// Loads the program into the kernel via ebpf.NewProgram (BPF_PROG_LOAD) and
// runs crafted packets through it with prog.Run (BPF_PROG_TEST_RUN), without
// attaching it to an interface and then checking verdicts, counters and hook
// wiring.

import (
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/xdpcap"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const xdpTX = 3 // stand-in "xdpcap was here" verdict, see attachFakeCapture

func udpPacket(t *testing.T, srcPort, dstPort uint16, payloadLen int) []byte {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.IP{192, 0, 2, 1}, DstIP: net.IP{198, 51, 100, 1},
	}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	err := udp.SetNetworkLayerForChecksum(ip)
	if err != nil {
		t.Fatal(err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(make([]byte, payloadLen))); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type testProg struct {
	prog        *ebpf.Program
	counters    *ebpf.Map
	dropHook    *xdpcap.Hook
	monitorHook *xdpcap.Hook
}

func loadTestProg(t *testing.T, filters []bpfDropFilter) *testProg {
	t.Helper()
	return loadTestProgFor(t, filters, dltEthernet)
}

func loadTestProgFor(t *testing.T, filters []bpfDropFilter, linkType layers.LinkType) *testProg {
	t.Helper()

	dropHook, err := xdpcap.NewHook("/sys/fs/bpf/test_drop") // not pinned
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cErr := dropHook.Close()
		if cErr != nil {
			t.Log("closing drophook failed", cErr)
		}
	})

	monitorHook, err := xdpcap.NewHook("/sys/fs/bpf/test_monitor")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cErr := monitorHook.Close()
		if cErr != nil {
			t.Log("closing monitorHook failed", cErr)
		}
	})

	counters, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8,
		MaxEntries: uint32(max(len(filters), 1)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cErr := counters.Close()
		if cErr != nil {
			t.Log("closing counters failed", err)
		}
	})

	insns, err := buildProgram(filters, linkType, dropHook.Map(), monitorHook.Map(), counters)
	if err != nil {
		t.Fatal(err)
	}

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.XDP, License: "GPL", Instructions: insns,
	})
	if err != nil {
		t.Fatalf("loading: %+v", err)
	}
	t.Cleanup(func() {
		cErr := prog.Close()
		if cErr != nil {
			t.Log("prog close failed", cErr)
		}
	})

	return &testProg{prog, counters, dropHook, monitorHook}
}

func (p *testProg) run(t *testing.T, pkt []byte) uint32 {
	t.Helper()
	ret, err := p.prog.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatal(err)
	}
	return ret
}

func (p *testProg) count(t *testing.T, rule int) uint64 {
	t.Helper()
	var perCPU []uint64
	if err := p.counters.Lookup(uint32(rule), &perCPU); err != nil {
		t.Fatal(err)
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total
}

// attachFakeCapture puts a program returning XDP_TX into hook's slot for
// action, standing in for the capture program xdpcap would install there.
// XDP_TX is just a valid action other than XDP_PASS or XDP_DROP, so a test
// getting XDP_TX back knows the packet exited through this hook rather than
// falling through the empty slot.
func attachFakeCapture(t *testing.T, hook *xdpcap.Hook, action uint32) {
	t.Helper()
	fake, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.XDP, License: "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, xdpTX),
			asm.Return(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cErr := fake.Close()
		if cErr != nil {
			t.Log("closing fake failed", cErr)
		}
	})

	if err := hook.Map().Put(action, fake); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		dErr := hook.Map().Delete(action)
		if dErr != nil {
			t.Log("deleting action from hook map failed", dErr)
		}
	})
}

var testFilters = []bpfDropFilter{
	{Description: "udp-9999", Expr: "udp dst port 9999"},
	{Description: "dns-amp", Expr: "udp src port 53 and len > 1000", Monitor: true},
}

func TestVerdictsAndCounters(t *testing.T) {
	p := loadTestProg(t, testFilters)

	if got := p.run(t, udpPacket(t, 1234, 9999, 10)); got != xdpDrop {
		t.Errorf("udp to 9999: got %d, want XDP_DROP", got)
	}
	if got := p.run(t, udpPacket(t, 53, 4321, 1200)); got != xdpPass {
		t.Errorf("large DNS response (monitor rule): got %d, want XDP_PASS", got)
	}
	if got := p.run(t, udpPacket(t, 53, 4321, 100)); got != xdpPass {
		t.Errorf("small DNS response: got %d, want XDP_PASS", got)
	}
	if got := p.run(t, udpPacket(t, 1234, 80, 10)); got != xdpPass {
		t.Errorf("unrelated packet: got %d, want XDP_PASS", got)
	}

	if got := p.count(t, 0); got != 1 {
		t.Errorf("udp-9999 counter: got %d, want 1", got)
	}
	if got := p.count(t, 1); got != 1 {
		t.Errorf("dns-amp counter: got %d, want 1", got)
	}
}

func TestDropHook(t *testing.T) {
	p := loadTestProg(t, testFilters)
	attachFakeCapture(t, p.dropHook, xdpDrop)

	if got := p.run(t, udpPacket(t, 1234, 9999, 10)); got != xdpTX {
		t.Errorf("dropped packet didn't exit through drop hook: got %d", got)
	}
	if got := p.run(t, udpPacket(t, 1234, 80, 10)); got != xdpPass {
		t.Errorf("passed packet went through drop hook: got %d", got)
	}
}

func TestMonitorHook(t *testing.T) {
	p := loadTestProg(t, testFilters)
	attachFakeCapture(t, p.monitorHook, xdpPass)

	if got := p.run(t, udpPacket(t, 53, 4321, 1200)); got != xdpTX {
		t.Errorf("monitor match didn't exit through monitor hook: got %d", got)
	}
	if got := p.run(t, udpPacket(t, 53, 4321, 100)); got != xdpPass {
		t.Errorf("non-matching packet went through monitor hook: got %d", got)
	}
}

// A packet matching a monitor rule and a later enforcing rule is dropped,
// and exits through the drop hook, not the monitor hook.
func TestMonitorThenDrop(t *testing.T) {
	p := loadTestProg(t, []bpfDropFilter{
		{Description: "watch-53", Expr: "udp src port 53", Monitor: true},
		{Description: "drop-9999", Expr: "udp dst port 9999"},
	})
	attachFakeCapture(t, p.monitorHook, xdpPass)

	if got := p.run(t, udpPacket(t, 53, 9999, 10)); got != xdpDrop {
		t.Errorf("got %d, want XDP_DROP via plain drop exit", got)
	}
	if got := p.count(t, 0); got != 1 {
		t.Errorf("monitor counter: got %d, want 1", got)
	}
}

func TestNoRules(t *testing.T) {
	p := loadTestProg(t, nil)
	if got := p.run(t, udpPacket(t, 1234, 80, 10)); got != xdpPass {
		t.Errorf("got %d, want XDP_PASS", got)
	}
}

func TestOnlyMonitorRules(t *testing.T) {
	p := loadTestProg(t, []bpfDropFilter{{Description: "watch-53", Expr: "udp src port 53", Monitor: true}})
	if got := p.run(t, udpPacket(t, 53, 4321, 10)); got != xdpPass {
		t.Errorf("got %d, want XDP_PASS", got)
	}
}

func TestOnlyDropRules(t *testing.T) {
	p := loadTestProg(t, []bpfDropFilter{{Description: "drop-9999", Expr: "udp dst port 9999"}})
	if got := p.run(t, udpPacket(t, 1234, 9999, 10)); got != xdpDrop {
		t.Errorf("got %d, want XDP_DROP", got)
	}
}

func TestReadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	content := `
{
  "interfaces": {
    "lo": {
      "bpf_drop_filters": [
        {
          "description": "Drop some UDP port 9999",
          "expr": "udp dst port 9999"
        },
        {
          "description": "Monitor some large DNS responses",
          "expr": "udp src port 53 and len > 1000",
          "monitor": true
        }
      ]
    },
    "ens3": {
      "bpf_drop_filters": [
        {
          "description": "Drop some TCP port 1337",
          "expr": "tcp dst port 1337"
        },
        {
          "description": "Monitor some UDP port 9998",
          "expr": "udp dst port 9998",
          "monitor": true
        }
      ]
    }
  }
}
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	xd, err := newXdpd(path, logger)
	if err != nil {
		t.Fatal(err)
	}

	conf := xd.getConf()
	want := map[string][]bpfDropFilter{
		"lo": {
			{Description: "Drop some UDP port 9999", Expr: "udp dst port 9999"},
			{Description: "Monitor some large DNS responses", Expr: "udp src port 53 and len > 1000", Monitor: true},
		},
		"ens3": {
			{Description: "Drop some TCP port 1337", Expr: "tcp dst port 1337"},
			{Description: "Monitor some UDP port 9998", Expr: "udp dst port 9998", Monitor: true},
		},
	}
	if len(conf.Interfaces) != len(want) {
		t.Fatalf("got %d interface, want %d", len(conf.Interfaces), len(want))
	}

	for wantIfname, wantBFDFilters := range want {
		if _, found := conf.Interfaces[wantIfname]; !found {
			t.Fatalf("unable to find expcted interface name: %s", wantIfname)
		}
		for i, wantBFDFilter := range wantBFDFilters {
			if conf.Interfaces[wantIfname].BPFDropFilters[i] != wantBFDFilter {
				t.Errorf("rule %d: got %+v, want %+v", i, conf.Interfaces[wantIfname].BPFDropFilters[i], wantBFDFilter)
			}
		}
	}
}

// rawUDPPacket is udpPacket without the Ethernet header, as XDP sees it on
// tun or WireGuard devices.
func rawUDPPacket(t *testing.T, srcPort, dstPort uint16) []byte {
	t.Helper()
	return udpPacket(t, srcPort, dstPort, 10)[14:]
}

func TestRawLinkType(t *testing.T) {
	rules := []bpfDropFilter{{Description: "udp-9999", Expr: "udp dst port 9999"}}

	raw := loadTestProgFor(t, rules, dltRaw)
	if got := raw.run(t, rawUDPPacket(t, 1234, 9999)); got != xdpDrop {
		t.Errorf("raw rules, raw packet to 9999: got %d, want XDP_DROP", got)
	}
	if got := raw.run(t, rawUDPPacket(t, 1234, 80)); got != xdpPass {
		t.Errorf("raw rules, raw packet to 80: got %d, want XDP_PASS", got)
	}

	// Ethernet rules on a raw packet read every field 14 bytes off: no error, no match.
	eth := loadTestProg(t, rules)
	if got := eth.run(t, rawUDPPacket(t, 1234, 9999)); got != xdpPass {
		t.Errorf("ethernet rules, raw packet: got %d, expected a silent miss (XDP_PASS)", got)
	}
}

func TestLinkTypeFor(t *testing.T) {
	if lt, err := linkTypeFor("lo"); err != nil || lt != dltEthernet {
		t.Errorf("lo: got %v, %v; want Ethernet", lt, err)
	}
	if _, err := linkTypeFor("does-not-exist0"); err == nil {
		t.Error("expected an error for a missing interface")
	}
}
