//go:build linux

package main

// Loads the program into the kernel via ebpf.NewProgram (BPF_PROG_LOAD) and
// runs crafted packets through it with prog.Run (BPF_PROG_TEST_RUN), without
// attaching it to an interface and then checking verdicts, counters and hook
// wiring.

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
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
			t.Log("closing counters failed", cErr)
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

func (p *testProg) count(t *testing.T, index int) uint64 {
	t.Helper()
	var perCPU []uint64
	if err := p.counters.Lookup(uint32(index), &perCPU); err != nil {
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
		t.Errorf("large DNS response (monitor filter): got %d, want XDP_PASS", got)
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

// A packet matching a monitor filter and a later dropping filter is dropped,
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

func TestNoFilters(t *testing.T) {
	p := loadTestProg(t, nil)
	if got := p.run(t, udpPacket(t, 1234, 80, 10)); got != xdpPass {
		t.Errorf("got %d, want XDP_PASS", got)
	}
}

func TestOnlyMonitorFilters(t *testing.T) {
	p := loadTestProg(t, []bpfDropFilter{{Description: "watch-53", Expr: "udp src port 53", Monitor: true}})
	if got := p.run(t, udpPacket(t, 53, 4321, 10)); got != xdpPass {
		t.Errorf("got %d, want XDP_PASS", got)
	}
}

func TestOnlyDropFilters(t *testing.T) {
	p := loadTestProg(t, []bpfDropFilter{{Description: "drop-9999", Expr: "udp dst port 9999"}})
	if got := p.run(t, udpPacket(t, 1234, 9999, 10)); got != xdpDrop {
		t.Errorf("got %d, want XDP_DROP", got)
	}
}

// writeConfDir creates a config directory holding files (name -> content).
func writeConfDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const goodConf = `{"interfaces": {"lo": {"bpf_drop_filters": [{"description": "Drop some UDP port 9999", "expr": "udp dst port 9999"}]}}}`

func wantInterfaces(t *testing.T, conf config, want map[string][]bpfDropFilter) {
	t.Helper()
	got := map[string][]bpfDropFilter{}
	for ifname, ifConf := range conf.Interfaces {
		got[ifname] = ifConf.BPFDropFilters
	}
	if !maps.EqualFunc(got, want, slices.Equal) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestReadConfig(t *testing.T) {
	dir := writeConfDir(t, map[string]string{
		"00-base.json": `
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
        }
      ]
    }
  }
}
`,
		"50-ddos.json": `
{
  "interfaces": {
    "lo": {
      "bpf_drop_filters": [
        {
          "description": "Drop a flood",
          "expr": "udp dst port 4444"
        }
      ]
    }
  }
}
`,
	})

	conf, err := readConf(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Filters for one interface are appended in file name order.
	wantInterfaces(t, conf, map[string][]bpfDropFilter{
		"lo": {
			{Description: "Drop some UDP port 9999", Expr: "udp dst port 9999", source: "00-base.json"},
			{Description: "Monitor some large DNS responses", Expr: "udp src port 53 and len > 1000", Monitor: true, source: "00-base.json"},
			{Description: "Drop a flood", Expr: "udp dst port 4444", source: "50-ddos.json"},
		},
		"ens3": {
			{Description: "Drop some TCP port 1337", Expr: "tcp dst port 1337", source: "00-base.json"},
		},
	})
	if want := []string{"00-base.json", "50-ddos.json"}; !slices.Equal(conf.files, want) {
		t.Errorf("files: got %v, want %v", conf.files, want)
	}
}

// rawUDPPacket is udpPacket without the Ethernet header, as XDP sees it on
// tun or WireGuard devices.
func rawUDPPacket(t *testing.T, srcPort, dstPort uint16) []byte {
	t.Helper()
	return udpPacket(t, srcPort, dstPort, 10)[14:]
}

func TestRawLinkType(t *testing.T) {
	bpfDropFilters := []bpfDropFilter{{Description: "udp-9999", Expr: "udp dst port 9999"}}

	raw := loadTestProgFor(t, bpfDropFilters, dltRaw)
	if got := raw.run(t, rawUDPPacket(t, 1234, 9999)); got != xdpDrop {
		t.Errorf("raw link type filters, raw packet to 9999: got %d, want XDP_DROP", got)
	}
	if got := raw.run(t, rawUDPPacket(t, 1234, 80)); got != xdpPass {
		t.Errorf("raw link type filters, raw packet to 80: got %d, want XDP_PASS", got)
	}

	// Ethernet link type filters on a raw packet read every field 14 bytes off: no error, no match.
	eth := loadTestProg(t, bpfDropFilters)
	if got := eth.run(t, rawUDPPacket(t, 1234, 9999)); got != xdpPass {
		t.Errorf("ethernet link type filters, raw packet: got %d, expected a silent miss (XDP_PASS)", got)
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

// Temp files written before a rename, editor and package manager leftovers,
// other suffixes and directories are not config, even when they look broken.
func TestReadConfigIgnores(t *testing.T) {
	broken := `{"interfaces": {`
	dir := writeConfDir(t, map[string]string{
		"00-base.json":          goodConf,
		".50-ddos.json.tmp":     broken,
		".50-ddos.json.swp":     broken,
		".hidden.json":          broken,
		"50-ddos.json~":         broken,
		"50-ddos.json.bak":      broken,
		"50-ddos.json.dpkg-old": broken,
		"README":                broken,
	})
	if err := os.Mkdir(filepath.Join(dir, "sub.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub.json", "inner.json"), []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}

	conf, err := readConf(dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"00-base.json"}; !slices.Equal(conf.files, want) {
		t.Errorf("files: got %v, want %v", conf.files, want)
	}
}

// Names are sorted as strings, not numbers, as documented.
func TestReadConfigOrderIsByName(t *testing.T) {
	dir := writeConfDir(t, map[string]string{
		"9-a.json":  `{"interfaces": {"lo": {"bpf_drop_filters": [{"description": "a", "expr": "udp dst port 1"}]}}}`,
		"10-b.json": `{"interfaces": {"lo": {"bpf_drop_filters": [{"description": "b", "expr": "udp dst port 2"}]}}}`,
	})
	conf, err := readConf(dir)
	if err != nil {
		t.Fatal(err)
	}
	wantInterfaces(t, conf, map[string][]bpfDropFilter{
		"lo": {
			{Description: "b", Expr: "udp dst port 2", source: "10-b.json"},
			{Description: "a", Expr: "udp dst port 1", source: "9-a.json"},
		},
	})
}

func TestReadConfigSymlinks(t *testing.T) {
	// To a file in the directory: read, under the link's name.
	dir := writeConfDir(t, map[string]string{"base.conf": goodConf})
	if err := os.Symlink("base.conf", filepath.Join(dir, "00-base.json")); err != nil {
		t.Fatal(err)
	}
	conf, err := readConf(dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"00-base.json"}; !slices.Equal(conf.files, want) {
		t.Errorf("files: got %v, want %v", conf.files, want)
	}

	// Out of the directory: the whole read fails.
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte(goodConf), 0o600); err != nil {
		t.Fatal(err)
	}
	dir = writeConfDir(t, map[string]string{"00-base.json": goodConf})
	if err := os.Symlink(outside, filepath.Join(dir, "50-outside.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := readConf(dir); err == nil || !strings.Contains(err.Error(), "50-outside.json") {
		t.Errorf("got %v, want an error about 50-outside.json", err)
	}
}

// An interface without filters in one file doesn't affect its filters from
// another, and one that only appears without filters is still configured.
// A file with just {} is fine and adds nothing.
func TestReadConfigEmptyInterface(t *testing.T) {
	dir := writeConfDir(t, map[string]string{
		"00-base.json":  `{"interfaces": {"lo": {}}}`,
		"50-ddos.json":  goodConf,
		"60-ens3.json":  `{"interfaces": {"ens3": {"bpf_drop_filters": []}}}`,
		"70-empty.json": `{}`,
	})
	conf, err := readConf(dir)
	if err != nil {
		t.Fatal(err)
	}
	wantInterfaces(t, conf, map[string][]bpfDropFilter{
		"lo":   {{Description: "Drop some UDP port 9999", Expr: "udp dst port 9999", source: "50-ddos.json"}},
		"ens3": nil,
	})
	if want := []string{"00-base.json", "50-ddos.json", "60-ens3.json", "70-empty.json"}; !slices.Equal(conf.files, want) {
		t.Errorf("files: got %v, want %v", conf.files, want)
	}
}

func TestReadConfigDuplicateAcrossFiles(t *testing.T) {
	dir := writeConfDir(t, map[string]string{
		"00-base.json": goodConf,
		"50-ddos.json": goodConf,
	})
	conf, err := readConf(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := `lo: filter "Drop some UDP port 9999" in 50-ddos.json duplicates the one in 00-base.json`
	if err := conf.validate(); err == nil || err.Error() != want {
		t.Errorf("got %v, want %q", err, want)
	}
}

func TestConfigFileCounts(t *testing.T) {
	dir := writeConfDir(t, map[string]string{
		"00-base.json": `{"interfaces": {
			"lo": {"bpf_drop_filters": [{"description": "a", "expr": "udp dst port 1"}]},
			"ens3": {"bpf_drop_filters": [{"description": "b", "expr": "udp dst port 2"}]}
		}}`,
		"50-ddos.json":  goodConf,
		"60-empty.json": `{}`,
	})
	conf, err := readConf(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"00-base.json": 2, "50-ddos.json": 1, "60-empty.json": 0}
	if got := conf.fileCounts(); !maps.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReadConfigInvalid(t *testing.T) {
	if _, err := readConf(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("expected an error for a missing directory")
	}

	for _, tc := range []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"no json files", map[string]string{"README": "x", ".00-base.json.tmp": goodConf}, "no *.json config files in "},
		{"broken json", map[string]string{"00-base.json": goodConf, "50-ddos.json": `{"interfaces": {`}, "parsing 50-ddos.json: "},
		{"zero bytes", map[string]string{"50-ddos.json": ""}, "parsing 50-ddos.json: jsontext: unexpected EOF"},
		{"unknown top level field", map[string]string{"50-ddos.json": `{"interface": {}}`}, `unknown object member name "interface"`},
		{"typo in a filter", map[string]string{"50-ddos.json": `{"interfaces": {"lo": {"bpf_drop_filters": [{"description": "d", "expr": "udp", "monitr": true}]}}}`}, `unknown object member name "monitr" within "/interfaces/lo/bpf_drop_filters/0"`},
		// v1 matched names ignoring case; v2 doesn't, so this is an unknown field.
		{"wrong case", map[string]string{"50-ddos.json": `{"interfaces": {"lo": {"bpf_drop_filters": [{"description": "d", "expr": "udp", "Monitor": true}]}}}`}, `unknown object member name "Monitor"`},
		{"field twice in a filter", map[string]string{"50-ddos.json": `{"interfaces": {"lo": {"bpf_drop_filters": [{"description": "d", "expr": "udp", "expr": "tcp"}]}}}`}, `duplicate object member name "expr"`},
		// v1 would silently keep only the last one, losing the first one's filters.
		{"interface twice in a file", map[string]string{"50-ddos.json": `{"interfaces": {"lo": {}, "lo": {}}}`}, `duplicate object member name "lo" within "/interfaces"`},
		{"trailing data", map[string]string{"50-ddos.json": `{} {}`}, "parsing 50-ddos.json: jsontext: invalid character '{' after top-level value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readConf(writeConfDir(t, tc.files))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

// The sample directory stays loadable as the docs point at it.
func TestSampleConfig(t *testing.T) {
	conf, err := readConf("conf.d.sample")
	if err != nil {
		t.Fatal(err)
	}
	if err := conf.validate(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"00-base.json", "50-ddos.json"}; !slices.Equal(conf.files, want) {
		t.Errorf("files: got %v, want %v", conf.files, want)
	}
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to load and attach BPF programs")
	}
}

// newDummyInterface creates a dummy interface for a test to attach to and
// removes it when the test is done. The tests do not use a real interface like
// lo, since something else (like a running sunet-xdpd) may have a filter
// attached to it and XDP does not allow two.
func newDummyInterface(t *testing.T, suffix string) string {
	t.Helper()

	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("needs the ip command (iproute2) to create a dummy interface")
	}

	// Interface names can be at most 15 characters, so the pid is cut to 5
	// digits to leave room for a suffix.
	ifname := fmt.Sprintf("xdpdtest%d%s", os.Getpid()%100000, suffix)
	if out, err := exec.Command("ip", "link", "add", ifname, "type", "dummy").CombinedOutput(); err != nil {
		t.Fatalf("creating dummy interface %s: %v: %s", ifname, err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("ip", "link", "del", ifname).CombinedOutput(); err != nil {
			t.Errorf("removing dummy interface %s: %v: %s", ifname, err, out)
		}
	})
	return ifname
}

// newTestXdpd returns an xdpd pinning under its own directory in bpffs, and the
// name of a dummy interface to use with it. Whatever is attached or pinned is
// detached and removed when the test is done.
func newTestXdpd(t *testing.T) (*xdpd, string) {
	t.Helper()

	ifname := newDummyInterface(t, "a")

	pinDir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("sunet-xdpd-test-%d", os.Getpid()))
	if err := os.MkdirAll(pinDir, 0o700); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	xd := newXdpd("unused", pinDir, logger)
	t.Cleanup(func() {
		if err := unloadAll(logger, pinDir); err != nil {
			t.Error("unloadAll:", err)
		}
		for _, f := range xd.filters {
			if err := f.Close(); err != nil {
				t.Log("closing filter failed", err)
			}
		}
	})
	return xd, ifname
}

func confFor(ifname string, bpfDropFilters ...bpfDropFilter) config {
	return config{Interfaces: map[string]interfaceConfig{ifname: {BPFDropFilters: bpfDropFilters}}}
}

// liveProg returns the IDs of the link on f and of the program it runs.
func liveProg(t *testing.T, f *filter) (link.ID, ebpf.ProgramID) {
	t.Helper()
	info, err := f.link.Info()
	if err != nil {
		t.Fatal(err)
	}
	return info.ID, info.Program
}

func TestApplyFailsOnMissingInterface(t *testing.T) {
	xd := newXdpd("unused", t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	err := xd.apply(config{Interfaces: map[string]interfaceConfig{"does-not-exist0": {}}})
	if err == nil {
		t.Fatal("expected an error for a missing interface")
	}
	if len(xd.filters) != 0 {
		t.Errorf("got %d filters after a failed apply, want 0", len(xd.filters))
	}
}

func TestApplyBadConfigKeepsRunning(t *testing.T) {
	requireRoot(t)
	xd, ifname := newTestXdpd(t)

	if err := xd.apply(confFor(ifname, bpfDropFilter{Description: "good", Expr: "udp dst port 9999"})); err != nil {
		t.Fatal(err)
	}
	f := xd.filters[ifname]
	linkID, progID := liveProg(t, f)

	err := xd.apply(confFor(
		ifname,
		bpfDropFilter{Description: "good", Expr: "udp dst port 9999"},
		bpfDropFilter{Description: "bad", Expr: "this is ((not a filter"},
	))
	if err == nil {
		t.Fatal("expected an error for an invalid expression")
	}

	if xd.filters[ifname] != f {
		t.Error("the filter was replaced by a failed apply")
	}
	if gotLink, gotProg := liveProg(t, f); gotLink != linkID || gotProg != progID {
		t.Errorf("failed apply changed what is attached: link %d -> %d, prog %d -> %d", linkID, gotLink, progID, gotProg)
	}
	if len(f.bpfDropFilters) != 1 {
		t.Errorf("got %d filters recorded for the running program, want 1", len(f.bpfDropFilters))
	}
}

func TestApplyUpdatesInPlace(t *testing.T) {
	requireRoot(t)
	xd, ifname := newTestXdpd(t)

	if err := xd.apply(confFor(ifname, bpfDropFilter{Description: "one", Expr: "udp dst port 9999"})); err != nil {
		t.Fatal(err)
	}
	f := xd.filters[ifname]
	linkID, progID := liveProg(t, f)

	if err := xd.apply(confFor(
		ifname,
		bpfDropFilter{Description: "one", Expr: "udp dst port 9999"},
		bpfDropFilter{Description: "two", Expr: "udp dst port 9998", Monitor: true},
	)); err != nil {
		t.Fatal(err)
	}

	gotLink, gotProg := liveProg(t, f)
	if gotLink != linkID {
		t.Errorf("link was replaced: %d -> %d", linkID, gotLink)
	}
	if gotProg == progID {
		t.Error("program was not replaced")
	}
	if len(f.bpfDropFilters) != 2 {
		t.Errorf("got %d filters, want 2", len(f.bpfDropFilters))
	}
}

func TestApplyRemovedInterface(t *testing.T) {
	requireRoot(t)
	xd, ifname := newTestXdpd(t)

	if err := xd.apply(confFor(ifname, bpfDropFilter{Description: "one", Expr: "udp dst port 9999"})); err != nil {
		t.Fatal(err)
	}
	for _, kind := range pinKinds {
		if _, err := os.Stat(pinPath(xd.pinDir, ifname, kind)); err != nil {
			t.Errorf("expected a %s pin after apply: %v", kind, err)
		}
	}

	if err := xd.apply(config{}); err != nil {
		t.Fatal(err)
	}

	if len(xd.filters) != 0 {
		t.Errorf("got %d filters, want 0", len(xd.filters))
	}
	entries, err := os.ReadDir(xd.pinDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("pin left behind: %s", e.Name())
	}
}

// A new process takes over what the previous one left pinned.
func TestApplyTakesOverPinnedLink(t *testing.T) {
	requireRoot(t)
	first, ifname := newTestXdpd(t)

	if err := first.apply(confFor(ifname, bpfDropFilter{Description: "one", Expr: "udp dst port 9999"})); err != nil {
		t.Fatal(err)
	}
	linkID, _ := liveProg(t, first.filters[ifname])

	second := newXdpd("unused", first.pinDir, first.logger)
	if err := second.apply(confFor(ifname, bpfDropFilter{Description: "two", Expr: "udp dst port 9998"})); err != nil {
		t.Fatal(err)
	}
	f := second.filters[ifname]
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Log("closing filter failed", err)
		}
	})

	if gotLink, _ := liveProg(t, f); gotLink != linkID {
		t.Errorf("took over a different link: %d, want %d", gotLink, linkID)
	}
}

func TestUnloadAllWithoutConfig(t *testing.T) {
	requireRoot(t)
	xd, ifname := newTestXdpd(t)

	if err := xd.apply(confFor(ifname, bpfDropFilter{Description: "one", Expr: "udp dst port 9999"})); err != nil {
		t.Fatal(err)
	}

	// No config involved: it goes by what is pinned.
	if err := unloadAll(xd.logger, xd.pinDir); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(xd.pinDir); !os.IsNotExist(err) {
		t.Errorf("pin dir still exists: %v", err)
	}
	if !xd.filters[ifname].unloaded() {
		t.Error("the running daemon would not notice it was unloaded")
	}
}

func TestUnloadAllNothingPinned(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := unloadAll(logger, filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Errorf("missing dir: %v", err)
	}

	empty := t.TempDir()
	if err := unloadAll(logger, empty); err != nil {
		t.Errorf("empty dir: %v", err)
	}
	if _, err := os.Stat(empty); !os.IsNotExist(err) {
		t.Error("expected the pin dir to be removed")
	}
}

// filterHits returns what prometheus would report for bpfDropFilter on ifname.
func filterHits(t *testing.T, xd *xdpd, ifname string, bdf bpfDropFilter) float64 {
	t.Helper()

	families, err := xd.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "filter_packets_total" {
			continue
		}
		for _, m := range family.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["iface"] == ifname && labels["description"] == bdf.Description {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// sendUDP9999 runs n packets matching "udp dst port 9999" through the program
// of f, as if they had arrived on the interface.
func sendUDP9999(t *testing.T, f *filter, n int) {
	t.Helper()

	for range n {
		ret, err := f.prog.Run(&ebpf.RunOptions{Data: udpPacket(t, 1234, 9999, 10)})
		if err != nil {
			t.Fatal(err)
		}
		if ret != xdpDrop {
			t.Fatalf("got %d, want XDP_DROP", ret)
		}
	}
}

// What the old program counted since the last updateMetrics must not be lost
// when a reload replaces it (and its counters).
func TestApplyKeepsCountsOfReplacedProgram(t *testing.T) {
	requireRoot(t)
	xd, ifname := newTestXdpd(t)

	drop := bpfDropFilter{Description: "one", Expr: "udp dst port 9999"}
	if err := xd.apply(confFor(ifname, drop)); err != nil {
		t.Fatal(err)
	}
	sendUDP9999(t, xd.filters[ifname], 3)

	// No updateMetrics in between, like for packets arriving while apply runs.
	if err := xd.apply(confFor(ifname, drop, bpfDropFilter{Description: "two", Expr: "udp dst port 9998"})); err != nil {
		t.Fatal(err)
	}
	if got := filterHits(t, xd, ifname, drop); got != 3 {
		t.Errorf("after reload: got %v hits, want 3", got)
	}

	// The new program starts from zero, and must not be counted on top of the old one.
	xd.updateMetrics()
	if got := filterHits(t, xd, ifname, drop); got != 3 {
		t.Errorf("after updateMetrics: got %v hits, want 3", got)
	}

	sendUDP9999(t, xd.filters[ifname], 2)
	xd.updateMetrics()
	if got := filterHits(t, xd, ifname, drop); got != 5 {
		t.Errorf("after more packets: got %v hits, want 5", got)
	}
}

// The same goes for an interface that is removed from the config.
func TestApplyKeepsCountsOfRemovedInterface(t *testing.T) {
	requireRoot(t)
	xd, ifname := newTestXdpd(t)

	drop := bpfDropFilter{Description: "one", Expr: "udp dst port 9999"}
	if err := xd.apply(confFor(ifname, drop)); err != nil {
		t.Fatal(err)
	}
	sendUDP9999(t, xd.filters[ifname], 3)

	if err := xd.apply(config{}); err != nil {
		t.Fatal(err)
	}
	if got := filterHits(t, xd, ifname, drop); got != 3 {
		t.Errorf("got %v hits, want 3", got)
	}
}

// Failing to clean up the pins of an interface that has been detached must not
// leave it around in xd.filters, where the missing link pin would be taken for
// an -unload.
func TestApplyRemovedInterfacePinCleanupFails(t *testing.T) {
	requireRoot(t)
	xd, ifname := newTestXdpd(t)

	if err := xd.apply(confFor(ifname, bpfDropFilter{Description: "one", Expr: "udp dst port 9999"})); err != nil {
		t.Fatal(err)
	}

	// Make the drop hook pin impossible to remove, a directory that is not empty.
	dropPin := pinPath(xd.pinDir, ifname, "drop")
	if err := os.Remove(dropPin); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dropPin, 0o700); err != nil {
		t.Fatal(err)
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Log("closing map failed", err)
		}
	})
	if err := m.Pin(filepath.Join(dropPin, "blocker")); err != nil {
		t.Fatal(err)
	}

	if err := xd.apply(config{}); !errors.Is(err, errCleanup) {
		t.Errorf("got error %v, want one wrapping errCleanup", err)
	}
	if len(xd.filters) != 0 {
		t.Errorf("got %d filters, want the detached one forgotten", len(xd.filters))
	}
	if pin := xd.removedPin(); pin != "" {
		t.Errorf("a detached filter was left behind and looks unloaded: %s", pin)
	}
}

// blockXDP attaches a program that isn't ours to ifname, which makes attaching
// ours fail with EBUSY.
func blockXDP(t *testing.T, ifname string) (unblock func()) {
	t.Helper()

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		t.Fatal(err)
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.XDP, License: "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, xdpPass), asm.Return()},
	})
	if err != nil {
		t.Fatal(err)
	}
	l, err := link.AttachXDP(link.XDPOptions{Program: prog, Interface: iface.Index})
	if err != nil {
		t.Fatal(err)
	}

	unblocked := false
	unblock = func() {
		if unblocked {
			return
		}
		unblocked = true
		if err := l.Close(); err != nil {
			t.Log("closing blocking link failed", err)
		}
		if err := prog.Close(); err != nil {
			t.Log("closing blocking program failed", err)
		}
	}
	t.Cleanup(unblock)
	return unblock
}

// A reload where a later interface can't be attached must leave every
// interface as it was: the ones swapped before the failure are put back and
// interfaces missing from the new config are not detached.
func TestApplyRollsBackWhenALaterSwapFails(t *testing.T) {
	requireRoot(t)
	xd, ifA := newTestXdpd(t)
	ifB := newDummyInterface(t, "b")
	ifC := newDummyInterface(t, "c")
	blockXDP(t, ifB)

	one := bpfDropFilter{Description: "one", Expr: "udp dst port 9999"}
	two := bpfDropFilter{Description: "two", Expr: "udp dst port 9998"}

	err := xd.apply(config{Interfaces: map[string]interfaceConfig{
		ifA: {BPFDropFilters: []bpfDropFilter{one}},
		ifC: {BPFDropFilters: []bpfDropFilter{one}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	fA, fC := xd.filters[ifA], xd.filters[ifC]
	linkA, progA := liveProg(t, fA)
	linkC, progC := liveProg(t, fC)

	// Interfaces are handled in name order: A is swapped, then B fails. C is
	// no longer in the config but must still be there afterwards.
	err = xd.apply(config{Interfaces: map[string]interfaceConfig{
		ifA: {BPFDropFilters: []bpfDropFilter{one, two}},
		ifB: {BPFDropFilters: []bpfDropFilter{one}},
	}})
	if err == nil {
		t.Fatal("expected an error since XDP can't be attached to the second interface")
	}

	if xd.filters[ifA] != fA || xd.filters[ifC] != fC || len(xd.filters) != 2 {
		t.Errorf("got filters %v, want only the original ones for %s and %s", slices.Sorted(maps.Keys(xd.filters)), ifA, ifC)
	}
	if gotLink, gotProg := liveProg(t, fA); gotLink != linkA || gotProg != progA {
		t.Errorf("%s: not put back: link %d -> %d, prog %d -> %d", ifA, linkA, gotLink, progA, gotProg)
	}
	if len(fA.bpfDropFilters) != 1 {
		t.Errorf("%s: got %d filters recorded for the running program, want 1", ifA, len(fA.bpfDropFilters))
	}
	if gotLink, gotProg := liveProg(t, fC); gotLink != linkC || gotProg != progC {
		t.Errorf("%s: changed although it was not part of the new config", ifC)
	}
	if pin := xd.removedPin(); pin != "" {
		t.Errorf("%s looks unloaded", pin)
	}

	// B was new, nothing may be left of it.
	for _, kind := range pinKinds {
		if _, err := os.Stat(pinPath(xd.pinDir, ifB, kind)); !os.IsNotExist(err) {
			t.Errorf("%s: %s pin left behind (stat error: %v)", ifB, kind, err)
		}
	}
}

// recreateDummyInterface removes and adds ifname again, which gives it a new
// ifindex and makes the kernel detach what was attached to it.
func recreateDummyInterface(t *testing.T, ifname string) {
	t.Helper()

	for _, args := range [][]string{{"link", "del", ifname}, {"link", "add", ifname, "type", "dummy"}} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
}

// When attaching again to an interface that was recreated fails, the filter of
// that interface must not stay around without a link pin, where it would be
// taken for an -unload and make the daemon exit.
func TestApplyRecreatedInterfaceAttachFails(t *testing.T) {
	requireRoot(t)
	xd, ifname := newTestXdpd(t)
	conf := confFor(ifname, bpfDropFilter{Description: "one", Expr: "udp dst port 9999"})

	if err := xd.apply(conf); err != nil {
		t.Fatal(err)
	}

	recreateDummyInterface(t, ifname)
	unblock := blockXDP(t, ifname)

	if err := xd.apply(conf); err == nil {
		t.Fatal("expected an error since XDP can't be attached to the recreated interface")
	}
	if len(xd.filters) != 0 {
		t.Errorf("got %d filters, want the one without a link forgotten", len(xd.filters))
	}
	if pin := xd.removedPin(); pin != "" {
		t.Errorf("%s looks unloaded", pin)
	}
	// The interface is still in the config, so its hooks stay for xdpcap.
	for _, kind := range []string{"drop", "monitor"} {
		if _, err := os.Stat(pinPath(xd.pinDir, ifname, kind)); err != nil {
			t.Errorf("%s hook pin removed: %v", kind, err)
		}
	}

	// A later reload tries again.
	unblock()
	if err := xd.apply(conf); err != nil {
		t.Fatal(err)
	}
	f := xd.filters[ifname]
	if f == nil {
		t.Fatal("the interface is not filtered after the retry")
	}
	liveProg(t, f)
}

// The hook pins made while preparing a new interface must not be left behind
// if the interface then fails to load.
func TestApplyBadConfigLeavesNoPinsForNewInterface(t *testing.T) {
	requireRoot(t)
	xd, ifname := newTestXdpd(t)

	if err := xd.apply(confFor(ifname, bpfDropFilter{Description: "bad", Expr: "this is ((not a filter"})); err == nil {
		t.Fatal("expected an error for an invalid expression")
	}

	entries, err := os.ReadDir(xd.pinDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("pin left behind: %s", e.Name())
	}
}

// Hook pins from a previous run may be in use by xdpcap, a failing load must leave them.
func TestApplyBadConfigKeepsHookPinsFromPreviousRun(t *testing.T) {
	requireRoot(t)
	first, ifname := newTestXdpd(t)

	if err := first.apply(confFor(ifname, bpfDropFilter{Description: "one", Expr: "udp dst port 9999"})); err != nil {
		t.Fatal(err)
	}

	second := newXdpd("unused", first.pinDir, first.logger)
	if err := second.apply(confFor(ifname, bpfDropFilter{Description: "bad", Expr: "this is ((not a filter"})); err == nil {
		t.Fatal("expected an error for an invalid expression")
	}

	for _, kind := range []string{"drop", "monitor"} {
		if _, err := os.Stat(pinPath(first.pinDir, ifname, kind)); err != nil {
			t.Errorf("%s hook pin from the previous run is gone: %v", kind, err)
		}
	}
}

// A takeover is undone too: if a later interface fails, the link a previous
// run left pinned must be running the program it had.
func TestApplyRollsBackTakeover(t *testing.T) {
	requireRoot(t)
	first, ifA := newTestXdpd(t)
	ifB := newDummyInterface(t, "b")
	blockXDP(t, ifB)

	one := bpfDropFilter{Description: "one", Expr: "udp dst port 9999"}
	if err := first.apply(confFor(ifA, one)); err != nil {
		t.Fatal(err)
	}
	linkID, progID := liveProg(t, first.filters[ifA])

	// A new process: A is taken over and swapped, then B fails.
	second := newXdpd("unused", first.pinDir, first.logger)
	err := second.apply(config{Interfaces: map[string]interfaceConfig{
		ifA: {BPFDropFilters: []bpfDropFilter{one, {Description: "two", Expr: "udp dst port 9998"}}},
		ifB: {BPFDropFilters: []bpfDropFilter{one}},
	}})
	if err == nil {
		t.Fatal("expected an error since XDP can't be attached to the second interface")
	}

	if len(second.filters) != 0 {
		t.Errorf("got %d filters, want none after a failed first load", len(second.filters))
	}
	if gotLink, gotProg := liveProg(t, first.filters[ifA]); gotLink != linkID || gotProg != progID {
		t.Errorf("%s: not put back: link %d -> %d, prog %d -> %d", ifA, linkID, gotLink, progID, gotProg)
	}
}

// A link that is detached already, like when the interface it was attached to
// is removed, can still be cleaned up. This is also what a retry looks like
// after a detach where the pin could not be removed.
func TestDetachPinnedLinkAlreadyDetached(t *testing.T) {
	requireRoot(t)
	xd, ifname := newTestXdpd(t)

	if err := xd.apply(confFor(ifname, bpfDropFilter{Description: "one", Expr: "udp dst port 9999"})); err != nil {
		t.Fatal(err)
	}

	recreateDummyInterface(t, ifname) // the kernel detaches the link, the pin stays

	linkPin := pinPath(xd.pinDir, ifname, "link")
	if _, err := os.Stat(linkPin); err != nil {
		t.Fatalf("expected the link pin to remain: %v", err)
	}
	if err := detachPinnedLink(xd.logger, linkPin); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(linkPin); !os.IsNotExist(err) {
		t.Errorf("link pin still exists: %v", err)
	}
}

// If putting back a swap fails, that interface runs the new program and that
// is what has to be tracked, with counters that can be read.
func TestApplyTracksSwapThatCouldNotBePutBack(t *testing.T) {
	requireRoot(t)
	xd, ifA := newTestXdpd(t)
	ifB := newDummyInterface(t, "b")
	blockXDP(t, ifB)

	one := bpfDropFilter{Description: "one", Expr: "udp dst port 9999"}
	two := bpfDropFilter{Description: "two", Expr: "udp dst port 9998"}
	if err := xd.apply(confFor(ifA, one)); err != nil {
		t.Fatal(err)
	}
	f := xd.filters[ifA]

	// Makes putting back the previous program of A fail.
	if err := f.prog.Close(); err != nil {
		t.Fatal(err)
	}

	err := xd.apply(config{Interfaces: map[string]interfaceConfig{
		ifA: {BPFDropFilters: []bpfDropFilter{one, two}},
		ifB: {BPFDropFilters: []bpfDropFilter{one}},
	}})
	if err == nil {
		t.Fatal("expected an error")
	}

	if xd.filters[ifA] != f || len(f.bpfDropFilters) != 2 {
		t.Errorf("%s: not tracked as running the new filters (%d recorded)", ifA, len(f.bpfDropFilters))
	}
	info, err := f.prog.Info()
	if err != nil {
		t.Fatalf("the tracked program can't be used: %v", err)
	}
	progID, _ := info.ID()
	if _, liveID := liveProg(t, f); liveID != progID {
		t.Errorf("the link runs program %d, the filter tracks %d", liveID, progID)
	}
	var perCPU []uint64
	if err := f.counters.Lookup(uint32(1), &perCPU); err != nil {
		t.Errorf("the tracked counters can't be read: %v", err)
	}
	if _, ok := xd.filters[ifB]; ok {
		t.Errorf("%s is tracked although it was never attached", ifB)
	}
}

// A daemon without filters, like after reloading an empty config, must still
// notice an -unload.
func TestRemovedPinWithoutFilters(t *testing.T) {
	pinDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	xd := newXdpd("unused", pinDir, logger)

	if pin := xd.removedPin(); pin != "" {
		t.Fatalf("%s reported as removed before anything was unloaded", pin)
	}

	if err := unloadAll(logger, pinDir); err != nil {
		t.Fatal(err)
	}
	if pin := xd.removedPin(); pin != pinDir {
		t.Errorf("got %q, want the removed pin directory %q", pin, pinDir)
	}
}

// A link the kernel detached while the interface kept its ifindex (like after
// moving it to another network namespace and back) is attached again, instead
// of an Update on it failing every reload.
func TestApplyReattachesDetachedLinkWithSameIfindex(t *testing.T) {
	requireRoot(t)
	xd, ifname := newTestXdpd(t)
	conf := confFor(ifname, bpfDropFilter{Description: "one", Expr: "udp dst port 9999"})

	if err := xd.apply(conf); err != nil {
		t.Fatal(err)
	}
	oldLink, _ := liveProg(t, xd.filters[ifname])

	// Detach it behind the daemon's back, the interface stays as it is.
	l, err := link.LoadPinnedLink(pinPath(xd.pinDir, ifname, "link"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Detach(); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	if err := xd.apply(conf); err != nil {
		t.Fatal(err)
	}
	f := xd.filters[ifname]
	if isDetached(f.link) {
		t.Fatal("still detached after the reload")
	}
	if newLink, _ := liveProg(t, f); newLink == oldLink {
		t.Error("expected a new link")
	}
}

// Interfaces a previous run left pinned that are no longer in the config are
// detached and their pins removed, like when an interface is removed from the
// config while the daemon isn't running.
func TestApplyRemovesOrphans(t *testing.T) {
	requireRoot(t)
	first, ifname := newTestXdpd(t)

	if err := first.apply(confFor(ifname, bpfDropFilter{Description: "one", Expr: "udp dst port 9999"})); err != nil {
		t.Fatal(err)
	}

	second := newXdpd("unused", first.pinDir, first.logger)
	if err := second.apply(config{}); err != nil {
		t.Fatal(err)
	}

	if !first.filters[ifname].unloaded() {
		t.Error("the link pin of the orphan is still there")
	}
	if !isDetached(first.filters[ifname].link) {
		t.Error("the orphan is still attached")
	}
	entries, err := os.ReadDir(first.pinDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("pin left behind: %s", e.Name())
	}
}

func TestPinOwner(t *testing.T) {
	for name, want := range map[string]string{
		"eth0-link":        "eth0",
		"br-lan-counters":  "br-lan",
		"wg0-drop":         "wg0",
		"eth0.100-monitor": "eth0.100",
		"something-else":   "",
		"-link":            "",
	} {
		got, ok := pinOwner(name)
		if got != want || ok != (want != "") {
			t.Errorf("%s: got %q, %v, want %q", name, got, ok, want)
		}
	}
}

func TestConfigValidateDuplicates(t *testing.T) {
	one := bpfDropFilter{Description: "one", Expr: "udp dst port 9999", source: "00-base.json"}
	monitorOne := bpfDropFilter{Description: "one", Expr: "udp dst port 9999", Monitor: true, source: "00-base.json"}

	if err := confFor("eth0", one, monitorOne).validate(); err != nil {
		t.Errorf("drop and monitor versions of one filter: %v", err)
	}
	if err := (config{Interfaces: map[string]interfaceConfig{
		"eth0": {BPFDropFilters: []bpfDropFilter{one}},
		"eth1": {BPFDropFilters: []bpfDropFilter{one}},
	}}).validate(); err != nil {
		t.Errorf("one filter on two interfaces: %v", err)
	}

	// In one file.
	err := confFor("eth0", one, monitorOne, one).validate()
	want := `eth0: filter "one" in 00-base.json duplicates the one in 00-base.json`
	if err == nil || err.Error() != want {
		t.Errorf("got %v, want %q", err, want)
	}

	// Across files: an error too, naming both.
	fromTool := one
	fromTool.source = "50-ddos.json"
	err = confFor("eth0", one, fromTool).validate()
	want = `eth0: filter "one" in 50-ddos.json duplicates the one in 00-base.json`
	if err == nil || err.Error() != want {
		t.Errorf("got %v, want %q", err, want)
	}

	// apply refuses it before it gets anywhere near the kernel.
	xd := newXdpd("unused", t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := xd.apply(confFor("does-not-exist0", one, one)); err == nil || !strings.Contains(err.Error(), "duplicates") {
		t.Errorf("got %v, want the duplicate to be refused", err)
	}
}

// An empty expr compiles to "match everything", so a drop filter without one
// (e.g. from a generator with an empty template variable) would drop all
// traffic on the interface.
func TestConfigValidateEmptyExpr(t *testing.T) {
	for _, expr := range []string{"", " \t\n"} {
		bdf := bpfDropFilter{Description: "flood", Expr: expr, source: "50-ddos.json"}
		want := `eth0: filter "flood" in 50-ddos.json has an empty expr`
		if err := confFor("eth0", bdf).validate(); err == nil || err.Error() != want {
			t.Errorf("expr %q: got %v, want %q", expr, err, want)
		}
	}

	// A missing expr, or a null entry in the list, ends up the same.
	for _, content := range []string{
		`{"interfaces": {"lo": {"bpf_drop_filters": [{"description": "flood"}]}}}`,
		`{"interfaces": {"lo": {"bpf_drop_filters": [null]}}}`,
	} {
		conf, err := readConf(writeConfDir(t, map[string]string{"50-ddos.json": content}))
		if err != nil {
			t.Fatal(err)
		}
		if err := conf.validate(); err == nil || !strings.Contains(err.Error(), "in 50-ddos.json has an empty expr") {
			t.Errorf("%s: got %v, want an empty expr error", content, err)
		}
	}
}

// A filter that doesn't compile names the file it came from, so the writer
// that broke a reload can be found.
func TestBuildProgramErrorNamesSource(t *testing.T) {
	bad := []bpfDropFilter{{Description: "Block flood", Expr: "not a filter", source: "50-ddos.json"}}
	// Fails on the first filter, before any of the (nil) maps are used.
	_, err := buildProgram(bad, dltEthernet, nil, nil, nil)
	want := `50-ddos.json: "Block flood": compiling "not a filter": `
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("got %v, want an error starting with %q", err, want)
	}
}

// A link pin that isn't an XDP link (here a TCX one) is refused, without
// panicking and without touching what that link runs. This used to be a nil
// dereference in attach.
func TestApplyRefusesNonXDPPinnedLink(t *testing.T) {
	requireRoot(t)
	xd, ifname := newTestXdpd(t)

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		t.Fatal(err)
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SchedCLS, License: "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, -1), asm.Return()}, // TCX_NEXT
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := prog.Close(); err != nil {
			t.Log("closing tcx program failed", err)
		}
	})
	tcx, err := link.AttachTCX(link.TCXOptions{Interface: iface.Index, Program: prog, Attach: ebpf.AttachTCXIngress})
	if errors.Is(err, ebpf.ErrNotSupported) {
		t.Skip("needs TCX links (Linux 6.6) for a link that isn't XDP")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := tcx.Close(); err != nil {
			t.Log("closing tcx link failed", err)
		}
	})
	linkPin := pinPath(xd.pinDir, ifname, "link")
	if err := tcx.Pin(linkPin); err != nil {
		t.Fatal(err)
	}
	before, err := tcx.Info()
	if err != nil {
		t.Fatal(err)
	}

	err = xd.apply(confFor(ifname, bpfDropFilter{Description: "one", Expr: "udp dst port 9999"}))
	if err == nil || !strings.Contains(err.Error(), "is not an XDP link") {
		t.Fatalf("got %v, want the non-XDP link to be refused", err)
	}

	if len(xd.filters) != 0 {
		t.Errorf("got %d filters, want none", len(xd.filters))
	}
	after, err := tcx.Info()
	if err != nil {
		t.Fatal(err)
	}
	if after.Program != before.Program {
		t.Errorf("the tcx link now runs program %d, want %d", after.Program, before.Program)
	}
	entries, err := os.ReadDir(xd.pinDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(linkPin) {
			t.Errorf("pin left behind: %s", e.Name())
		}
	}
	if _, err := os.Stat(linkPin); err != nil {
		t.Errorf("the tcx link pin is gone: %v", err)
	}
}
