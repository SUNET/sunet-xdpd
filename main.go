// As this code interacts with XDP it is only usable on linux
//go:build linux

// sunet-xdpd reads bpf (tcpdump) filter expressions from a config file and creates
// a XDP program that drops matching packets per interface.
//
// The XDP link is pinned so filtering keeps running when sunet-xdpd exits,
// crashes or restarts. On startup, sunet-xdpd takes over the running filter
// and swaps in its own program without a gap. To stop filtering:
//
//	sunet-xdpd -unload
//
// Reload config with:
//
//	pkill -HUP sunet-xdpd
//
// Pins in /sys/fs/bpf/sunet-xdpd:
//
//	<ifname>-link      the XDP attachment, filtering lasts as long as this pin exists
//	<ifname>-counters  per-filter match counters of the running program, can be inspected with e.g. bpftools
//	<ifname>-drop      xdpcap hook for dropped packets
//	<ifname>-monitor   xdpcap hook for passed packets that matched a filter in monitor mode
//
// Capture matched packets via the xdpcap hook files (be careful with using an
// empty filter if dropping a lot of packets with the filter as it can be a lot
// of packets):
//
//	xdpcap /sys/fs/bpf/sunet-xdpd/drop - "" | tcpdump -nr -
//	xdpcap /sys/fs/bpf/sunet-xdpd/drop - "tcp and port 80" | tcpdump -nr -
//	xdpcap /sys/fs/bpf/sunet-xdpd/drop dropped.pcap "tcp and port 80"

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cloudflare/cbpfc"
	"github.com/cloudflare/xdpcap"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const (
	xdpDrop = 1
	xdpPass = 2

	pinDir = "/sys/fs/bpf/sunet-xdpd"
	//linkPin = pinDir + "/link"

	// Stack bytes reserved for our own use (the counter key at R10-4).
	// cbpfc places cBPF scratch memory below this.
	stackReserved = 4

	// cbpfc filters return 0 if the filter did not match the packet.
	noFilterMatch = 0
)

type xdpd struct {
	confPath       string
	conf           config
	confMtx        sync.RWMutex
	filters        []*filter
	logger         *slog.Logger
	currentMetrics map[metricLabels]uint64
}

type metricLabels struct {
	ifaceName   string
	description string
	expr        string
	mode        string
}

type config struct {
	Interfaces map[string]interfaceConfig `json:"interfaces"`
}

type interfaceConfig struct {
	BPFDropFilters []bpfDropFilter `json:"bpf_drop_filters"`
}

type bpfDropFilter struct {
	Description string `json:"description"`
	Expr        string `json:"expr"`
	Monitor     bool   `json:"monitor,omitempty"`
}

func newXdpd(confPath string, logger *slog.Logger) (*xdpd, error) {
	xd := xdpd{
		confPath:       confPath,
		logger:         logger,
		currentMetrics: map[metricLabels]uint64{},
	}

	err := xd.setConf()
	if err != nil {
		return nil, err
	}

	return &xd, nil
}

func (xd *xdpd) getConf() config {
	xd.confMtx.RLock()
	defer xd.confMtx.RUnlock()
	return xd.conf
}

func (xd *xdpd) setConf() error {
	root, err := os.OpenRoot(filepath.Dir(xd.confPath))
	if err != nil {
		return fmt.Errorf("setConf: unable to OpenRoot: %w", err)
	}
	defer func() {
		cErr := root.Close()
		if cErr != nil {
			xd.logger.Error("root.Close failed", "error", err.Error())
		}
	}()

	confBytes, err := root.ReadFile(filepath.Base(xd.confPath))
	if err != nil {
		return err
	}

	var conf config

	err = json.Unmarshal(confBytes, &conf)
	if err != nil {
		return err
	}

	xd.confMtx.Lock()
	xd.conf = conf
	xd.confMtx.Unlock()

	return nil
}

func main() {
	unloadFlag := flag.Bool("unload", false, "detach the running filters, remove all pins and exit")
	configFlag := flag.String("config", "sunet-xdpd.json", "config file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	xd, err := newXdpd(*configFlag, logger)
	if err != nil {
		logger.Error("newXdpd failed", "error", err.Error())
		os.Exit(1)
	}

	if *unloadFlag {
		err = xd.unloadFilters()
		if err != nil {
			logger.Error("unloadFilters failed", "error", err.Error())
			os.Exit(1)
		}
	} else {
		err = xd.run()
		if err != nil {
			logger.Error("run failed", "error", err.Error())
			os.Exit(1)
		}
	}
}

type promMetrics struct {
	filterHits *prometheus.CounterVec
}

var promCounterLabels = []string{"iface", "description", "expr", "mode"}

func newPromMetrics(reg prometheus.Registerer) *promMetrics {
	m := &promMetrics{
		filterHits: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "filter_packets_total",
				Help: "The total number of packets that matched a filter expression",
			},
			promCounterLabels,
		),
	}
	return m
}

// run loads the rules and attaches them (or takes over a running filter).
// Rules are re-read on SIGHUP and exists on SIGINT or SIGTERM.
// Exiting only closes file descriptors, the pinned filter keeps running.
func (xd *xdpd) run() error {
	// Register before loading anything, so an early SIGHUP doesn't kill the process.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP, os.Interrupt, syscall.SIGTERM)

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	pm := newPromMetrics(reg)

	promMux := http.NewServeMux()
	promServer := &http.Server{
		Addr:           "127.0.0.1:2112",
		Handler:        promMux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	promMux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

	idleConnsClosed := make(chan struct{})
	shutdownPromServer := make(chan struct{})
	go func() {
		<-shutdownPromServer
		xd.logger.Info("shutting down prometheus listener", "listen_addr", promServer.Addr)

		if err := promServer.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			xd.logger.Error("HTTP server Shutdown", "error", err.Error())
		}
		close(idleConnsClosed)
	}()

	go func() {
		xd.logger.Info("starting prometheus listener", "listen_addr", promServer.Addr)
		if err := promServer.ListenAndServe(); err != http.ErrServerClosed {
			// Error starting or closing listener:
			xd.logger.Error("HTTP server ListenAndServe", "error", err.Error())
		}
	}()

	// Create the directory where we create pin files.
	if err := os.MkdirAll(pinDir, 0o700); err != nil {
		return fmt.Errorf("creating %s (is bpffs mounted at /sys/fs/bpf?): %w", pinDir, err)
	}

	err := xd.loadFilters()
	if err != nil {
		return fmt.Errorf("loadFilters failed: %w", err)
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

runLoop:
	for {
		select {
		case <-ticker.C:
			for _, f := range xd.filters {
				if f.unloaded() {
					return fmt.Errorf("ticker: filter was unloaded (link pin %s removed), exiting", f.linkPin)
				}
				xd.updateMetrics(pm)
			}

		case sig := <-sigs:
			for _, f := range xd.filters {
				if f.unloaded() {
					return fmt.Errorf("sigs: filter was unloaded (link pin %s removed), exiting", f.linkPin)
				}
			}

			if sig != syscall.SIGHUP {
				xd.logger.Info("exiting; the filters stays attached (stop them with -unload)")
				close(shutdownPromServer)
				break runLoop
			}

			// Update config
			err = xd.setConf()
			if err != nil {
				return fmt.Errorf("unable to set config in response to SIGHUP: %w", err)
			}

			newConf := xd.getConf()

			// For any filters belonging to interfaces that no longer exists in config we need to unload those programs
			for _, f := range xd.filters {
				if _, ok := newConf.Interfaces[f.iface.Name]; !ok {
					xd.logger.Info("unloading interface no longer being filtered by config", "iface", f.iface.Name)
					err := f.unload(xd.logger)
					if err != nil {
						xd.logger.Error("failed unloading no longer monitored interface", "error", err.Error())
					}
				}
			}

			xd.updateMetrics(pm)
			// The eBPF counter map will be recreated so reset
			// currentMetric counters. We still keep the contents
			// around since they are used for cleaning up
			// prometheis metrics inside updateMetrics
			for ml := range xd.currentMetrics {
				xd.currentMetrics[ml] = 0
			}

			err = xd.loadFilters()
			if err != nil {
				return fmt.Errorf("unable to reload filters in response to SIGHUP: %w", err)
			}
		}
	}

	// Wait for prom server to be done with connections
	<-idleConnsClosed

	return nil
}

// filter is the loaded state: the attached program and its counters.
// The hook maps are shared by every program version, so a running
// xdpcap session keeps working across reloads.
type filter struct {
	linkPin               string
	iface                 *net.Interface
	linkType              layers.LinkType
	dropHook, monitorHook *ebpf.Map
	link                  link.Link
	tookOver              bool // link was pinned by a previous run
	prog                  *ebpf.Program
	counters              *ebpf.Map
	bpfDropFilters        []bpfDropFilter
}

// load builds a program for rules and attaches it or atomically replaces
// the running program if one is already attached.
// On error the previous program keeps running untouched.
func (f *filter) load(logger *slog.Logger, conf config) (err error) {
	logger.Info("load()", "iface", f.iface.Name)
	ifConf := conf.Interfaces[f.iface.Name]

	// Fix G115 (CWE-190): integer overflow conversion int -> uint32 (Confidence: MEDIUM, Severity: HIGH)
	intMaxEntries := len(ifConf.BPFDropFilters)
	if intMaxEntries < 0 || intMaxEntries > math.MaxUint32 {
		return fmt.Errorf("the number of bpfDropFilters does not fit in MaxEntries uint32")
	}
	maxEntries := uint32(intMaxEntries)
	counters, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       fmt.Sprintf("%s_filter_counters", f.iface.Name),
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: uint32(max(maxEntries, 1)), // a zero-size map fails to create
	})
	if err != nil {
		return fmt.Errorf("creating counters map '%s': %w", counters, err)
	}
	defer func() {
		if err != nil {
			cErr := counters.Close()
			if cErr != nil {
				logger.Error("unable to close counters", "error", err.Error())
			}
		}
	}()

	insns, err := buildProgram(ifConf.BPFDropFilters, f.linkType, f.dropHook, f.monitorHook, counters)
	if err != nil {
		return err
	}

	progSpec := &ebpf.ProgramSpec{
		Name:         fmt.Sprintf("sunet_xdpd_%s", f.iface.Name),
		Type:         ebpf.XDP,
		License:      "GPL",
		Instructions: insns,
	}

	// Fix e.g. "ens3: single-buffer XDP requires MTU less than 3506" on interfaces with a large MTU.
	// I noticed the program will fail to load if this is used on "lo" so skip that interface
	if f.iface.Name != "lo" {
		progSpec.Flags = unix.BPF_F_XDP_HAS_FRAGS
	}

	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		if errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("loading program failed: invalid argument (check if the network driver or kernel version lacks BPF_F_XDP_HAS_FRAGS support)")
		}
		// The verifier log is the key to debugging hand-built programs.
		if ve, found := errors.AsType[*ebpf.VerifierError](err); found {
			return fmt.Errorf("loading program: %+v", ve)
		}
		return fmt.Errorf("loading program: %w", err)
	}
	defer func() {
		if err != nil {
			cErr := prog.Close()
			if cErr != nil {
				logger.Error("unable to close prog", "error", err.Error())
			}
		}
	}()

	if f.link == nil {
		if err := f.attach(logger, f.iface, prog); err != nil {
			return err
		}
	} else {
		fmt.Printf("updating filter for %s", f.iface.Name)
		if err := f.link.Update(prog); err != nil {
			// Update swaps the program in place: packets go from the old program
			// straight to the new one, with no unfiltered window in between.
			return fmt.Errorf("replacing program: %w", err)
		}
	}

	// The new program is live; retire the old one.
	oldProg, oldCounters := f.prog, f.counters
	f.prog, f.counters, f.bpfDropFilters = prog, counters, ifConf.BPFDropFilters
	if oldProg != nil {
		err = oldProg.Close()
		if err != nil {
			return fmt.Errorf("unable to close oldProg: %w", err)
		}
	}
	if oldCounters != nil {
		err = oldCounters.Unpin()
		if err != nil {
			return fmt.Errorf("unable to unpin oldCounters: %w", err)
		}
		err = oldCounters.Close()
		if err != nil {
			return fmt.Errorf("unable to close oldCounters: %w", err)
		}
	}

	counterPin := filepath.Join(pinDir, fmt.Sprintf("%s-counters", f.iface.Name))
	err = os.Remove(counterPin) // Pin fails if a stale pin exists
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("removing counterpin %s failed: %w", counterPin, err)
		}
	}
	if err := counters.Pin(counterPin); err != nil {
		// Not fatal: filtering works, only outside inspection is affected.
		logger.Info("warning: pinning counters", "error", err.Error())
	}

	how := "attached"
	if f.tookOver {
		how = "took over running filter"
	}
	logger.Info("filter attachement", "how", how, "on", f.iface.Name, "link_type", linkTypeName(f.linkType), "num_rules", len(ifConf.BPFDropFilters), "pins_dir", pinDir)
	return nil
}

func (xd *xdpd) loadFilters() (err error) {
	conf := xd.getConf()
	xd.logger.Info("loading filters")

	// Reset filters list since we will build it up from scratch again,
	// calling close will not stop a program from running.
	if xd.filters != nil {
		for _, f := range xd.filters {
			err = f.dropHook.Close()
			if err != nil {
				xd.logger.Error("closing previous drophook failed", "error", err.Error())
			}
			err = f.monitorHook.Close()
			if err != nil {
				xd.logger.Error("closing previous monitorhook failed", "error", err.Error())
			}
			err = f.Close()
			if err != nil {
				xd.logger.Error("closing previous filter failed", "error", err.Error())
			}
		}

		xd.filters = nil
	}

	for ifname := range conf.Interfaces {
		iface, err := net.InterfaceByName(ifname)
		if err != nil {
			return fmt.Errorf("getting interface %s: %w", ifname, err)
		}

		// What XDP's data pointer points at depends on the device type, and
		// every rule's byte offsets depend on that.
		linkType, err := linkTypeFor(iface.Name)
		if err != nil {
			return err
		}

		// Reuse pinned hooks if they exist, so xdpcap paths stay valid across restarts.
		dropHook, err := openHook(xd.logger, fmt.Sprintf("%s-drop", iface.Name))
		if err != nil {
			return err
		}

		monitorHook, err := openHook(xd.logger, fmt.Sprintf("%s-monitor", iface.Name))
		if err != nil {
			return err
		}

		f := &filter{
			linkPin:     filepath.Join(pinDir, fmt.Sprintf("%s-link", iface.Name)),
			iface:       iface,
			linkType:    linkType,
			dropHook:    dropHook,
			monitorHook: monitorHook,
		}

		xd.filters = append(xd.filters, f)
	}

	for _, f := range xd.filters {
		err := f.load(xd.logger, conf)
		if err != nil {
			return fmt.Errorf("loadFilters: load failed: %w", err)
		}
	}
	return nil
}

// attach takes over the pinned link if a previous run left one, swapping
// in prog without a gap. Otherwise it attaches prog and pins the link so
// filtering outlives this process.
func (f *filter) attach(logger *slog.Logger, iface *net.Interface, prog *ebpf.Program) error {
	logger.Info("attach()", "iface", iface.Name)
	l, err := link.LoadPinnedLink(f.linkPin, nil)
	switch {
	case err == nil:
		info, err := l.Info()
		if err != nil {
			cErr := l.Close()
			if cErr != nil {
				logger.Error("error closing link", "link_pin", f.linkPin, "error", cErr.Error())
			}
			return fmt.Errorf("inspecting pinned link: %w", err)
		}
		xdp := info.XDP()

		if xdp == nil || int(xdp.Ifindex) != f.iface.Index {
			cErr := l.Close()
			if cErr != nil {
				logger.Error("link close failed when inspecting XDP info", "link_pin", f.linkPin, "error", err.Error())
			}

			// The xdp Ifindex being 0 indicates the pin file
			// exists in the filesystem but is in a detached state
			// (we called Detach() on it), it is still a valid link
			// file but it does not actually reference the interface it once
			// did anymore.
			if xdp.Ifindex == 0 {
				logger.Warn("found detached link file, unpinning it")
				err := l.Unpin()
				if err != nil {
					logger.Error("failed unpinning detached link file", "link_pin", f.linkPin, "error", err.Error())
				}
			}

			return fmt.Errorf("%s is attached to a different interface; unload it first", f.linkPin)
		}
		if err := l.Update(prog); err != nil {
			cErr := l.Close()
			if cErr != nil {
				logger.Error("link close failed after update failed", "link_pin", f.linkPin, "error", err.Error())
			}
			return fmt.Errorf("replacing running program: %w", err)
		}
		f.tookOver = true

	case errors.Is(err, os.ErrNotExist):
		logger.Info("link is missing, attaching XDP", "iface", iface.Name)
		l, err = link.AttachXDP(link.XDPOptions{Program: prog, Interface: f.iface.Index})
		if err != nil {
			// If we fail here the error message can be fairly opaque, a tip is to check dmesg, e.g. I have seen:
			// "failed to attach link: create link: invalid argument" which turned up in dmesg like so:
			// ===
			// virtio_net virtio1 ens3: single-buffer XDP requires MTU less than 3506
			// ===
			return fmt.Errorf("attaching XDP for %s: %w", iface.Name, err)
		}
		logger.Info("creating pin", "iface", iface.Name, "link_pin", f.linkPin)
		if err := l.Pin(f.linkPin); err != nil {
			cErr := l.Close() // not pinned yet, so this detaches again
			if cErr != nil {
				logger.Error("closing pin %s failed after failed pin", "link_pin", f.linkPin, "error", err.Error())
			}
			return fmt.Errorf("pinning link: %w", err)
		}

	default:
		return fmt.Errorf("opening pinned link: %w", err)
	}

	f.link = l
	logger.Info("pin was created", "iface", iface.Name, "link_pin", f.linkPin)
	return nil
}

// Close only closes file descriptors. The link, counters and hooks stay
// pinned, so the kernel keeps filtering after this process exits.
func (f *filter) Close() error {
	if f.link != nil {
		err := f.link.Close()
		if err != nil {
			return fmt.Errorf("link close failed: %w", err)
		}
	}
	if f.prog != nil {
		err := f.prog.Close()
		if err != nil {
			return fmt.Errorf("prog close failed : %w", err)
		}
	}
	if f.counters != nil {
		err := f.counters.Close()
		if err != nil {
			return fmt.Errorf("counters close failed:  %w", err)
		}
	}
	return nil
}

// unloaded reports whether someone ran -unload (or removed the pins)
// while this process was running.
func (f *filter) unloaded() bool {
	_, err := os.Stat(f.linkPin)
	return errors.Is(err, os.ErrNotExist)
}

func (f *filter) unload(logger *slog.Logger) error {
	l, err := link.LoadPinnedLink(f.linkPin, nil)
	switch {
	case err == nil:
		// Detach works even if a running sunet-xdpd still holds a
		// reference open, this will however leave the pin file in
		// /sys/fs/bpf, we unpin it further down to actually clean up
		// the file.
		if err := l.Detach(); err != nil {
			cErr := l.Close()
			if cErr != nil {
				logger.Error("closing link failed after failed detach", "link_pin", f.linkPin, "error", cErr.Error())
			}
			return fmt.Errorf("detaching %s: %w", f.linkPin, err)
		}
		// Do not leave a detached link file in the directory, it will
		// make us find it and and try to use it, only to have the XDP
		// info in it return ifindex 0 which of course does not match
		// the interface we are configuring it with (e.g. even "lo" starts
		// at 0x1).
		err := l.Unpin()
		if err != nil {
			logger.Error("unpinning link failed after successfull detach", "link_pin", f.linkPin, "error", err.Error())
		}
		cErr := l.Close()
		if cErr != nil {
			logger.Error("closing link failed after successful unpin", "link_pin", f.linkPin, "error", cErr.Error())
		}
		logger.Info("detached filter and removed link pin", "link_pin", f.linkPin)
	case errors.Is(err, os.ErrNotExist):
		logger.Info("no filter attached for %s", "link_pin", f.linkPin)
	default:
		return fmt.Errorf("opening pinned link %s: %w", f.linkPin, err)
	}

	return nil
}

// unload detaches the running filter and removes all pins.
func (xd *xdpd) unloadFilters() error {
	for _, f := range xd.filters {
		err := f.unload(xd.logger)
		if err != nil {
			return fmt.Errorf("calling f.unload failed: %w", err)
		}
	}
	if err := os.RemoveAll(pinDir); err != nil {
		return fmt.Errorf("removing pin dir %s: %w", pinDir, err)
	}
	return nil
}

func (xd *xdpd) updateMetrics(pm *promMetrics) {
	seenMetrics := map[metricLabels]struct{}{}
	for _, f := range xd.filters {
		for i, bfd := range f.bpfDropFilters {
			mode := "drop"
			if bfd.Monitor {
				mode = "monitor"
			}

			ml := metricLabels{
				ifaceName:   f.iface.Name,
				description: bfd.Description,
				expr:        bfd.Expr,
				mode:        mode,
			}

			seenMetrics[ml] = struct{}{}

			var perCPU []uint64
			if err := f.counters.Lookup(uint32(i), &perCPU); err != nil {
				xd.logger.Error("reading counters failed", "description", bfd.Description, "error", err.Error())
				continue
			}

			var total uint64
			for _, v := range perCPU {
				total += v
			}

			prev := xd.currentMetrics[ml]
			delta := total - prev
			if total < prev { // counter map was recreated
				delta = total
			}
			xd.currentMetrics[ml] = total

			//xd.logger.Info("LATEST LOGS", "total", total, "prev", prev, "delta", delta)
			pm.filterHits.WithLabelValues(ml.ifaceName, ml.description, ml.expr, ml.mode).Add(float64(delta))

			//xd.logger.Info("counter status", "iface", f.iface.Name, "description", bfd.Description, "mode", mode, "total", latestTotal, "expr", bfd.Expr)
		}
	}

	// Remove metrics that refer to label sets that no longer match a filter
	for ml := range xd.currentMetrics {
		if _, found := seenMetrics[ml]; !found {
			deleted := pm.filterHits.DeleteLabelValues(ml.ifaceName, ml.description, ml.expr, ml.mode)
			if deleted {
				xd.logger.Info("deleted metrics for removed filter", "iface", ml.ifaceName, "description", ml.description, "expr", ml.expr, "mode", ml.mode)
			} else {
				xd.logger.Error("unable to delete metrics for unmanaged interface", "iface", ml.ifaceName)
			}
			delete(xd.currentMetrics, ml)
		}
	}
}

// buildProgram assembles the XDP program
func buildProgram(bpfDropFilters []bpfDropFilter, linkType layers.LinkType, dropHook, monitorHook, counters *ebpf.Map) (asm.Instructions, error) {
	prog := asm.Instructions{
		asm.Mov.Reg(asm.R9, asm.R1), // save ctx; R9 is callee-saved and not given to cbpfc
		asm.Mov.Imm(asm.R8, 0),      // "a monitor filter matched" flag, also callee-saved
	}

	for i, bdf := range bpfDropFilters {
		filter, err := exprToCBPF(bdf.Expr, linkType)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", bdf.Description, err)
		}

		result := fmt.Sprintf("result_%d", i)
		next := "pass"
		if i+1 < len(bpfDropFilters) {
			next = fmt.Sprintf("filter_%d", i+1)
		}

		f, err := cbpfc.ToEBPF(filter, cbpfc.EBPFOpts{
			PacketStart: asm.R2,
			PacketEnd:   asm.R3,
			Result:      asm.R4,
			ResultLabel: result,
			Working:     [4]asm.Register{asm.R4, asm.R5, asm.R6, asm.R7},
			StackOffset: stackReserved,
			LabelPrefix: fmt.Sprintf("filter%d", i), // unique per filter so labels don't collide
		})
		if err != nil {
			return nil, fmt.Errorf("filter %s: converting to eBPF: %w", bdf.Description, err)
		}

		prog = append(prog, loadPacket(fmt.Sprintf("filter_%d", i))...)
		prog = append(prog, f...)
		// How this works is that ResultLabel above references the
		// following instruction by tagging it using .WithSymbol().
		// So after the cbpfc-generated instructions we inserted on the
		// line above this comment has exectued we will jump to the
		// instruction inserted on the following line. If there was no
		// match jump to the next filter
		prog = append(prog, asm.JEq.Imm(asm.R4, noFilterMatch, next).WithSymbol(result))
		// If there was a match we end up here, and increment the filter hit counter:
		prog = append(prog, countRule(counters, i)...)

		if bdf.Monitor {
			// If the filter was matched but is currently in
			// "monitor" mode just remember that we hit it and
			// continue with the next filter or pass the packet
			prog = append(
				prog,
				asm.Mov.Imm(asm.R8, 1), // remember the match, keep evaluating
				// Jump to either the next filter or "pass" if on the last filter:
				asm.Ja.Label(next),
			)
		} else {
			// This is a real filter filter, drop the packet
			prog = append(prog, asm.Ja.Label("drop"))
		}
	}

	// The verifier rejects unreachable code, so only emit the exits
	// that some filter can actually reach.
	hasDrop, hasMonitor := false, false
	for _, bdf := range bpfDropFilters {
		if bdf.Monitor {
			hasMonitor = true
		} else {
			hasDrop = true
		}
	}

	if hasMonitor {
		// If the code above encountered a matching monitoring filter,
		// filled in R8 and ended up jumping to "pass" because the
		// packet did not encounter any actual drop filters, jump to
		// the the monitor hook tagged via .WithSymbol("monitor"):
		prog = append(prog, asm.JNE.Imm(asm.R8, 0, "monitor").WithSymbol("pass"))
		prog = append(prog, asm.Mov.Imm(asm.R0, xdpPass))
	} else {
		prog = append(prog, asm.Mov.Imm(asm.R0, xdpPass).WithSymbol("pass"))
	}
	// If we reached this point the instruction flow neither jumped to
	// "drop" or "monitor" hooks, meaning no filters was hit and we can
	// return, R0 is expexted to be set to XDP_PASS in that case.
	prog = append(prog, asm.Return())

	if hasMonitor {
		prog = append(prog, hookExit("monitor", monitorHook, xdpPass)...)
	}
	if hasDrop {
		prog = append(prog, hookExit("drop", dropHook, xdpDrop)...)
	}

	return prog, nil
}

// loadPacket (re)loads the packet start / end pointers into R2 / R3.
// It runs at the start of every filter because a monitor filter counter
// update is a helper call, which clobbers R1-R5.
func loadPacket(label string) asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(asm.R2, asm.R9, 0, asm.Word).WithSymbol(label), // xdp_md->data
		asm.LoadMem(asm.R3, asm.R9, 4, asm.Word),                   // xdp_md->data_end
	}
}

// countRule does counters[i]++ on a per-CPU array.
func countRule(counters *ebpf.Map, i int) asm.Instructions {
	done := fmt.Sprintf("counted_%d", i)
	return asm.Instructions{
		asm.StoreImm(asm.RFP, -stackReserved, int64(i), asm.Word), // key on the stack
		asm.LoadMapPtr(asm.R1, counters.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -stackReserved),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, done), // NULL check, required by the verifier
		asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord),
		asm.Add.Imm(asm.R1, 1),
		asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(done), // landing spot for the NULL check
	}
}

// hookExit is the equivalent of xdpcap_exit(ctx, hook, action) from xdpcaps hook.h.
// The key is a constant, which lets the verifier / JIT emit a direct,
// patchable tail call (a no-op while no xdpcap program is attached).
func hookExit(label string, hookMap *ebpf.Map, action int32) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R1, asm.R9).WithSymbol(label),
		asm.LoadMapPtr(asm.R2, hookMap.FD()),
		asm.Mov.Imm(asm.R3, action),
		asm.FnTailCall.Call(),
		// Only reached when no xdpcap program is attached for this action.
		asm.Mov.Imm(asm.R0, action),
		asm.Return(),
	}
}

// libpcap DLT_* values for pcap.CompileBPFFilter. These are libpcap's
// runtime numbers, which for some link types differ from the LINKTYPE_*
// numbers used in pcap files, and gopacket's layers.LinkType constants use
// the file numbers: layers.LinkTypeRaw is 101 (LINKTYPE_RAW), which libpcap
// rejects here. Ethernet happens to be 1 in both.
const (
	dltEthernet = layers.LinkType(1)  // DLT_EN10MB
	dltRaw      = layers.LinkType(12) // DLT_RAW on Linux: frames start at the IP header
)

func linkTypeName(lt layers.LinkType) string {
	switch lt {
	case dltEthernet:
		return "ethernet"
	case dltRaw:
		return "raw IP"
	default:
		return fmt.Sprintf("DLT %d", lt)
	}
}

// linkTypeFor picks the libpcap link type matching what XDP sees on ifname:
// libpcap needs it to know what's at byte 0 of the packet, and a wrong one
// silently makes filters compare the wrong bytes.
func linkTypeFor(ifname string) (layers.LinkType, error) {
	rootDir := "/sys/class/net"
	// sysfs has symlinks in many locations so doing OpenRoot() on rootDir fails
	// when looking up e.g. "lo" that is itself a symlink pointing outside it.
	root, err := os.OpenRoot("/sys")
	if err != nil {
		return 0, fmt.Errorf("linkTypeFor(): unable to open root dir %s: %w", rootDir, err)
	}
	b, err := root.ReadFile(filepath.Join("class/net", ifname, "type"))
	if err != nil {
		return 0, fmt.Errorf("reading device type of %s: %w", ifname, err)
	}
	switch t := strings.TrimSpace(string(b)); t {
	case "1", "772": // ARPHRD_ETHER, ARPHRD_LOOPBACK (lo uses a zeroed Ethernet header)
		return dltEthernet, nil
	case "65534": // ARPHRD_NONE: tun, WireGuard; frames start at the IP header
		return dltRaw, nil
	default:
		return 0, fmt.Errorf("%s: unsupported device type %s (see ARPHRD_* in linux/if_arp.h)", ifname, t)
	}
}

// exprToCBPF compiles a tcpdump expression to cBPF using libpcap.
// linkType says what's at the start of the packet, so libpcap can
// compute the right offsets (see linkTypeFor).
func exprToCBPF(expr string, linkType layers.LinkType) ([]bpf.Instruction, error) {
	raw, err := pcap.CompileBPFFilter(linkType, 65535, expr)
	if err != nil {
		return nil, fmt.Errorf("compiling %q: %w", expr, err)
	}

	rawInsns := make([]bpf.RawInstruction, len(raw))
	for i, r := range raw {
		rawInsns[i] = bpf.RawInstruction{Op: r.Code, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}

	insns, ok := bpf.Disassemble(rawInsns)
	if !ok {
		return nil, fmt.Errorf("could not decode cBPF for %q", expr)
	}
	return insns, nil
}

// openHook returns the pinned xdpcap hook map called name, creating and
// pinning it if it doesn't exist yet.
func openHook(logger *slog.Logger, name string) (*ebpf.Map, error) {
	path := filepath.Join(pinDir, name)

	m, err := ebpf.LoadPinnedMap(path, nil)
	if err == nil {
		if m.Type() != ebpf.ProgramArray {
			cErr := m.Close()
			if cErr != nil {
				logger.Error("unable to close map", "error", err.Error())
			}
			return nil, fmt.Errorf("%s exists but is not an xdpcap hook", path)
		}
		return m, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("opening %s hook: %w", name, err)
	}

	hook, err := xdpcap.NewHook(path)
	if err != nil {
		return nil, fmt.Errorf("creating %s hook: %w", name, err)
	}
	if err := hook.Pin(); err != nil {
		cErr := hook.Close()
		if cErr != nil {
			logger.Error("unable to close hook", "error", err.Error())
		}
		return nil, fmt.Errorf("pinning %s hook: %w", name, err)
	}
	// The Hook only wraps this map; closing the map releases everything.
	return hook.Map(), nil
}
