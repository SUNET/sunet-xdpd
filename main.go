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
// A reload is all or nothing per run: if the config can't be read or any BPF
// expression fails to compile or load, the error is logged and the filters that are
// running are left as they are. Interfaces removed from the config are detached
// and their pins removed, also on startup for interfaces that were removed while
// sunet-xdpd wasn't running. That happens once the new config is running, so if
// it fails the reload is still done: it is logged as a warning and tried again
// on the next reload.
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
//	xdpcap /sys/fs/bpf/sunet-xdpd/eth0-drop - "" | tcpdump -nr -
//	xdpcap /sys/fs/bpf/sunet-xdpd/eth0-drop - "tcp and port 80" | tcpdump -nr -
//	xdpcap /sys/fs/bpf/sunet-xdpd/eth0-drop dropped.pcap "tcp and port 80"
//	xdpcap /sys/fs/bpf/sunet-xdpd/eth0-monitor - "" | tcpdump -nr -

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
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

	defaultPinDir = "/sys/fs/bpf/sunet-xdpd"

	// Stack bytes reserved for our own use (the counter key at R10-4).
	// cbpfc places cBPF scratch memory below this.
	stackReserved = 4

	// cbpfc filters return 0 if the filter did not match the packet.
	noFilterMatch = 0
)

var version = "dev" // overridden via -ldflags "-X main.version=..."

// pinKinds are the suffixes of the files we pin per interface, see the
// package documentation.
var pinKinds = []string{"link", "counters", "drop", "monitor"}

func pinPath(dir, ifname, kind string) string {
	return filepath.Join(dir, fmt.Sprintf("%s-%s", ifname, kind))
}

type xdpd struct {
	confPath string
	pinDir   string
	// filters holds the running filters by interface name. It lives as long
	// as the process (it is not rebuilt on reload) and is only touched from
	// the goroutine running run().
	filters        map[string]*filter
	logger         *slog.Logger
	reg            *prometheus.Registry
	pm             *promMetrics
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

func newXdpd(confPath, pinDir string, logger *slog.Logger) *xdpd {
	reg := prometheus.NewRegistry()
	return &xdpd{
		confPath:       confPath,
		pinDir:         pinDir,
		filters:        map[string]*filter{},
		logger:         logger,
		reg:            reg,
		pm:             newPromMetrics(reg),
		currentMetrics: map[metricLabels]uint64{},
	}
}

// validate checks what readConf can't. Filters on one interface with the same
// description, expr and mode share their metric labels, which would mix up
// their counts.
func (c config) validate() error {
	type key struct {
		description, expr string
		monitor           bool
	}
	for _, ifname := range slices.Sorted(maps.Keys(c.Interfaces)) {
		seen := map[key]int{}
		for i, bdf := range c.Interfaces[ifname].BPFDropFilters {
			k := key{bdf.Description, bdf.Expr, bdf.Monitor}
			if first, ok := seen[k]; ok {
				return fmt.Errorf("%s: filters %d and %d have the same description, expr and monitor setting", ifname, first, i)
			}
			seen[k] = i
		}
	}
	return nil
}

// readConf reads and parses the config file. It has no side effects, so a
// broken config can never leave the daemon half way between two configs.
func readConf(path string) (conf config, err error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return config{}, fmt.Errorf("readConf: unable to OpenRoot: %w", err)
	}
	defer func() {
		cErr := root.Close()
		if cErr != nil {
			err = errors.Join(err, fmt.Errorf("closing config root: %w", cErr))
		}
	}()

	confBytes, err := root.ReadFile(filepath.Base(path))
	if err != nil {
		return config{}, err
	}

	err = json.Unmarshal(confBytes, &conf)
	if err != nil {
		return config{}, fmt.Errorf("parsing %s: %w", path, err)
	}

	return conf, nil
}

func main() {
	unloadFlag := flag.Bool("unload", false, "detach all running filters, remove all pins and exit")
	configFlag := flag.String("config", "sunet-xdpd.json", "config file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With(
		slog.String("version", version),
		slog.String("go_version", runtime.Version()),
	)

	if *unloadFlag {
		// Works from what is pinned, so it does not need a (valid) config.
		err := unloadAll(logger, defaultPinDir)
		if err != nil {
			logger.Error("unloadAll failed", "error", err.Error())
			os.Exit(1)
		}
		return
	}

	xd := newXdpd(*configFlag, defaultPinDir, logger)
	err := xd.run()
	if err != nil {
		logger.Error("run failed", "error", err.Error())
		os.Exit(1)
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

// run loads the filters and attaches them (or takes over a running filter).
// The config is re-read on SIGHUP and it exits on SIGINT or SIGTERM, or when
// someone runs -unload. Exiting only closes file descriptors, the pinned
// filter keeps running.
//
// A failing initial load is an error, but a failing reload is only logged:
// the filters that are running keep running.
func (xd *xdpd) run() error {
	// Register before loading anything, so an early SIGHUP doesn't kill the process.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP, os.Interrupt, syscall.SIGTERM)

	xd.reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	promMux := http.NewServeMux()
	promServer := &http.Server{
		Addr:           "127.0.0.1:2112",
		Handler:        promMux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	promMux.Handle("/metrics", promhttp.HandlerFor(xd.reg, promhttp.HandlerOpts{}))

	go func() {
		xd.logger.Info("starting prometheus listener", "listen_addr", promServer.Addr)
		if err := promServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			// Error starting or closing listener:
			xd.logger.Error("HTTP server ListenAndServe", "error", err.Error())
		}
	}()
	defer func() {
		xd.logger.Info("shutting down prometheus listener", "listen_addr", promServer.Addr)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := promServer.Shutdown(ctx); err != nil {
			// Error from closing listeners, or context timeout:
			xd.logger.Error("HTTP server Shutdown", "error", err.Error())
		}
	}()

	// Create the directory where we create pin files.
	if err := os.MkdirAll(xd.pinDir, 0o700); err != nil {
		return fmt.Errorf("creating %s (is bpffs mounted at /sys/fs/bpf?): %w", xd.pinDir, err)
	}

	conf, err := readConf(xd.confPath)
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}
	if err := xd.apply(conf); err != nil {
		if !errors.Is(err, errCleanup) {
			return fmt.Errorf("loading filters: %w", err)
		}
		xd.logger.Warn("filters loaded", "error", err.Error())
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if pin := xd.removedPin(); pin != "" {
				xd.logger.Info("pin removed (-unload?), exiting", "pin", pin)
				return nil
			}
			xd.updateMetrics()

		case sig := <-sigs:
			if pin := xd.removedPin(); pin != "" {
				xd.logger.Info("pin removed (-unload?), exiting", "pin", pin)
				return nil
			}

			if sig != syscall.SIGHUP {
				xd.logger.Info("exiting; the filters stay attached (stop them with -unload)")
				return nil
			}

			xd.reload()
		}
	}
}

// reload applies the config file to the running filters. Nothing is
// changed if the config can't be read or if any filter fails to build, see apply.
func (xd *xdpd) reload() {
	conf, err := readConf(xd.confPath)
	if err != nil {
		xd.logger.Error("reload failed, keeping the running filters", "error", err.Error())
		return
	}

	err = xd.apply(conf)
	switch {
	case err == nil:
		xd.logger.Info("reload done")
	case errors.Is(err, errCleanup):
		xd.logger.Warn("reload done", "error", err.Error())
	default:
		xd.logger.Error("reload failed", "error", err.Error())
	}
}

// removedPin returns the path of a pin that is gone because someone ran
// -unload (or removed it by hand) while this process was running, or "". The
// pin directory counts too: without it a daemon with no filters, like after
// reloading an empty config, would never notice an -unload.
func (xd *xdpd) removedPin() string {
	if pathMissing(xd.pinDir) {
		return xd.pinDir
	}
	for _, f := range xd.filters {
		if f.unloaded() {
			return f.linkPin
		}
	}
	return ""
}

func pathMissing(path string) bool {
	_, err := os.Stat(path)
	return errors.Is(err, os.ErrNotExist)
}

// filter is the loaded state: the attached program and its counters.
// The hook maps are shared by every program version, so a running
// xdpcap session keeps working across reloads.
type filter struct {
	pinDir                string
	linkPin               string
	iface                 *net.Interface
	linkType              layers.LinkType
	dropHook, monitorHook *ebpf.Map
	link                  link.Link
	prog                  *ebpf.Program
	counters              *ebpf.Map
	bpfDropFilters        []bpfDropFilter
}

// pendingFilter is a new program for an interface that is built but not live.
type pendingFilter struct {
	f              *filter // the running filter to update, or a new one that isn't attached yet
	isNew          bool
	iface          *net.Interface
	linkType       layers.LinkType
	bpfDropFilters []bpfDropFilter
	prog           *ebpf.Program
	counters       *ebpf.Map
	swap           swapKind
	newPins        []string      // hook pins created by prepare, as opposed to found from a previous run
	prev           *ebpf.Program // for tookOverPinned: the program that was running, to put back
}

// swapKind says how a pendingFilter was made live, which decides how to undo it.
type swapKind int

const (
	notSwapped     swapKind = iota
	swappedInPlace          // the program of the link we already had was replaced
	attachedFresh           // we created and pinned a new link
	tookOverPinned          // the program of a link a previous run left pinned was replaced, see prev
)

// closePrev releases the handle on the program that a takeover replaced.
func (p *pendingFilter) closePrev(logger *slog.Logger) {
	if p.prev != nil {
		logClose(logger, "previous program", p.prev)
		p.prev = nil
	}
}

// discard releases what prepare created.
func (p *pendingFilter) discard(logger *slog.Logger) {
	p.closePrev(logger)
	if p.prog != nil {
		logClose(logger, "pending program", p.prog)
	}
	if p.counters != nil {
		logClose(logger, "pending counters", p.counters)
	}
	if p.isNew {
		logClose(logger, "pending drop hook", p.f.dropHook)
		logClose(logger, "pending monitor hook", p.f.monitorHook)

		// Nothing will ever find these again, but pins from a previous run
		// stay since they may be in use by xdpcap.
		for _, pin := range p.newPins {
			if err := os.Remove(pin); err != nil && !errors.Is(err, os.ErrNotExist) {
				logger.Error("removing hook pin created for a filter that was not loaded failed", "pin", pin, "error", err.Error())
			}
		}
	}
}

// errCleanup is wrapped in what apply returns when conf is running but cleaning
// up after interfaces that are no longer in it failed.
var errCleanup = errors.New("the new config is running, but cleaning up after interfaces no longer in it failed")

// apply makes conf what is running, in steps so a broken config doesn't leave
// things half changed:
//
//  1. prepare builds and loads a program for every interface. This changes
//     nothing that is running, if anything fails here the error is returned
//     and the previous filters keep running untouched.
//  2. swapAll makes the new programs live, one interface at a time, without
//     retiring anything. The kernel can still refuse here (e.g. the driver
//     rejects the program), in which case the interfaces that were already
//     swapped are put back and the error is returned.
//  3. Only when every swap has worked are the previous programs retired and
//     the interfaces no longer in conf detached, including ones a previous
//     run left pinned. Errors from this step wrap errCleanup.
//
// Putting a swap back can fail too, then the error says so and that
// interface is kept track of as running the new program.
func (xd *xdpd) apply(conf config) error {
	xd.logger.Info("loading filters")

	pending, err := xd.prepare(conf)
	if err != nil {
		return err
	}

	if err := xd.swapAll(pending); err != nil {
		for _, p := range pending {
			if p.swap != notSwapped {
				// Putting it back failed, so it is still running the new
				// program. That is what has to be tracked from here on.
				xd.retire(p)
				continue
			}
			p.discard(xd.logger)
		}
		return err
	}

	for _, p := range pending {
		xd.retire(p)
	}

	// Before the loop below, so the interfaces it removes are still tracked
	// and not taken for orphans.
	errs := xd.removeOrphans(conf)

	for ifname, f := range xd.filters {
		if _, ok := conf.Interfaces[ifname]; ok {
			continue
		}
		xd.logger.Info("unloading interface no longer being filtered by config", "iface", ifname)
		if err := detachPinnedLink(xd.logger, f.linkPin); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ifname, err))
			if !errors.Is(err, errPinRemains) {
				continue // still attached and counting, try again on the next reload
			}
		}

		// Nothing is counted after the detach, so this is the final count. Read
		// it before release closes the counters.
		xd.collect(ifname, f.counters, f.bpfDropFilters, nil)

		// It is detached now, so forget it even if cleaning up fails below. The
		// link pin is gone, so keeping it would look like an -unload behind our
		// back to removedPin and make us exit.
		delete(xd.filters, ifname)
		if err := f.release(xd.logger, pinKinds); err != nil {
			// Harmless leftovers: they are reused if the interface is added
			// again, and removed by -unload or the next removeOrphans.
			errs = append(errs, fmt.Errorf("%s: removing pins: %w", ifname, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%w: %w", errCleanup, errors.Join(errs...))
	}
	return nil
}

// removeOrphans detaches and removes what is pinned for interfaces that are
// neither in conf nor tracked: those removed from the config while the daemon
// wasn't running, and leftovers of a cleanup that failed earlier.
func (xd *xdpd) removeOrphans(conf config) []error {
	entries, err := os.ReadDir(xd.pinDir)
	if err != nil {
		return []error{fmt.Errorf("listing pins in %s: %w", xd.pinDir, err)}
	}

	orphans := map[string]struct{}{}
	for _, e := range entries {
		ifname, ok := pinOwner(e.Name())
		if !ok {
			continue
		}
		if _, ok := conf.Interfaces[ifname]; ok {
			continue
		}
		if _, ok := xd.filters[ifname]; ok {
			continue
		}
		orphans[ifname] = struct{}{}
	}

	var errs []error
	for _, ifname := range slices.Sorted(maps.Keys(orphans)) {
		xd.logger.Info("unloading interface that is pinned but not in the config", "iface", ifname)
		if err := detachPinnedLink(xd.logger, pinPath(xd.pinDir, ifname, "link")); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ifname, err))
			if !errors.Is(err, errPinRemains) {
				continue // still attached, keep its pins and try again next time
			}
		}
		if err := removePins(xd.pinDir, ifname, pinKinds); err != nil {
			errs = append(errs, fmt.Errorf("%s: removing pins: %w", ifname, err))
		}
	}
	return errs
}

// pinOwner returns the interface a pin file name like "eth0-link" belongs to.
func pinOwner(name string) (string, bool) {
	for _, kind := range pinKinds {
		if ifname, ok := strings.CutSuffix(name, "-"+kind); ok && ifname != "" {
			return ifname, true
		}
	}
	return "", false
}

// swapAll makes the prepared programs live. If one fails, the ones that were
// already swapped are undone, newest first.
func (xd *xdpd) swapAll(pending []*pendingFilter) error {
	for i, p := range pending {
		err := xd.swap(p)
		if err == nil {
			continue
		}

		errs := []error{fmt.Errorf("%s: %w", p.iface.Name, err)}
		xd.logger.Error("swapping in the new program failed, putting back the previous ones", "iface", p.iface.Name, "error", err.Error())
		for _, done := range slices.Backward(pending[:i]) {
			if uErr := xd.undo(done); uErr != nil {
				errs = append(errs, fmt.Errorf("%s: putting back the previous program: %w", done.iface.Name, uErr))
			}
		}
		return errors.Join(errs...)
	}
	return nil
}

// prepare builds a program for every interface in conf without changing
// anything that is running.
func (xd *xdpd) prepare(conf config) (pending []*pendingFilter, err error) {
	defer func() {
		if err != nil {
			for _, p := range pending {
				p.discard(xd.logger)
			}
			pending = nil
		}
	}()

	if err := conf.validate(); err != nil {
		return nil, err
	}

	// In order, so the same config gives the same behaviour every time.
	for _, ifname := range slices.Sorted(maps.Keys(conf.Interfaces)) {
		ifConf := conf.Interfaces[ifname]
		iface, err := net.InterfaceByName(ifname)
		if err != nil {
			return pending, fmt.Errorf("getting interface %s: %w", ifname, err)
		}

		// What XDP's data pointer points at depends on the device type, and
		// every filter's byte offsets depend on that.
		linkType, err := linkTypeFor(iface.Name)
		if err != nil {
			return pending, err
		}

		p := &pendingFilter{
			f:              xd.filters[ifname],
			iface:          iface,
			linkType:       linkType,
			bpfDropFilters: ifConf.BPFDropFilters,
		}

		if p.f == nil {
			p.isNew = true
			p.f, p.newPins, err = xd.newFilter(iface, linkType)
			if err != nil {
				return pending, err
			}
		}
		pending = append(pending, p)

		p.prog, p.counters, err = buildProgramAndCounters(xd.logger, iface, linkType, p.bpfDropFilters, p.f.dropHook, p.f.monitorHook)
		if err != nil {
			return pending, fmt.Errorf("%s: %w", ifname, err)
		}
	}

	return pending, nil
}

// newFilter opens the xdpcap hooks of iface, reusing pinned hooks if they
// exist so xdpcap paths stay valid across restarts. It also returns the pins
// it had to create.
func (xd *xdpd) newFilter(iface *net.Interface, linkType layers.LinkType) (*filter, []string, error) {
	var created []string

	dropPin := pinPath(xd.pinDir, iface.Name, "drop")
	dropHook, dropCreated, err := openHook(xd.logger, dropPin)
	if err != nil {
		return nil, nil, err
	}
	if dropCreated {
		created = append(created, dropPin)
	}

	monitorPin := pinPath(xd.pinDir, iface.Name, "monitor")
	monitorHook, monitorCreated, err := openHook(xd.logger, monitorPin)
	if err != nil {
		logClose(xd.logger, "drop hook", dropHook)
		if dropCreated {
			if rErr := os.Remove(dropPin); rErr != nil {
				xd.logger.Error("removing drop hook pin failed", "pin", dropPin, "error", rErr.Error())
			}
		}
		return nil, nil, err
	}
	if monitorCreated {
		created = append(created, monitorPin)
	}

	return &filter{
		pinDir:      xd.pinDir,
		linkPin:     pinPath(xd.pinDir, iface.Name, "link"),
		iface:       iface,
		linkType:    linkType,
		dropHook:    dropHook,
		monitorHook: monitorHook,
	}, created, nil
}

// buildProgramAndCounters creates the counter map and loads the XDP program
// for bpfDropFilters, without attaching it to anything.
func buildProgramAndCounters(logger *slog.Logger, iface *net.Interface, linkType layers.LinkType, bpfDropFilters []bpfDropFilter, dropHook, monitorHook *ebpf.Map) (*ebpf.Program, *ebpf.Map, error) {
	logger.Info("building program", "iface", iface.Name)

	// Fix G115 (CWE-190): integer overflow conversion int -> uint32 (Confidence: MEDIUM, Severity: HIGH)
	intMaxEntries := len(bpfDropFilters)
	if intMaxEntries < 0 || intMaxEntries > math.MaxUint32 {
		return nil, nil, fmt.Errorf("the number of bpfDropFilters does not fit in MaxEntries uint32")
	}
	maxEntries := uint32(intMaxEntries)
	counterName := fmt.Sprintf("%s_filter_counters", iface.Name)
	counters, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       counterName,
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: uint32(max(maxEntries, 1)), // a zero-size map fails to create
	})
	if err != nil {
		return nil, nil, fmt.Errorf("creating counters map '%s': %w", counterName, err)
	}
	success := false
	defer func() {
		if !success {
			logClose(logger, "counters", counters)
		}
	}()

	insns, err := buildProgram(bpfDropFilters, linkType, dropHook, monitorHook, counters)
	if err != nil {
		return nil, nil, err
	}

	progSpec := &ebpf.ProgramSpec{
		Name:         fmt.Sprintf("sunet_xdpd_%s", iface.Name),
		Type:         ebpf.XDP,
		License:      "GPL",
		Instructions: insns,
	}

	// Fix e.g. "ens3: single-buffer XDP requires MTU less than 3506" on interfaces with a large MTU.
	// I noticed the program will fail to load if this is used on "lo" so skip that interface
	if iface.Name != "lo" {
		progSpec.Flags = unix.BPF_F_XDP_HAS_FRAGS
	}

	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		// The verifier log is the key to debugging hand-built programs,
		// check for it first since it can wrap EINVAL too.
		if ve, found := errors.AsType[*ebpf.VerifierError](err); found {
			return nil, nil, fmt.Errorf("loading program: %+v", ve)
		}
		if errors.Is(err, unix.EINVAL) {
			return nil, nil, fmt.Errorf("loading program failed: invalid argument (check if the network driver or kernel version lacks BPF_F_XDP_HAS_FRAGS support): %w", err)
		}
		return nil, nil, fmt.Errorf("loading program: %w", err)
	}

	success = true
	return prog, counters, nil
}

// swap makes the prepared program the live one: it attaches it (taking over
// a pinned link from a previous run if there is one) or atomically replaces
// the running program. Nothing is retired, so it can be undone, see undo. On
// error the previous program keeps running.
func (xd *xdpd) swap(p *pendingFilter) error {
	f := p.f

	if f.link != nil && (f.iface.Index != p.iface.Index || isDetached(f.link)) {
		// The kernel detaches the link when the device goes away, like when
		// it is recreated (tun, WireGuard, hotplug) or moved to another network
		// namespace. It can come back with the same ifindex, so that alone
		// doesn't tell. Update fails on a detached link, attach makes a new one.
		xd.logger.Warn("link was detached from the interface, attaching again", "iface", p.iface.Name, "old_ifindex", f.iface.Index, "ifindex", p.iface.Index)
		logClose(xd.logger, "stale link", f.link)
		f.link = nil
	}
	f.iface, f.linkType = p.iface, p.linkType

	if f.link != nil {
		// Update swaps the program in place: packets go from the old program
		// straight to the new one, with no unfiltered window in between.
		xd.logger.Info("updating filter", "iface", f.iface.Name)
		if err := f.link.Update(p.prog); err != nil {
			return fmt.Errorf("replacing program: %w", err)
		}
		p.swap = swappedInPlace
		return nil
	}

	prev, err := f.attach(xd.logger, p.prog)
	if err != nil {
		if !p.isNew {
			// The link was detached, and attach has already unpinned it. What is left has no link pin, which removedPin
			// would take for an -unload. A later reload tries again.
			if fErr := xd.forget(f); fErr != nil {
				err = errors.Join(err, fErr)
			}
		}
		return err
	}
	p.swap = attachedFresh
	if prev != nil {
		p.swap = tookOverPinned
		p.prev = prev
	}
	return nil
}

// undo puts back what swap changed. The filter still tracks the previous
// program, since nothing has been retired yet.
func (xd *xdpd) undo(p *pendingFilter) error {
	f := p.f

	var errs []error
	switch p.swap {
	case swappedInPlace:
		if err := f.link.Update(f.prog); err != nil {
			return err
		}

	case attachedFresh:
		if err := detachPinnedLink(xd.logger, f.linkPin); err != nil {
			errs = append(errs, err)
			if !errors.Is(err, errPinRemains) {
				return errors.Join(errs...) // still attached
			}
		}
		logClose(xd.logger, "link", f.link)
		f.link = nil

		if !p.isNew {
			// Its old link had been detached by the kernel, so there is
			// nothing to put back: it had no filter before this either. Keeping it would look like an
			// -unload behind our back to removedPin, since the link pin
			// is gone. A later reload tries again.
			errs = append(errs, xd.forget(f))
		}

	case tookOverPinned:
		// The link stays pinned and keeps filtering with the program it had.
		if err := f.link.Update(p.prev); err != nil {
			return err
		}
		logClose(xd.logger, "link", f.link)
		f.link = nil
	}

	p.swap = notSwapped
	p.closePrev(xd.logger)
	return errors.Join(errs...) // nil errors are dropped
}

// forget stops keeping track of an interface that is still in the config but
// has no link anymore, and releases what it holds, taking what its counters
// have counted first. A later reload attaches it from scratch. The xdpcap hook
// pins stay: that reload reuses them, so a running xdpcap keeps working.
func (xd *xdpd) forget(f *filter) error {
	xd.collect(f.iface.Name, f.counters, f.bpfDropFilters, nil)
	delete(xd.filters, f.iface.Name)
	if err := f.release(xd.logger, []string{"link", "counters"}); err != nil {
		return fmt.Errorf("removing pins: %w", err)
	}
	return nil
}

// retire makes the swapped-in program of p the one the filter keeps track of,
// and retires the one it replaced. Call it when every swap has worked.
func (xd *xdpd) retire(p *pendingFilter) {
	f := p.f

	oldProg, oldCounters, oldBPFDropFilters := f.prog, f.counters, f.bpfDropFilters
	f.prog, f.counters, f.bpfDropFilters = p.prog, p.counters, p.bpfDropFilters
	if p.isNew {
		xd.filters[f.iface.Name] = f
	}

	// Packets keep being counted in the old map until the swap, so what it
	// has counted since the last updateMetrics has to be collected now, after
	// the swap and before the map is closed below.
	if oldCounters != nil {
		xd.collect(f.iface.Name, oldCounters, oldBPFDropFilters, nil)
	}

	// The new counters start from zero, so the baseline we compute deltas
	// against has to as well.
	for ml := range xd.currentMetrics {
		if ml.ifaceName == f.iface.Name {
			xd.currentMetrics[ml] = 0
		}
	}

	if oldProg != nil {
		logClose(xd.logger, "old program", oldProg)
	}
	if oldCounters != nil {
		if uErr := oldCounters.Unpin(); uErr != nil {
			xd.logger.Error("unable to unpin old counters", "error", uErr.Error())
		}
		logClose(xd.logger, "old counters", oldCounters)
	}

	counterPin := pinPath(f.pinDir, f.iface.Name, "counters")
	if rErr := os.Remove(counterPin); rErr != nil && !errors.Is(rErr, os.ErrNotExist) { // Pin fails if a stale pin exists
		xd.logger.Error("removing stale counters pin failed", "counters_pin", counterPin, "error", rErr.Error())
	}
	if pErr := f.counters.Pin(counterPin); pErr != nil {
		// Not fatal: filtering works, only outside inspection is affected.
		xd.logger.Warn("pinning counters", "counters_pin", counterPin, "error", pErr.Error())
	}

	how := "updated"
	switch p.swap {
	case attachedFresh:
		how = "attached"
	case tookOverPinned:
		how = "took over running filter"
	}
	p.closePrev(xd.logger)

	xd.logger.Info("filter attachment", "how", how, "on", f.iface.Name, "link_type", linkTypeName(f.linkType), "num_filters", len(p.bpfDropFilters), "pins_dir", f.pinDir)
}

// attach takes over the pinned link if a previous run left one, swapping
// in prog without a gap. Otherwise it attaches prog and pins the link so
// filtering outlives this process. If it took over a link it returns the
// program that was running, which the caller must close or put back.
func (f *filter) attach(logger *slog.Logger, prog *ebpf.Program) (prev *ebpf.Program, err error) {
	logger.Info("attach()", "iface", f.iface.Name)

	l, err := link.LoadPinnedLink(f.linkPin, nil)
	switch {
	case err == nil:
		prev, err := f.adopt(logger, l, prog)
		if err != nil {
			return nil, err
		}
		if prev != nil {
			return prev, nil
		}
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("opening pinned link: %w", err)
	}

	logger.Info("link is missing, attaching XDP", "iface", f.iface.Name)
	l, err = link.AttachXDP(link.XDPOptions{Program: prog, Interface: f.iface.Index})
	if err != nil {
		// If we fail here the error message can be fairly opaque, a tip is to check dmesg, e.g. I have seen:
		// "failed to attach link: create link: invalid argument" which turned up in dmesg like so:
		// ===
		// virtio_net virtio1 ens3: single-buffer XDP requires MTU less than 3506
		// ===
		return nil, fmt.Errorf("attaching XDP for %s: %w", f.iface.Name, err)
	}
	logger.Info("creating pin", "iface", f.iface.Name, "link_pin", f.linkPin)
	if err := l.Pin(f.linkPin); err != nil {
		logClose(logger, "link not pinned yet, so this detaches again", l)
		return nil, fmt.Errorf("pinning link: %w", err)
	}

	f.link = l
	return nil, nil
}

// adopt swaps prog into the link a previous run left pinned and returns the
// program that was running, so the swap can be undone. It returns nil (and no
// error) for a link that is detached from its interface: that pin has been
// removed, so the caller can attach and pin a new one.
func (f *filter) adopt(logger *slog.Logger, l link.Link, prog *ebpf.Program) (prev *ebpf.Program, err error) {
	info, err := l.Info()
	if err != nil {
		logClose(logger, f.linkPin, l)
		return nil, fmt.Errorf("inspecting pinned link: %w", err)
	}

	xdp := info.XDP()
	switch {
	case xdp == nil:
		logClose(logger, f.linkPin, l)
		return nil, fmt.Errorf("%s is not an XDP link; unload it first", f.linkPin)

	case xdp.Ifindex == 0:
		// The xdp Ifindex being 0 indicates the pin file
		// exists in the filesystem but is in a detached state
		// (we called Detach() on it), it is still a valid link
		// file but it does not actually reference the interface it once
		// did anymore.
		logger.Warn("found detached link file, unpinning it", "link_pin", f.linkPin)
		uErr := l.Unpin()
		logClose(logger, f.linkPin, l)
		if uErr != nil {
			return nil, fmt.Errorf("unpinning detached link %s: %w", f.linkPin, uErr)
		}
		return nil, nil

	case int(xdp.Ifindex) != f.iface.Index:
		logClose(logger, f.linkPin, l)
		return nil, fmt.Errorf("%s is attached to a different interface; unload it first", f.linkPin)
	}

	// Hold on to the running program, Update drops the link's reference to it.
	prev, err = ebpf.NewProgramFromID(info.Program)
	if err != nil {
		logClose(logger, f.linkPin, l)
		return nil, fmt.Errorf("getting the program running on %s: %w", f.linkPin, err)
	}

	logger.Info("updating existing pin", "iface", f.iface.Name, "link_pin", f.linkPin)
	if err := l.Update(prog); err != nil {
		logClose(logger, "previous program", prev)
		logClose(logger, f.linkPin, l)
		return nil, fmt.Errorf("replacing running program: %w", err)
	}
	f.link = l
	return prev, nil
}

// Close only closes file descriptors. The link, counters and hooks stay
// pinned, so the kernel keeps filtering after this process exits.
func (f *filter) Close() error {
	var errs []error
	if f.link != nil {
		errs = append(errs, closeErr("link", f.link))
	}
	if f.prog != nil {
		errs = append(errs, closeErr("prog", f.prog))
	}
	if f.counters != nil {
		errs = append(errs, closeErr("counters", f.counters))
	}
	if f.dropHook != nil {
		errs = append(errs, closeErr("drop hook", f.dropHook))
	}
	if f.monitorHook != nil {
		errs = append(errs, closeErr("monitor hook", f.monitorHook))
	}
	return errors.Join(errs...) // nil errors are dropped
}

func closeErr(what string, c io.Closer) error {
	if err := c.Close(); err != nil {
		return fmt.Errorf("%s close failed: %w", what, err)
	}
	return nil
}

// unloaded reports whether someone ran -unload (or removed the pins)
// while this process was running.
func (f *filter) unloaded() bool {
	return pathMissing(f.linkPin)
}

// release is for a filter that has been detached (see detachPinnedLink). It
// releases the file descriptors and removes the pins of the given kinds.
func (f *filter) release(logger *slog.Logger, kinds []string) error {
	if err := f.Close(); err != nil {
		logger.Error("closing removed filter failed", "iface", f.iface.Name, "error", err.Error())
	}
	return removePins(f.pinDir, f.iface.Name, kinds)
}

// removePins removes the pins of the given kinds (see pinKinds) for ifname. A
// missing file is fine.
func removePins(dir, ifname string, kinds []string) error {
	var errs []error
	for _, kind := range kinds {
		err := os.Remove(pinPath(dir, ifname, kind))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// errPinRemains is wrapped in what detachPinnedLink returns when the filter
// was detached but its link pin could not be removed. Unlike other errors from
// it the filter is no longer attached, and removing the pin can be tried again.
var errPinRemains = errors.New("detached, but the link pin remains")

// detachPinnedLink detaches the XDP program of the link pinned at linkPin and
// removes the pin. Nothing pinned is not an error. If the pin can't be removed
// after the detach the error wraps errPinRemains.
func detachPinnedLink(logger *slog.Logger, linkPin string) error {
	l, err := link.LoadPinnedLink(linkPin, nil)
	switch {
	case err == nil:
		defer logClose(logger, linkPin, l)

		// Detach works even if a running sunet-xdpd still holds a
		// reference open, this will however leave the pin file in
		// /sys/fs/bpf, we unpin it further down to actually clean up
		// the file. A link that is detached already (e.g. by the kernel when the
		// interface was removed, or by an earlier attempt that couldn't unpin it)
		// goes straight to the unpinning.
		if !isDetached(l) {
			if err := l.Detach(); err != nil {
				return fmt.Errorf("detaching %s: %w", linkPin, err)
			}
			logger.Info("detached filter", "link_pin", linkPin)
		}

		// Do not leave a detached link file in the directory, it will
		// make us find it and and try to use it, only to have the XDP
		// info in it return ifindex 0 which of course does not match
		// the interface we are configuring it with (e.g. even "lo" starts
		// at 0x1).
		if err := l.Unpin(); err != nil {
			return fmt.Errorf("%w: unpinning %s: %w", errPinRemains, linkPin, err)
		}
		logger.Info("removed link pin", "link_pin", linkPin)
	case errors.Is(err, os.ErrNotExist):
		logger.Info("no filter attached", "link_pin", linkPin)
	default:
		return fmt.Errorf("opening pinned link %s: %w", linkPin, err)
	}

	return nil
}

// isDetached reports whether l is an XDP link that no longer is attached to
// an interface.
func isDetached(l link.Link) bool {
	info, err := l.Info()
	if err != nil {
		return false
	}
	xdp := info.XDP()
	return xdp != nil && xdp.Ifindex == 0
}

// unloadAll detaches every filter pinned in pinDir and removes all pins. It
// goes by what is pinned and not by the config, so it works with a missing or
// broken config and for interfaces that have since left the config.
func unloadAll(logger *slog.Logger, pinDir string) error {
	links, err := filepath.Glob(filepath.Join(pinDir, "*-link"))
	if err != nil {
		return fmt.Errorf("listing link pins in %s: %w", pinDir, err)
	}

	var errs []error
	stillAttached := false
	for _, linkPin := range links {
		if err := detachPinnedLink(logger, linkPin); err != nil {
			errs = append(errs, err)
			if !errors.Is(err, errPinRemains) {
				stillAttached = true
			}
		}
	}
	if stillAttached {
		// Keep the pins of what is still attached so -unload can be retried.
		return errors.Join(errs...)
	}

	// Everything is detached now, removing the directory also gets rid of any
	// pin that could not be removed above.
	if err := os.RemoveAll(pinDir); err != nil {
		errs = append(errs, fmt.Errorf("removing pin dir %s: %w", pinDir, err))
	}
	return errors.Join(errs...)
}

// logClose closes c and logs a failure, for cleanup where there is nothing
// better to do with the error. c must not be nil.
func logClose(logger *slog.Logger, what string, c io.Closer) {
	if err := c.Close(); err != nil {
		logger.Error("close failed", "what", what, "error", err.Error())
	}
}

// updateMetrics adds what the running programs have counted since the last
// time to the prometheus metrics, and removes metrics of filters that are gone.
func (xd *xdpd) updateMetrics() {
	seenMetrics := map[metricLabels]struct{}{}
	for _, f := range xd.filters {
		xd.collect(f.iface.Name, f.counters, f.bpfDropFilters, seenMetrics)
	}

	// Remove metrics that refer to label sets that no longer match a filter
	for ml := range xd.currentMetrics {
		if _, found := seenMetrics[ml]; !found {
			deleted := xd.pm.filterHits.DeleteLabelValues(ml.ifaceName, ml.description, ml.expr, ml.mode)
			if deleted {
				xd.logger.Info("deleted metrics for removed filter", "iface", ml.ifaceName, "description", ml.description, "expr", ml.expr, "mode", ml.mode)
			} else {
				xd.logger.Error("unable to delete metrics for unmanaged interface", "iface", ml.ifaceName)
			}
			delete(xd.currentMetrics, ml)
		}
	}
}

// collect adds what counters (a per-CPU array with one counter per entry in
// bpfDropFilters) has counted since the last time to the prometheus metrics. The
// metrics it touched are added to seen, if that is not nil.
func (xd *xdpd) collect(ifname string, counters *ebpf.Map, bpfDropFilters []bpfDropFilter, seen map[metricLabels]struct{}) {
	for i, bfd := range bpfDropFilters {
		mode := "drop"
		if bfd.Monitor {
			mode = "monitor"
		}

		ml := metricLabels{
			ifaceName:   ifname,
			description: bfd.Description,
			expr:        bfd.Expr,
			mode:        mode,
		}

		if seen != nil {
			seen[ml] = struct{}{}
		}

		var perCPU []uint64
		if err := counters.Lookup(uint32(i), &perCPU); err != nil {
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

		xd.pm.filterHits.WithLabelValues(ml.ifaceName, ml.description, ml.expr, ml.mode).Add(float64(delta))
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
		prog = append(prog, countFilter(counters, i)...)

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

// countFilter does counters[i]++ on a per-CPU array.
func countFilter(counters *ebpf.Map, i int) asm.Instructions {
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
func linkTypeFor(ifname string) (linkType layers.LinkType, err error) {
	rootDir := "/sys/class/net"
	// sysfs has symlinks in many locations so doing OpenRoot() on rootDir fails
	// when looking up e.g. "lo" that is itself a symlink pointing outside it.
	root, err := os.OpenRoot("/sys")
	if err != nil {
		return 0, fmt.Errorf("linkTypeFor(): unable to open root dir %s: %w", rootDir, err)
	}
	defer func() {
		cErr := root.Close()
		if cErr != nil {
			err = errors.Join(err, fmt.Errorf("closing /sys root: %w", cErr))
		}
	}()

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

// openHook returns the pinned xdpcap hook map at path, creating and pinning
// it if it doesn't exist yet. It reports whether it created it.
func openHook(logger *slog.Logger, path string) (m *ebpf.Map, created bool, err error) {
	name := filepath.Base(path)

	m, err = ebpf.LoadPinnedMap(path, nil)
	if err == nil {
		if m.Type() != ebpf.ProgramArray {
			logClose(logger, path, m)
			return nil, false, fmt.Errorf("%s exists but is not an xdpcap hook", path)
		}
		return m, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("opening %s hook: %w", name, err)
	}

	hook, err := xdpcap.NewHook(path)
	if err != nil {
		return nil, false, fmt.Errorf("creating %s hook: %w", name, err)
	}
	if err := hook.Pin(); err != nil {
		logClose(logger, name, hook)
		return nil, false, fmt.Errorf("pinning %s hook: %w", name, err)
	}
	// The Hook only wraps this map; closing the map releases everything.
	return hook.Map(), true, nil
}
