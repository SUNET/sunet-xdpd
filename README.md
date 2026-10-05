# sunet-xdpd

This is a daemon that reads config files that describe BPF (tcpdump) filter
expressions that should be applied to a network interface via XDP. Each filter
has an action, `drop` or `pass`, which is what happens to a packet the filter
matches.

The tool relies heavily on the Cloudflare
[cbpfc](https://github.com/cloudflare/cbpfc) library for generating eBPF from
classic BPF. On top of this we use
[gopacket](https://github.com/google/gopacket) to allow us the write actual BPF
filter strings (like you would do when using tcpdump) which it then compiles
into the BPF instructions that `cbpfc` wants.

The filters of an interface are tried in order and the first one that matches
a packet decides what happens to it; a packet no filter matches is passed. An
empty `expr` matches every packet, so a last filter with an empty `expr` sets
the default action, for example to only let some traffic through:
```json
{
  "interfaces": {
    "eth0": {
      "bpf_filters": [
        {"description": "Allow SSH", "expr": "tcp dst port 22", "action": "pass"},
        {"description": "Allow DNS replies", "expr": "udp src port 53", "action": "pass"},
        {"description": "Drop the rest", "expr": "", "action": "drop"}
      ]
    }
  }
}
```

A given filter can be applied in a "monitor" mode, and when this is done the
matches are counted but the filter does not decide anything: the filters after
it are still tried, as if it did not match. This can be helpful for figuring
out the impact of adding a given filter.

The eBPF code is instrumented to call hook maps for
[xdpcap](https://github.com/cloudflare/xdpcap), so that you can capture pcap of
matched packets for further analysis. There is one hook per interface for
packets a filter dropped or passed (`<ifname>-filter`, use `-actions` to pick
one of them) and one for packets that only matched filters in monitor mode
(`<ifname>-monitor`), e.g. for eth0:
```
xdpcap -actions drop /sys/fs/bpf/sunet-xdpd/eth0-filter - "" | tcpdump -nr -
xdpcap -actions drop /sys/fs/bpf/sunet-xdpd/eth0-filter - "tcp and port 80" | tcpdump -nr -
xdpcap -actions drop /sys/fs/bpf/sunet-xdpd/eth0-filter dropped.pcap "tcp and port 80"
xdpcap -actions pass /sys/fs/bpf/sunet-xdpd/eth0-filter - "" | tcpdump -nr -
xdpcap /sys/fs/bpf/sunet-xdpd/eth0-monitor - "" | tcpdump -nr -
```

Matched packets are counted per filter and are visible in prometheus metrics
available at 127.0.0.1:2112/metrics, labelled with the interface, description,
expr, action and whether the filter is in monitor mode, e.g.:
```
curl http://127.0.0.1:2112/metrics | grep ^filter
```

## Configuration
The config is read from every `*.json` file in the directory given by
`-config-dir` (default `/etc/sunet-xdpd/conf.d`), and the filters for an
interface are appended across files. This way separate processes can each own a
file, for example:
```
/etc/sunet-xdpd/conf.d/00-base.json   # from config management
/etc/sunet-xdpd/conf.d/50-ddos.json   # from a DDoS mitigation tool
```

See [conf.d.sample](conf.d.sample) for the file format. The rules are:

* Files are read in name order, sorted as strings, so `10-x.json` comes before
  `9-x.json`. Names starting with `.`, other suffixes and directories are
  skipped.
* To change a file, write a temporary file starting with `.` in the same
  directory and rename it into place, so a half written file is never read.
  Then reload with `pkill -HUP sunet-xdpd`, once all files of a change are in
  place.
* A reload is all or nothing: if any file is broken (invalid JSON, an unknown
  field or one given twice, a filter without an `action` or an `expr`, an
  action other than `drop` or `pass`, an expression that doesn't compile)
  nothing changes and the error, naming the file, is logged. A broken file
  from one writer blocks changes from all of them until it is fixed.
* `action` and `expr` have no defaults, they must be given for every filter.
  `"expr": ""` is allowed and matches every packet.
* Two filters on one interface with the same description, expr, action and
  monitor setting are an error, also when they are in different files.
* Filters after one with an empty `expr` that is not in monitor mode could
  never match, so they are an error, also when they are in a later file. Put a
  default filter in a file that sorts last, like `99-default.json`.
* Removing a file removes its filters on the next reload. A directory without
  `*.json` files is an error rather than detaching every filter, so to run
  without filters use a file containing `{}`, or `sunet-xdpd -unload`.
* The log line after a load or reload lists the files that were read and how
  many filters each added.

## Building
The Dockerfile is not meant for creating a container, rather it is a way to
more easily build a static executable even when the google/gopacket dependency
requires use of CGO and needs to link with libpcap for BPF expression compilation.
This way we do not have to care about installing libpcap on machines running the tool.

Example for building binaries for two different targets with binaries ending up
in the "dist" directory can look like this:
```
docker buildx build --platform linux/amd64,linux/arm64 -o dist .
```

## Formatting and linting
When working with this code at least the following tools are expected to be
run at the top level directory prior to commiting:

* `gofumpt -l -w .` (see [gofumpt](https://github.com/mvdan/gofumpt))
* `go vet ./...`
* `staticcheck ./...` (see [staticcheck](https://staticcheck.io))
* `gosec ./...` (see [gosec](https://github.com/securego/gosec))
* `golangci-lint run` (see [golangci-lint](https://golangci-lint.run))
* `go test ./...`
* `govulncheck ./...` (see [govulncheck](https://go.dev/doc/tutorial/govulncheck))
