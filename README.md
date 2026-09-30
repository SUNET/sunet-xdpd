# sunet-xdpd

This is a daemon that reads a config file that describes BPF (tcpdump) filter
expressions that should be applied to a network interface via XDP, and when the
filter is matched the matching packet is dropped.

The tool relies heavily on the Cloudflare
[cbpfc](https://github.com/cloudflare/cbpfc) library for generating eBPF from
classic BPF. On top of this we use
[gopacket](https://github.com/google/gopacket) to allow us the write actual BPF
filter strings (like you would do when using tcpdump) which it then compiles
into the BPF instructions that `cbpfc` wants.

A given filter can be applied in a "monitor" mode, and when this is done the
packets are matched but not dropped, which can be helpful for figuring out the
impact of adding a given filter.

The eBPF code is instrumented to call hook maps for
[xdpcap](https://github.com/cloudflare/xdpcap), so that you can capture pcap of
matched packets for further analysis:
```
xdpcap /sys/fs/bpf/sunet-xdpd/drop - "" | tcpdump -nr -
xdpcap /sys/fs/bpf/sunet-xdpd/drop - "tcp and port 80" | tcpdump -nr -
xdpcap /sys/fs/bpf/sunet-xdpd/drop dropped.pcap "tcp and port 80"
```

Matched packets are counted per filter and are visible in prometheus metrics
available at 127.0.0.1:2112/metrics, e.g.:
```
curl http://127.0.0.1:2112/metrics | grep ^filter
```

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
