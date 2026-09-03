# trepd

Small IPv4/IPv6 route exchange daemon using the TREP protocol over TCP.

The lower peer address listens and the higher address connects. Routes received
from the peer are installed in the local main routing table through the tunnel
interface.

Use `mk_router.sh` to deploy locally and remotely, compile, and run against each other.
Router never re-advertises other routes learned from `trepd`.

Motivation was to have a simple, self-deploying, yet automatic means to exchange 
routes between two hosts, for example, over a `tuntom` tunnel.

## Build

    g++ -std=c++17 -O2 -Wall -Wextra -Wpedantic trepd.cpp -o trepd

The two-host setup is normally started with:

    sudo -E ./mk_router.sh <id> <host|user@host> [options...]

## Directional policy

The complete route-selection and filtering pipeline is described in the
Export pipeline and directional options section below.

## Export pipeline and directional options

The outbound route pipeline is:

    kernel routing table
            |
            +-- --to-peer-filter
            +-- --to-peer-static / --to-peer-connected
            |
            +-- --export-filter
            |
            v
          TCP peer

### --to-peer-filter PREFIX

Selects kernel routes contained in PREFIX.

It is an initial route selector. It is combined with the other
to-peer selectors as an OR condition:

    --to-peer-filter 10.0.0.0/8
    --to-peer-static

This selects routes matching the prefix filter OR routes classified as
static.

The option affects only routes read from the kernel routing table. It does
not affect explicit --to-peer-route injections.

The IPv6 form is --to-peer-filter6 PREFIX.

### --to-peer-static

Selects kernel routes whose protocol is static, boot, or unspecified. Routes
with scope link are excluded from this selector.

The IPv6 form is --to-peer-static6.

### --to-peer-connected

Selects kernel routes whose protocol is kernel. The IPv6 form is
--to-peer-connected6.

### --to-peer-default

Explicitly allows the default route. The default route is otherwise never
selected implicitly, even when --to-peer-static or --to-peer-connected is
enabled.

The IPv6 form is --to-peer-default6.

### --to-peer-route PREFIX

Explicitly injects PREFIX into the outbound snapshot. The prefix does not
need to exist in the local routing table.

An explicit route bypasses --export-filter completely. This is intentional:
--to-peer-route is an explicit instruction to advertise a specific route.

The IPv6 form is --to-peer-route6.

### --export-filter PREFIX

This is the final outbound allow-list. It runs after the kernel route
selectors and immediately before route serialization and TCP transmission.

For kernel routes, a route must pass both the to-peer selection and the
export filter:

    to-peer selection AND export-filter

Multiple --export-filter options are combined as OR:

    --export-filter 10.0.0.0/8
    --export-filter 192.168.0.0/16

Explicit --to-peer-route routes bypass this check.

The IPv6 form is --export-filter6.

### --from-peer-* options

These options are available in mk_router.sh. They configure the remote
process by translating to the corresponding --to-peer-* option:

    --from-peer-route       -> remote --to-peer-route
    --from-peer-static      -> remote --to-peer-static
    --from-peer-connected   -> remote --to-peer-connected
    --from-peer-default     -> remote --to-peer-default

IPv6 options use the 6 suffix.

There is deliberately no --from-peer-filter. Filtering of received routes is
handled locally by --import-filter.

### --import-filter PREFIX

This is the final inbound allow-list. It runs after a valid route frame is
decoded and immediately before the route is placed into the pending snapshot
for installation in the local routing table.

A received route must pass --import-filter to be installed. Multiple import
filters are combined as OR.

The IPv6 form is --import-filter6.

### Typical combinations

Export only selected static routes in a prefix:

    --to-peer-static --export-filter 10.0.0.0/8

Inject a route regardless of the local kernel table and regardless of the
export filter:

    --to-peer-route 1.1.1.1/32 --export-filter 10.0.0.0/8

Request static routes from the remote peer, but install only selected
received prefixes locally:

    --from-peer-static --import-filter 10.0.0.0/8

## mk_router.sh

Default TCP port is 43000 + ID, so ID 42 uses port 43042. This is separate
from tuntom's usual UDP port 42042.

TREP_PORT overrides the port. TREP_DISTANCE overrides the metric assigned to
received routes.

mk_router.sh passes to-peer and final filters only to the local process.
from-peer selectors are translated to to-peer selectors on the remote process.
Transport and logging options are passed to both processes.

It also idempotently ensures the mapping

    100 trepd

in /etc/iproute2/rt_protos on both hosts.

## Logging and reconnect

    --debug
    --quiet

The daemon has bounded TCP, netlink, and connect waits. TCP connect timeout is
5 seconds, TCP send/receive timeout is 5 seconds, TCP user timeout is 10 seconds,
keepalive starts after 10 seconds idle, and reconnect delay is 2 seconds.

If the tunnel interface disappears, trepd waits for it, refreshes its ifindex,
and recreates the listener when necessary.

Logs from mk_router.sh are:

    /tmp/trepd-<id>-client.log
    /tmp/trepd-<id>-server.log

## Wireshark

Load trepd.lua with:

    wireshark -X lua_script:trepd.lua

The dissector recognizes TCP ports 43001 through 43255. For a custom port use
Decode As and select TREP. It displays messages such as:

    TREP  ROUTE4 1.1.1.1/32

Suggested coloring filter:

    trepd.type == 3 || trepd.type == 4

## Troubleshooting

    ss -ltnp | grep 430
    ip route show proto trepd
    ip -6 route show proto trepd

Use --debug and inspect both client and server logs.
