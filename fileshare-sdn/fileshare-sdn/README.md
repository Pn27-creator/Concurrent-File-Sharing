# Concurrent File Sharing System: SDN (Mininet + OpenFlow)

This package is the *network* part of the project: a virtual network, an OpenFlow controller that decides
which hosts may reach the file service, and a monitor that reads the switch's packet/byte counters.
It needs a Linux machine (a VM is fine) with Mininet and Open vSwitch:

```bash
sudo apt install mininet openvswitch-switch      # Ubuntu / Debian
sudo service openvswitch-switch start
```

The controller itself is plain Python 3.8+ with **no dependencies** (it speaks OpenFlow 1.0 directly), so there is
nothing to `pip install`.

```
fileshare-sdn/
  controller.py        OpenFlow 1.0 controller: installs rules from policy.json, polls counters
  policy.json          the network policy (which clients may reach the service)
  topology.py          Mininet topology + scripted demo (sudo)
  net_worker.py        helper started on each Mininet host during the performance test
  tests/test_controller.py   tests the controller with a fake switch (no Mininet needed)
```

## Run the demo

Unzip `fileshare-server`, `fileshare-client` and `fileshare-sdn` **side by side** (same parent folder).

```bash
# terminal 1: the controller (leave it running; it prints counters as traffic flows)
cd fileshare-sdn
python3 controller.py

# terminal 2: the network, the file server, and the scripted demo
cd fileshare-sdn
sudo python3 topology.py demo            # options: --bw 10  --sizes 1MB,5MB  --skip-live-policy
sudo python3 topology.py cli             # same network, but you get the "mininet>" prompt
```

If a run was interrupted and Mininet complains, clean up with `sudo mn -c`.

Topology: `h1` 10.0.0.1, `h2` 10.0.0.2, `h3` 10.0.0.3 (clients) and `srv` 10.0.0.100 (runs the file server) around
one Open vSwitch `s1`, all links limited to 10 Mbit/s by default so throughput numbers mean something.
Users on the server: h1 = alice, h2 = bob, h3 = carol (from `manage_users.py demo-users`).

## What the demo shows

1. **SDN allow/block.** Clients h1 and h2 reach the file service; h3 is blocked *by the switch*, so its TCP
   connection simply times out. The BLOCK rule's counter shows h3's dropped packets.
2. **Application-level access control, across that network.** bob (h2) is allowed to reach the server
   but still cannot download alice's private file; public and shared files work; wrong passwords fail.
   This is the key distinction: the *network rule* decides whether packets reach the service at all, the
   *server's authorization check* decides which files an authenticated user may read.
3. **Live policy change.** `policy.json` is edited (h2 added to the block list), the controller notices within
   one polling interval, re-programs the switch, h2 is cut off; the file is then restored and h2 returns.
4. **Evaluation.** For several file sizes, 1 then 2 simultaneous clients: time per client, per-client and
   aggregate throughput, and the switch counters for the same transfer next to the file bytes. The
   switch figure is larger because it counts Ethernet/IP/TCP headers, the TCP handshake and the login/command
   messages; the opposite-direction rule holds the ACK traffic.

## policy.json

```json
{ "service": { "ip": "10.0.0.100", "port": 5000 },
  "allow": ["10.0.0.1", "10.0.0.2"],
  "block": ["10.0.0.3"],
  "default_action": "drop",
  "allow_icmp": true }
```

It becomes these OpenFlow rules (highest priority wins):

| Priority | Match | Action |
|---|---|---|
| 200 | TCP client -> server:port, and server:port -> client, for each `block` IP | drop |
| 100 | the same two directions, for each `allow` IP | forward (`NORMAL` = ordinary learning switch) |
| 10 | ARP (and ICMP if `allow_icmp`) | forward |
| 0 | everything else | drop (`default_action`) |

Edit the file while the controller runs and the new rules are installed within one polling interval
(`--interval`, default 2 s). A syntactically wrong edit is ignored (the old rules stay) and an error is logged.
`topology.py` must use the same policy file as the controller (both default to `./policy.json`).
Rule counters are also appended to `logs/flow_stats.csv` (time, rule, packets, bytes, Mbit/s).

## Look at the switch yourself

```text
mininet> sh ovs-ofctl -O OpenFlow10 dump-flows s1       # the rules and their n_packets / n_bytes
mininet> h3 python3 ../fileshare-client/client.py --host 10.0.0.100 probe     # times out: blocked
mininet> h1 python3 ../fileshare-client/client.py --host 10.0.0.100 --user alice --password alice123 shell
```

Try Wireshark/tcpdump on `s1-eth1` to see the plain-text login on an unencrypted server, then start the server
with TLS (see the server README) and compare.

## Tests and what has been verified

`python3 tests/test_controller.py` connects a fake OpenFlow 1.0 switch to the controller and checks the handshake,
the exact rules installed, message sizes, multi-part statistics replies, counter labelling, the CSV log, live policy
reload and recovery from a bad policy edit.

Not verified: this package was written and tested without Mininet or Open vSwitch available, so the
controller's messages have been checked against the OpenFlow 1.0 specification and a fake switch, and `topology.py`
against a stand-in for Mininet, but not against real Open vSwitch. If something differs on your VM, the most likely
places are: the switch not connecting (check the controller is running and `--controller-port` is 6653), or a
different `ovs-ofctl dump-flows` output format (the parser is `FLOW_RE` in `topology.py`; the controller log shows the
same counters independently).

## Troubleshooting

* *"The switch did not connect to a controller"*: start `controller.py` first; check nothing else uses port 6653.
* *Controller logs `OpenFlow error: type=... code=...`*: the switch rejected a rule; send me that line.
* *`Cannot find the server`*: unzip the three packages side by side or use `--server-dir` / `--client-dir`.
* *Leftover interfaces / "File exists" errors*: `sudo mn -c`.
