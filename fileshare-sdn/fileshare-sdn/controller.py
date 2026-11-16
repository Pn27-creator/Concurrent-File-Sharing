#!/usr/bin/env python3
"""SDN controller for the file-sharing network (OpenFlow 1.0, Python stdlib only).

    python3 controller.py                       # listens on 0.0.0.0:6653
    python3 controller.py --policy policy.json --interval 2

SDN in one paragraph
--------------------
The *data plane* (an Open vSwitch inside Mininet) forwards or drops packets by
looking them up in a flow table.  The *control plane* (this program) decides
what is in that table.  When the switch connects, this controller sends it
FLOW_MOD messages:  "packets matching X -> do Y".  Later it sends
STATS_REQUEST messages and the switch answers with a packet counter and a byte
counter for every rule -- that is the bandwidth monitoring.

The policy (policy.json) is turned into these rules:

    priority 200  BLOCK  client -> server:port        action: drop
    priority 100  ALLOW  client -> server:port        action: forward (NORMAL)
    priority 100  ALLOW  server:port -> client        action: forward (NORMAL)
    priority  10  ARP (and optionally ICMP)           action: forward (NORMAL)
    priority   0  everything else                     action: drop

NORMAL means "behave like an ordinary learning switch" (Open vSwitch does the
MAC learning itself), so the controller only has to describe *policy*, not
routing.  Edit policy.json while this runs and the new rules are installed
within one polling interval.

This is an *network-level* rule (may this host's TCP packets reach the file
service at all?).  It is different from the login/permission checks inside
the server (may this *user* read this *file*?).
"""

import argparse
import csv
import ipaddress
import json
import logging
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("controller")

# --- OpenFlow 1.0 constants (from the specification) -------------------------
OFP_VERSION = 0x01
OFPT_HELLO, OFPT_ERROR = 0, 1
OFPT_ECHO_REQUEST, OFPT_ECHO_REPLY = 2, 3
OFPT_FEATURES_REQUEST, OFPT_FEATURES_REPLY = 5, 6
OFPT_PACKET_IN = 10
OFPT_FLOW_MOD = 14
OFPT_STATS_REQUEST, OFPT_STATS_REPLY = 16, 17
OFPT_BARRIER_REQUEST, OFPT_BARRIER_REPLY = 18, 19

OFPST_FLOW = 1
OFPFC_ADD, OFPFC_DELETE = 0, 3
OFPP_NORMAL = 0xFFFA        # "act like a normal learning switch"
OFPP_NONE = 0xFFFF
NO_BUFFER = 0xFFFFFFFF

# Wildcard bits of ofp_match: a set bit means "do not look at this field".
OFPFW_IN_PORT, OFPFW_DL_VLAN, OFPFW_DL_SRC, OFPFW_DL_DST = 1 << 0, 1 << 1, 1 << 2, 1 << 3
OFPFW_DL_TYPE, OFPFW_NW_PROTO, OFPFW_TP_SRC, OFPFW_TP_DST = 1 << 4, 1 << 5, 1 << 6, 1 << 7
OFPFW_NW_SRC_SHIFT, OFPFW_NW_DST_SHIFT = 8, 14          # 6-bit "ignore N low bits"
OFPFW_ALL = (1 << 22) - 1

# ofp_match is 40 bytes: wildcards, in_port, dl_src, dl_dst, dl_vlan, dl_vlan_pcp,
# pad, dl_type, nw_tos, nw_proto, pad, nw_src, nw_dst, tp_src, tp_dst.
MATCH = struct.Struct("!IH6s6sHBxHBB2xIIHH")
HEADER = struct.Struct("!BBHI")                        # version, type, length, xid
FLOW_STATS = struct.Struct("!HBx40sIIHHH6xQQQ")        # 88 bytes, then actions

ETH_IP, ETH_ARP = 0x0800, 0x0806
IP_ICMP, IP_TCP = 1, 6


# --- building and reading OpenFlow messages ----------------------------------
def build_match(dl_type=None, nw_proto=None, nw_src=None, nw_dst=None,
                tp_src=None, tp_dst=None):
    """An ofp_match that looks only at the fields given (all others wildcarded)."""
    wildcards = OFPFW_ALL
    if dl_type is not None:
        wildcards &= ~OFPFW_DL_TYPE
    if nw_proto is not None:
        wildcards &= ~OFPFW_NW_PROTO
    if nw_src is not None:
        wildcards &= ~(0x3F << OFPFW_NW_SRC_SHIFT)       # 0 ignored bits = exact
    if nw_dst is not None:
        wildcards &= ~(0x3F << OFPFW_NW_DST_SHIFT)
    if tp_src is not None:
        wildcards &= ~OFPFW_TP_SRC
    if tp_dst is not None:
        wildcards &= ~OFPFW_TP_DST
    ip = lambda s: int(ipaddress.IPv4Address(s)) if s else 0
    return MATCH.pack(wildcards, 0, b"\0" * 6, b"\0" * 6, 0, 0,
                      dl_type or 0, 0, nw_proto or 0, ip(nw_src), ip(nw_dst),
                      tp_src or 0, tp_dst or 0)


def decode_match(raw):
    """Turn an ofp_match back into {field: value} for the fields it looks at."""
    (wc, _in_port, _dl_src, _dl_dst, _vlan, _pcp, dl_type, _tos, nw_proto,
     nw_src, nw_dst, tp_src, tp_dst) = MATCH.unpack(raw)
    fields = {}
    if not wc & OFPFW_DL_TYPE:
        fields["dl_type"] = dl_type
    if not wc & OFPFW_NW_PROTO:
        fields["nw_proto"] = nw_proto
    for name, value, shift in (("nw_src", nw_src, OFPFW_NW_SRC_SHIFT),
                               ("nw_dst", nw_dst, OFPFW_NW_DST_SHIFT)):
        ignored = (wc >> shift) & 0x3F
        if ignored == 0:
            fields[name] = str(ipaddress.IPv4Address(value))
        elif ignored < 32:
            fields[name] = f"{ipaddress.IPv4Address(value)}/{32 - ignored}"
    if not wc & OFPFW_TP_SRC:
        fields["tp_src"] = tp_src
    if not wc & OFPFW_TP_DST:
        fields["tp_dst"] = tp_dst
    return fields


def header(msg_type, length, xid):
    return HEADER.pack(OFP_VERSION, msg_type, length, xid)


def flow_mod(match, priority, port=None, command=OFPFC_ADD, xid=0):
    """FLOW_MOD: add (or delete) a rule.  port=None means 'drop' (no action)."""
    actions = struct.pack("!HHHH", 0, 8, port, 0) if port is not None else b""  # OUTPUT
    body = match + struct.pack("!QHHHHIHH", 0, command, 0, 0, priority,
                               NO_BUFFER, OFPP_NONE, 0) + actions
    return header(OFPT_FLOW_MOD, 8 + len(body), xid) + body


def flow_stats_request(xid):
    """STATS_REQUEST for every flow: 'send me your counters'."""
    body = struct.pack("!HH", OFPST_FLOW, 0) + build_match() + struct.pack("!BxH", 0xFF, OFPP_NONE)
    return header(OFPT_STATS_REQUEST, 8 + len(body), xid) + body


def parse_flow_stats(body):
    """Entries of a flow-stats reply -> [(priority, match_raw, packets, bytes)]."""
    entries, offset = [], 0
    while offset + FLOW_STATS.size <= len(body):
        (length, _table, match_raw, _sec, _nsec, priority, _idle, _hard,
         _cookie, packets, nbytes) = FLOW_STATS.unpack_from(body, offset)
        if length < FLOW_STATS.size:
            break
        entries.append((priority, match_raw, packets, nbytes))
        offset += length
    return entries


# --- policy -> rules ---------------------------------------------------------
@dataclass
class Rule:
    priority: int
    fields: dict
    forward: bool
    label: str

    @property
    def key(self):
        return (self.priority, tuple(sorted(self.fields.items())))

    def message(self, xid=0):
        return flow_mod(build_match(**self.fields), self.priority,
                        OFPP_NORMAL if self.forward else None, xid=xid)


def load_policy(path):
    policy = json.loads(Path(path).read_text(encoding="utf-8"))
    service = policy["service"]
    ipaddress.IPv4Address(service["ip"])
    if not 0 < int(service["port"]) < 65536:
        raise ValueError("service.port must be 1-65535")
    for name in ("allow", "block"):
        for ip in policy.get(name, []):
            ipaddress.IPv4Address(ip)
    if policy.get("default_action", "drop") not in ("drop", "forward"):
        raise ValueError("default_action must be 'drop' or 'forward'")
    return policy


def build_rules(policy):
    server_ip, port = policy["service"]["ip"], int(policy["service"]["port"])
    rules = [Rule(0, {}, policy.get("default_action", "drop") == "forward",
                  "DEFAULT everything else: " + policy.get("default_action", "drop")),
             Rule(10, {"dl_type": ETH_ARP}, True, "ARP (address resolution)")]
    if policy.get("allow_icmp", True):
        rules.append(Rule(10, {"dl_type": ETH_IP, "nw_proto": IP_ICMP}, True, "ICMP (ping)"))

    def pair(client, priority, forward, word):
        to_server = {"dl_type": ETH_IP, "nw_proto": IP_TCP, "nw_src": client,
                     "nw_dst": server_ip, "tp_dst": port}
        to_client = {"dl_type": ETH_IP, "nw_proto": IP_TCP, "nw_src": server_ip,
                     "nw_dst": client, "tp_src": port}
        return [Rule(priority, to_server, forward, f"{word} {client} -> {server_ip}:{port}"),
                Rule(priority, to_client, forward, f"{word} {server_ip}:{port} -> {client}")]

    for client in policy.get("allow", []):
        rules += pair(client, 100, True, "ALLOW")
    for client in policy.get("block", []):          # higher priority: block wins
        rules += pair(client, 200, False, "BLOCK")
    return rules


# --- one connected switch ----------------------------------------------------
class SwitchSession:
    def __init__(self, controller, sock, addr):
        self.c = controller
        self.sock = sock
        self.addr = addr
        self.send_lock = threading.Lock()
        self.xid = 0
        self.dpid = None
        self.rule_index = {}
        self.previous = {}          # rule key -> (time, bytes)
        self.pending = []           # stats entries when a reply arrives in parts
        self.last_printed = None
        self.policy_mtime = None
        self.alive = True

    def send(self, data):
        with self.send_lock:
            self.sock.sendall(data)

    def next_xid(self):
        self.xid += 1
        return self.xid

    def recv_exact(self, n):
        data = bytearray()
        while len(data) < n:
            part = self.sock.recv(n - len(data))
            if not part:
                raise ConnectionError("switch closed the connection")
            data.extend(part)
        return bytes(data)

    def run(self):
        try:
            self.send(header(OFPT_HELLO, 8, self.next_xid()))
            threading.Thread(target=self.poll_loop, daemon=True).start()
            while True:
                version, msg_type, length, xid = HEADER.unpack(self.recv_exact(8))
                body = self.recv_exact(length - 8) if length > 8 else b""
                self.handle(msg_type, xid, body)
        except (ConnectionError, OSError) as error:
            log.info("switch %s disconnected (%s)", self.dpid_text(), error)
        finally:
            self.alive = False
            self.sock.close()

    def dpid_text(self):
        return f"{self.dpid:016x}" if self.dpid is not None else str(self.addr)

    def handle(self, msg_type, xid, body):
        if msg_type == OFPT_HELLO:
            self.send(header(OFPT_FEATURES_REQUEST, 8, self.next_xid()))
        elif msg_type == OFPT_ECHO_REQUEST:                 # keep-alive from the switch
            self.send(header(OFPT_ECHO_REPLY, 8 + len(body), xid) + body)
        elif msg_type == OFPT_FEATURES_REPLY:
            self.dpid = struct.unpack_from("!Q", body, 0)[0]
            log.info("switch %s connected from %s", self.dpid_text(), self.addr[0])
            self.install_policy()
        elif msg_type == OFPT_STATS_REPLY:
            kind, flags = struct.unpack_from("!HH", body, 0)
            if kind == OFPST_FLOW:
                self.pending += parse_flow_stats(body[4:])
                if not flags & 1:                           # last part of the reply
                    entries, self.pending = self.pending, []
                    self.report(entries)
        elif msg_type == OFPT_BARRIER_REPLY:
            log.info("switch %s: all %d rules are in place", self.dpid_text(), len(self.rule_index))
        elif msg_type == OFPT_ERROR:
            err_type, err_code = struct.unpack_from("!HH", body, 0)
            log.error("switch %s reported an OpenFlow error: type=%d code=%d",
                      self.dpid_text(), err_type, err_code)
        # PACKET_IN and everything else: ignored (the default rule drops them)

    # -- policy ----------------------------------------------------------------
    def install_policy(self):
        try:
            self.policy_mtime = os.stat(self.c.policy_path).st_mtime_ns
            policy = load_policy(self.c.policy_path)
        except (OSError, ValueError, KeyError) as error:
            # Keep the rules already in the switch; try again when the file changes.
            log.error("cannot use policy (keeping the current rules): %s", error)
            return
        rules = build_rules(policy)
        # Start from a clean table: delete every existing rule, then add ours.
        self.send(flow_mod(build_match(), 0, None, OFPFC_DELETE, self.next_xid()))
        for rule in rules:
            self.send(rule.message(self.next_xid()))
        self.send(header(OFPT_BARRIER_REQUEST, 8, self.next_xid()))
        self.rule_index = {rule.key: rule for rule in rules}
        self.previous.clear()
        log.info("policy installed: service %s:%s  allow=%s  block=%s  default=%s",
                 policy["service"]["ip"], policy["service"]["port"],
                 policy.get("allow", []), policy.get("block", []),
                 policy.get("default_action", "drop"))

    def poll_loop(self):
        """Every interval: pick up policy edits, then ask the switch for counters."""
        while self.alive:
            time.sleep(self.c.interval)
            if self.dpid is None or not self.alive:
                continue
            try:
                mtime = os.stat(self.c.policy_path).st_mtime_ns
                if self.policy_mtime is not None and mtime != self.policy_mtime:
                    log.info("policy.json changed: re-installing rules")
                    self.install_policy()
                self.send(flow_stats_request(self.next_xid()))
            except OSError:
                return

    # -- bandwidth monitoring ------------------------------------------------------
    def report(self, entries):
        now = time.time()
        rows = []
        for priority, match_raw, packets, nbytes in entries:
            fields = decode_match(match_raw)
            key = (priority, tuple(sorted(fields.items())))
            rule = self.rule_index.get(key)
            label = rule.label if rule else f"other rule {fields} (priority {priority})"
            rate = 0.0
            if key in self.previous:
                then, old_bytes = self.previous[key]
                delta = nbytes - old_bytes if nbytes >= old_bytes else nbytes
                rate = delta * 8 / 1e6 / (now - then) if now > then else 0.0
            self.previous[key] = (now, nbytes)
            rows.append((priority, label, packets, nbytes, rate))
        rows.sort(key=lambda r: (-r[0], r[1]))
        self.c.log_stats(self.dpid_text(), now, rows)
        busy = [r for r in rows if r[2] > 0]
        signature = [(r[1], r[3]) for r in busy]
        if busy and signature != self.last_printed:         # print only when something moved
            self.last_printed = signature
            self.c.print_table(self.dpid_text(), busy)


# --- the controller ----------------------------------------------------------
class Controller:
    def __init__(self, host, port, policy_path, interval, stats_csv):
        self.host, self.port = host, port
        self.policy_path = policy_path
        self.interval = interval
        self.stats_csv = Path(stats_csv) if stats_csv else None
        self.csv_lock = threading.Lock()
        self.ready = threading.Event()
        self.listener = None
        if self.stats_csv:
            self.stats_csv.parent.mkdir(parents=True, exist_ok=True)
            with self.stats_csv.open("w", newline="") as f:
                csv.writer(f).writerow(["time", "switch", "rule", "packets", "bytes", "mbit_per_s"])

    def log_stats(self, switch, now, rows):
        if not self.stats_csv:
            return
        with self.csv_lock, self.stats_csv.open("a", newline="") as f:
            writer = csv.writer(f)
            for _priority, label, packets, nbytes, rate in rows:
                if packets:
                    writer.writerow([f"{now:.3f}", switch, label, packets, nbytes, f"{rate:.3f}"])

    def print_table(self, switch, rows):
        print(f"\n[{time.strftime('%H:%M:%S')}] switch {switch}: rule counters (cumulative) and current rate")
        print(f"  {'RULE':<44}{'PACKETS':>10}{'BYTES':>14}{'Mbit/s':>9}")
        for _priority, label, packets, nbytes, rate in rows:
            print(f"  {label:<44}{packets:>10}{nbytes:>14}{rate:>9.2f}")

    def serve_forever(self):
        with socket.socket() as listener:
            self.listener = listener
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.host, self.port))
            self.port = listener.getsockname()[1]
            listener.listen(8)
            log.info("OpenFlow controller listening on %s:%d (policy: %s)",
                     self.host, self.port, self.policy_path)
            self.ready.set()
            while True:
                try:
                    sock, addr = listener.accept()
                except OSError:
                    return
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                threading.Thread(target=SwitchSession(self, sock, addr).run,
                                 daemon=True).start()


def main():
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="OpenFlow 1.0 controller for the file-sharing network")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=6653)
    parser.add_argument("--policy", default=str(here / "policy.json"))
    parser.add_argument("--interval", type=float, default=2.0,
                        help="seconds between counter polls / policy checks")
    parser.add_argument("--stats-csv", default=str(here / "logs" / "flow_stats.csv"),
                        help="append per-rule counters here ('' to disable)")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
    try:
        load_policy(args.policy)
    except (OSError, ValueError, KeyError) as error:
        raise SystemExit(f"Cannot read policy {args.policy}: {error}")
    try:
        Controller(args.host, args.port, args.policy, args.interval, args.stats_csv).serve_forever()
    except KeyboardInterrupt:
        log.info("Controller stopped")


if __name__ == "__main__":
    main()
