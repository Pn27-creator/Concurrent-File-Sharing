#!/usr/bin/env python3
"""Tests the controller WITHOUT Mininet by connecting a fake OpenFlow 1.0 switch.

    python3 tests/test_controller.py

The fake switch decodes the controller's messages with its own, independent
struct offsets (taken from the OpenFlow 1.0 specification), keeps a flow table,
decides what happens to synthetic packets, counts them, and answers the
controller's statistics requests.  It checks that the controller

  * completes the handshake and answers keep-alive echoes,
  * installs the allow / block / default rules described by policy.json,
  * reads (multi-part) flow statistics and labels every rule correctly,
  * writes bandwidth figures to the CSV log,
  * re-installs rules when policy.json changes, and keeps the old rules if the
    edit is invalid.

It cannot prove that real Open vSwitch accepts the messages -- run the Mininet
demo for that.
"""

import csv
import ipaddress
import json
import socket
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from controller import Controller  # noqa: E402

RESULTS = []


def check(name, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  -- {detail}" if detail and not ok else ""))
    RESULTS.append(bool(ok))


def wait_for(condition, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if condition():
            return True
        time.sleep(0.02)
    return False


def ip_int(s):
    return int(ipaddress.IPv4Address(s))


class FakeSwitch:
    """A tiny OpenFlow 1.0 switch."""

    def __init__(self, port, dpid=0xABCDEF):
        self.dpid = dpid
        self.sock = socket.create_connection(("127.0.0.1", port))
        self.flows = []
        self.lock = threading.Lock()
        self.messages = []          # (type, length) of everything received
        self.barriers = 0
        self.echo_reply = None
        self.stats_requests = 0
        threading.Thread(target=self.loop, daemon=True).start()
        self.send(0, 0, 1, b"")     # HELLO (type 0)

    # -- wire ------------------------------------------------------------------
    def send(self, msg_type, length_extra, xid, body):
        self.sock.sendall(struct.pack("!BBHI", 1, msg_type, 8 + len(body), xid) + body)

    def recv_exact(self, n):
        data = b""
        while len(data) < n:
            part = self.sock.recv(n - len(data))
            if not part:
                raise ConnectionError
            data += part
        return data

    def loop(self):
        try:
            while True:
                version, mtype, length, xid = struct.unpack("!BBHI", self.recv_exact(8))
                body = self.recv_exact(length - 8)
                self.messages.append((mtype, length))
                if version != 1:
                    raise AssertionError("controller must speak OpenFlow 1.0")
                if mtype == 5:      # FEATURES_REQUEST -> FEATURES_REPLY (32 bytes, no ports)
                    self.send(6, 0, xid, struct.pack("!QIB3xII", self.dpid, 256, 1, 0, 0))
                elif mtype == 14:   # FLOW_MOD
                    self.flow_mod(length, body)
                elif mtype == 18:   # BARRIER_REQUEST
                    self.barriers += 1
                    self.send(19, 0, xid, b"")
                elif mtype == 16:   # STATS_REQUEST
                    self.stats_requests += 1
                    self.reply_stats(xid, body)
                elif mtype == 3:    # ECHO_REPLY
                    self.echo_reply = (xid, body)
        except (ConnectionError, OSError):
            pass

    # -- flow table (decoded with explicit offsets from the spec) -------------------
    def flow_mod(self, length, body):
        match = body[:40]
        wildcards, = struct.unpack_from("!I", match, 0)
        dl_type, = struct.unpack_from("!H", match, 22)
        nw_proto = match[25]
        nw_src, nw_dst, tp_src, tp_dst = struct.unpack_from("!IIHH", match, 28)
        cookie, command, idle, hard, priority, buffer_id, out_port, flags = struct.unpack_from("!QHHHHIHH", body, 40)
        actions = body[64:]
        with self.lock:
            if command == 3:                              # OFPFC_DELETE (non-strict, match all)
                assert wildcards == (1 << 22) - 1, "delete must wildcard everything"
                self.flows.clear()
                return
            assert command == 0 and buffer_id == 0xFFFFFFFF
            if actions:
                atype, alen, aport, _ = struct.unpack("!HHHH", actions)
                assert (atype, alen) == (0, 8) and len(actions) == 8
                forward = aport == 0xFFFA                 # OFPP_NORMAL
                assert forward, "only NORMAL output expected"
            else:
                forward = False
            self.flows.append({
                "raw_match": match, "wc": wildcards, "dl_type": dl_type, "nw_proto": nw_proto,
                "nw_src": nw_src, "nw_dst": nw_dst, "tp_src": tp_src, "tp_dst": tp_dst,
                "priority": priority, "forward": forward, "packets": 0, "bytes": 0,
                "actions": actions, "length": length,
            })

    def rule_matches(self, f, pkt):
        wc = f["wc"]
        if not wc & (1 << 4) and f["dl_type"] != pkt["dl_type"]:
            return False
        if not wc & (1 << 5) and f["nw_proto"] != pkt.get("proto", -1):
            return False
        for name, shift in (("nw_src", 8), ("nw_dst", 14)):
            if ((wc >> shift) & 0x3F) == 0 and f[name] != pkt.get(name, -1):
                return False
        if not wc & (1 << 6) and f["tp_src"] != pkt.get("sport", -1):
            return False
        if not wc & (1 << 7) and f["tp_dst"] != pkt.get("dport", -1):
            return False
        return True

    def packets(self, count, size, **pkt):
        """Send `count` packets of `size` bytes through the table; return the verdict."""
        pkt.setdefault("dl_type", 0x0800)
        for key in ("nw_src", "nw_dst"):
            if isinstance(pkt.get(key), str):
                pkt[key] = ip_int(pkt[key])
        with self.lock:
            best = None
            for f in self.flows:
                if self.rule_matches(f, pkt) and (best is None or f["priority"] > best["priority"]):
                    best = f
            if best is None:
                return "miss"
            best["packets"] += count
            best["bytes"] += count * size
            return "forward" if best["forward"] else "drop"

    def tcp(self, src, dst, sport, dport, count=1, size=1514):
        return self.packets(count, size, nw_src=src, nw_dst=dst, proto=6, sport=sport, dport=dport)

    def reply_stats(self, xid, body):
        assert struct.unpack_from("!HH", body, 0) == (1, 0), "expected a flow-stats request"
        assert len(body) == 4 + 44
        with self.lock:
            entries = []
            for f in self.flows:
                length = 88 + len(f["actions"])
                entries.append(struct.pack("!HBx40sIIHHH6xQQQ", length, 0, f["raw_match"], 5, 0,
                                           f["priority"], 0, 0, 0, f["packets"], f["bytes"]) + f["actions"])
        half = max(1, len(entries) // 2)                   # send in two parts (MORE flag)
        self.send(17, 0, xid, struct.pack("!HH", 1, 1) + b"".join(entries[:half]))
        self.send(17, 0, xid, struct.pack("!HH", 1, 0) + b"".join(entries[half:]))

    def close(self):
        self.sock.close()


def read_csv(path):
    with open(path) as f:
        return list(csv.DictReader(f))


def main():
    tmp = Path(tempfile.mkdtemp(prefix="sdn-test-"))
    policy_path = tmp / "policy.json"
    base = {"service": {"ip": "10.0.0.100", "port": 5000},
            "allow": ["10.0.0.1", "10.0.0.2"], "block": ["10.0.0.3"],
            "default_action": "drop", "allow_icmp": True}
    policy_path.write_text(json.dumps(base))
    stats_csv = tmp / "stats.csv"

    controller = Controller("127.0.0.1", 0, str(policy_path), 0.3, str(stats_csv))
    threading.Thread(target=controller.serve_forever, daemon=True).start()
    controller.ready.wait(5)

    print("\n== handshake and rule installation ==")
    sw = FakeSwitch(controller.port)
    check("controller installs 9 rules and a barrier", wait_for(lambda: len(sw.flows) == 9 and sw.barriers == 1),
          f"{len(sw.flows)} flows, {sw.barriers} barriers")
    lengths = sorted({f["length"] for f in sw.flows})
    check("FLOW_MOD sizes match the spec (72 drop / 80 output)", lengths == [72, 80], str(lengths))
    types = [m[0] for m in sw.messages]
    check("message order: features request, delete, adds, barrier",
          types[:2] == [0, 5] and types.index(14) < types.index(18), str(types[:5]))

    print("\n== policy enforced on packets ==")
    S = "10.0.0.100"
    check("allowed client -> server:5000 forwarded", sw.tcp("10.0.0.1", S, 40001, 5000, 100, 1514) == "forward")
    check("server:5000 -> allowed client forwarded", sw.tcp(S, "10.0.0.1", 5000, 40001, 100, 66) == "forward")
    check("second allowed client forwarded", sw.tcp("10.0.0.2", S, 40002, 5000, 50, 1514) == "forward")
    check("blocked client -> server dropped", sw.tcp("10.0.0.3", S, 40003, 5000, 4, 74) == "drop")
    check("unlisted host dropped by default rule", sw.tcp("10.0.0.4", S, 40004, 5000, 3, 74) == "drop")
    check("allowed client to another port dropped", sw.tcp("10.0.0.1", S, 40005, 22, 2, 74) == "drop")
    check("client-to-client TCP dropped", sw.tcp("10.0.0.1", "10.0.0.2", 40006, 5000, 2, 74) == "drop")
    check("ARP forwarded", sw.packets(5, 60, dl_type=0x0806) == "forward")
    check("ICMP forwarded", sw.packets(5, 98, proto=1, nw_src="10.0.0.1", nw_dst=S) == "forward")

    print("\n== statistics, labels and bandwidth log ==")
    check("controller polls statistics", wait_for(lambda: sw.stats_requests >= 2))
    check("CSV has rows", wait_for(lambda: stats_csv.exists() and len(read_csv(stats_csv)) >= 6))
    time.sleep(0.4)
    rows = read_csv(stats_csv)
    last = {}
    for r in rows:
        last[r["rule"]] = r
    r1 = last.get("ALLOW 10.0.0.1 -> 10.0.0.100:5000")
    check("ALLOW client->server labelled with exact counters",
          r1 and int(r1["packets"]) == 100 and int(r1["bytes"]) == 151400, str(r1))
    r1b = last.get("ALLOW 10.0.0.100:5000 -> 10.0.0.1")
    check("ALLOW server->client labelled", r1b and int(r1b["packets"]) == 100 and int(r1b["bytes"]) == 6600, str(r1b))
    rb = last.get("BLOCK 10.0.0.3 -> 10.0.0.100:5000")
    check("BLOCK rule counted the dropped packets", rb and int(rb["packets"]) == 4, str(rb))
    rd = last.get("DEFAULT everything else: drop")
    check("default rule counted the rest", rd and int(rd["packets"]) == 3 + 2 + 2, str(rd))
    check("ARP and ICMP rules counted", last.get("ARP (address resolution)") and last.get("ICMP (ping)"))
    check("no unlabelled rules", not [k for k in last if k.startswith("other rule")], str([k for k in last if k.startswith("other")]))

    before = len(read_csv(stats_csv))
    sw.tcp("10.0.0.1", S, 40001, 5000, 2000, 1514)       # traffic between two polls
    check("rate column shows bandwidth when bytes move",
          wait_for(lambda: any(float(r["mbit_per_s"]) > 1 and r["rule"] == "ALLOW 10.0.0.1 -> 10.0.0.100:5000"
                               for r in read_csv(stats_csv)[before:])))

    print("\n== keep-alive and error messages ==")
    sw.send(2, 0, 777, b"ping")                           # ECHO_REQUEST
    check("echo request answered with same xid and payload", wait_for(lambda: sw.echo_reply == (777, b"ping")), str(sw.echo_reply))
    sw.send(1, 0, 5, struct.pack("!HH", 3, 5) + b"x" * 8)  # ERROR
    sw.send(2, 0, 778, b"")
    check("controller survives an OFPT_ERROR", wait_for(lambda: sw.echo_reply == (778, b"")))

    print("\n== live policy change ==")
    new = dict(base, block=["10.0.0.3", "10.0.0.2"], allow=["10.0.0.1"])
    policy_path.write_text(json.dumps(new))
    check("rules re-installed after policy.json edit",
          wait_for(lambda: sw.barriers == 2 and len(sw.flows) == 9), f"{sw.barriers} barriers, {len(sw.flows)} flows")
    check("client 10.0.0.2 now blocked", sw.tcp("10.0.0.2", S, 40010, 5000) == "drop")
    check("client 10.0.0.1 still allowed", sw.tcp("10.0.0.1", S, 40011, 5000) == "forward")
    check("block beats allow when both listed",
          (policy_path.write_text(json.dumps(dict(base, allow=["10.0.0.1", "10.0.0.2"], block=["10.0.0.2"]))),
           wait_for(lambda: sw.barriers == 3))[1] and sw.tcp("10.0.0.2", S, 40012, 5000) == "drop")

    snapshot = [(f["priority"], f["wc"], f["forward"]) for f in sw.flows]
    policy_path.write_text('{"service": {"ip": "not-an-ip", "port": 5000}}')
    time.sleep(1.0)
    check("invalid policy edit keeps the old rules",
          sw.barriers == 3 and [(f["priority"], f["wc"], f["forward"]) for f in sw.flows] == snapshot)
    check("old rules still enforce policy", sw.tcp("10.0.0.1", S, 40013, 5000) == "forward")

    print("\n== reconnect ==")
    policy_path.write_text(json.dumps(base))
    time.sleep(0.8)
    sw.close()
    sw2 = FakeSwitch(controller.port, dpid=2)
    check("a new switch gets the policy too", wait_for(lambda: len(sw2.flows) == 9 and sw2.barriers == 1))
    check("new switch enforces it", sw2.tcp("10.0.0.3", S, 1, 5000) == "drop" and sw2.tcp("10.0.0.1", S, 1, 5000) == "forward")

    print(f"\n{sum(RESULTS)}/{len(RESULTS)} checks passed")
    sys.exit(0 if all(RESULTS) else 1)


if __name__ == "__main__":
    main()
