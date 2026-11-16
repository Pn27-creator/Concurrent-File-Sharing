#!/usr/bin/env python3
"""Mininet topology and scripted demo for the file-sharing project (run with sudo).

    Terminal 1:  python3 controller.py
    Terminal 2:  sudo python3 topology.py demo          # scripted walk-through
                 sudo python3 topology.py cli           # network + Mininet prompt

Topology (one switch, links limited to --bw Mbit/s so throughput is meaningful):

        h1 10.0.0.1 ---+
        h2 10.0.0.2 ---+--- s1 (Open vSwitch, OpenFlow 1.0) --- srv 10.0.0.100
        h3 10.0.0.3 ---+                |                          (file server)
                                        +--- remote controller (controller.py)

The demo shows, in order:
  1. SDN rules: h1 and h2 may reach the file service, h3 is blocked by the switch.
  2. Server-side access control over that network: bob cannot download alice's
     private file, but can download her public one.
  3. Live policy change: the controller re-programs the switch when policy.json
     is edited (h2 is blocked, then unblocked).
  4. Performance: 1 and 2 simultaneous clients, several file sizes -> time and
     throughput; switch packet/byte counters compared with the file bytes.
"""

import argparse
import json
import os
import re
import shlex
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

try:
    from mininet.cli import CLI
    from mininet.link import TCLink
    from mininet.log import setLogLevel
    from mininet.net import Mininet
    from mininet.node import OVSSwitch, RemoteController
except ImportError:
    sys.exit("Mininet is not installed here.  On Ubuntu:  sudo apt install mininet openvswitch-switch")

HERE = Path(__file__).resolve().parent
PYTHON = sys.executable
SERVER_IP = "10.0.0.100"
SERVICE_PORT = 5000
CLIENT_HOSTS = {"h1": ("10.0.0.1", "alice", "alice123"),
                "h2": ("10.0.0.2", "bob", "bob123"),
                "h3": ("10.0.0.3", "carol", "carol123")}

FLOW_RE = re.compile(r"n_packets=(\d+), n_bytes=(\d+).*?priority=(\d+)(?:,(\S*))? actions=(\S+)")


def say(text=""):
    print(text, flush=True)


def section(title):
    say(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def format_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def parse_size(text):
    text = text.strip().upper().replace("IB", "B")
    for unit, mult in (("GB", 1024 ** 3), ("MB", 1024 ** 2), ("KB", 1024), ("B", 1)):
        if text.endswith(unit):
            return int(float(text[:-len(unit)]) * mult)
    return int(text)


class Lab:
    def __init__(self, args):
        self.args = args
        self.server_dir = Path(args.server_dir).resolve()
        self.client_dir = Path(args.client_dir).resolve()
        self.policy_path = Path(args.policy).resolve()
        self.logdir = Path(args.logdir).resolve()
        self.logdir.mkdir(parents=True, exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix="fileshare-lab-"))
        self.data_dir = self.work / "server-data"
        self.net = None
        self.server_proc = None
        self.workers = []

    # -- network ---------------------------------------------------------------
    def start_network(self):
        for path, what in ((self.server_dir / "server.py", "server"),
                           (self.client_dir / "client.py", "client")):
            if not path.exists():
                sys.exit(f"Cannot find the {what} at {path}\n"
                         "Unzip fileshare-server, fileshare-client and fileshare-sdn side by side, "
                         "or pass --server-dir / --client-dir.")
        self.net = Mininet(controller=None, link=TCLink, autoSetMacs=True)
        self.net.addController("c0", controller=RemoteController,
                               ip=self.args.controller_ip, port=self.args.controller_port)
        self.switch = self.net.addSwitch("s1", cls=OVSSwitch, protocols="OpenFlow10")
        link = {"bw": self.args.bw} if self.args.bw else {}
        self.srv = self.net.addHost("srv", ip=f"{SERVER_IP}/24")
        self.net.addLink(self.srv, self.switch, **link)
        self.hosts = {}
        for name, (ip, _user, _password) in CLIENT_HOSTS.items():
            self.hosts[name] = self.net.addHost(name, ip=f"{ip}/24")
            self.net.addLink(self.hosts[name], self.switch, **link)
        self.net.start()

        say("Waiting for the switch to connect to the controller ...")
        end = time.time() + 20
        while time.time() < end and not self.switch.connected():
            time.sleep(0.5)
        if not self.switch.connected():
            self.net.stop()
            sys.exit(f"The switch did not connect to a controller at "
                     f"{self.args.controller_ip}:{self.args.controller_port}.\n"
                     "Start it first, in another terminal:  python3 controller.py")
        end = time.time() + 15            # wait for the controller's rules to arrive
        while time.time() < end and not any(f["priority"] == 100 for f in self.flows()):
            time.sleep(0.3)
        say("Switch connected; the controller has programmed its flow table.")

    def stop_network(self):
        for proc in self.workers:
            if proc.poll() is None:
                proc.terminate()
        if self.server_proc and self.server_proc.poll() is None:
            self.server_proc.terminate()
            try:
                self.server_proc.wait(5)
            except subprocess.TimeoutExpired:
                self.server_proc.kill()
        if self.net:
            self.net.stop()

    # -- file server ---------------------------------------------------------------
    def start_server(self):
        subprocess.run([PYTHON, str(self.server_dir / "manage_users.py"),
                        "--data-dir", str(self.data_dir), "demo-users"],
                       check=True, capture_output=True)
        log = open(self.logdir / "server.log", "w")
        self.server_proc = self.srv.popen(
            [PYTHON, str(self.server_dir / "server.py"), "--host", "0.0.0.0",
             "--port", str(SERVICE_PORT), "--data-dir", str(self.data_dir)],
            stdout=log, stderr=subprocess.STDOUT)
        for _ in range(40):
            if "reachable" in self.client(self.hosts["h1"], "probe", timeout=2)[1]:
                say(f"File server is running on srv ({SERVER_IP}:{SERVICE_PORT}); log: {self.logdir / 'server.log'}")
                return
            time.sleep(0.5)
        sys.exit("The file server did not start; see " + str(self.logdir / "server.log"))

    # -- running things on hosts -----------------------------------------------------
    def client(self, host, *words, user=None, password=None, timeout=10):
        """Run client.py on a Mininet host.  Returns (exit code, output)."""
        cmd = f"{shlex.quote(PYTHON)} {shlex.quote(str(self.client_dir / 'client.py'))} " \
              f"--host {SERVER_IP} --port {SERVICE_PORT} --connect-timeout {timeout}"
        if user:
            cmd += f" --user {shlex.quote(user)}"
        cmd += " " + " ".join(shlex.quote(str(w)) for w in words)
        env = f"FILESHARE_PASSWORD={shlex.quote(password)} " if password else ""
        out = host.cmd(f"{env}{cmd} ; echo __RC=$?")
        match = re.search(r"__RC=(\d+)", out)
        code = int(match.group(1)) if match else 1
        return code, re.sub(r"__RC=\d+\s*$", "", out).strip()

    def as_user(self, host_name, *words):
        _ip, user, password = CLIENT_HOSTS[host_name]
        return self.client(self.hosts[host_name], *words, user=user, password=password)

    # -- switch counters -----------------------------------------------------------------
    def flows(self):
        text = self.switch.cmd("ovs-ofctl -O OpenFlow10 dump-flows s1")
        out = []
        for line in text.splitlines():
            m = FLOW_RE.search(line)
            if not m:
                continue
            packets, nbytes, priority, match, action = m.groups()
            items = (match or "").split(",")
            kv = dict(i.split("=", 1) for i in items if "=" in i)
            words = [i for i in items if i and "=" not in i]
            out.append({"priority": int(priority), "packets": int(packets), "bytes": int(nbytes),
                        "action": action, "label": self.label(int(priority), kv, words, action),
                        "to_server": "tp_dst" in kv, "from_server": "tp_src" in kv})
        return out

    @staticmethod
    def label(priority, kv, words, action):
        if priority == 0:
            return "DEFAULT everything else"
        if "arp" in words:
            return "ARP"
        if "icmp" in words:
            return "ICMP"
        word = "BLOCK" if action == "drop" else "ALLOW"
        if "tp_dst" in kv:
            return f"{word} {kv.get('nw_src')} -> {kv.get('nw_dst')}:{kv['tp_dst']}"
        if "tp_src" in kv:
            return f"{word} {kv.get('nw_src')}:{kv['tp_src']} -> {kv.get('nw_dst')}"
        return f"{word} {','.join(words)}"

    def counters(self):
        return {f["label"]: f for f in self.flows()}

    def print_counters(self, only_active=True):
        say(f"  {'RULE':<40}{'PACKETS':>10}{'BYTES':>13}")
        for f in sorted(self.flows(), key=lambda f: (-f["priority"], f["label"])):
            if f["packets"] or not only_active:
                say(f"  {f['label']:<40}{f['packets']:>10}{f['bytes']:>13}")

    # -- demo steps --------------------------------------------------------------------
    def step_sdn_rules(self):
        section("1. SDN network policy: which hosts may even reach the file service?")
        say("   The switch rules come from policy.json (installed by the controller).")
        for name, (ip, _u, _p) in CLIENT_HOSTS.items():
            code, out = self.client(self.hosts[name], "probe", timeout=3)
            verdict = "REACHABLE" if code == 0 else "BLOCKED  (TCP connection timed out)"
            say(f"   {name} ({ip}) -> {SERVER_IP}:{SERVICE_PORT} : {verdict}")
        say("\n   Switch counters (rules that matched traffic so far):")
        self.print_counters()
        say("\n   The BLOCK rule's packets are h3's connection attempts (TCP retries) being dropped")
        say("   in the switch -- they never reached the server.")

    def step_access_control(self):
        section("2. Server-side access control over the network (authentication + authorization)")
        sample = self.work / "secret-plan.txt"
        sample.write_text("alice's private plan\n")
        public = self.work / "poster.txt"
        public.write_text("a poster anyone may read\n")

        def show(who, what, result):
            code, out = result
            say(f"   {who:<6} {what:<38} -> {'ALLOWED' if code == 0 else 'DENIED '}  "
                f"{out.splitlines()[-1] if out else ''}")

        show("alice", "upload secret-plan.txt (private)", self.as_user("h1", "upload", sample))
        show("alice", "upload poster.txt (public)", self.as_user("h1", "upload", public, "--public"))
        dest = self.work / "bob-copy"
        show("bob", "download alice/secret-plan.txt", self.as_user("h2", "download", "alice/secret-plan.txt", dest / "a"))
        show("bob", "download alice/poster.txt", self.as_user("h2", "download", "alice/poster.txt", dest / "b"))
        code, out = self.client(self.hosts["h2"], "list", user="bob", password="WRONG")
        say(f"   bob    login with a wrong password          -> {'ALLOWED' if code == 0 else 'DENIED '}  {out.splitlines()[-1] if out else ''}")
        show("alice", "share secret-plan.txt with bob", self.as_user("h1", "share", "secret-plan.txt", "bob"))
        show("bob", "download alice/secret-plan.txt (shared)", self.as_user("h2", "download", "alice/secret-plan.txt", dest / "c"))
        self.as_user("h1", "delete", "secret-plan.txt")
        self.as_user("h1", "delete", "poster.txt")

        audit = self.data_dir / "audit.log"
        if audit.exists():
            denied = [json.loads(l) for l in audit.read_text().splitlines() if '"download_denied"' in l]
            say("\n   Server audit log, denied downloads (note the source IP seen by the server):")
            for e in denied[-3:]:
                say(f"   {e['time']}  user={e['user']}  ip={e['ip']}  file={e['file']}")

    def step_live_policy(self):
        section("3. Live policy change: the controller re-programs the switch")
        original = self.policy_path.read_text()
        policy = json.loads(original)
        h2 = CLIENT_HOSTS["h2"][0]
        if h2 in policy.get("block", []):
            say("   (h2 is already blocked in policy.json; skipping this step)")
            return
        try:
            policy.setdefault("block", []).append(h2)
            say(f"   Editing {self.policy_path.name}: adding {h2} (h2) to the block list ...")
            self.policy_path.write_text(json.dumps(policy, indent=2))
            if self.wait_rule(f"BLOCK {h2} -> {SERVER_IP}:{SERVICE_PORT}", present=True):
                code, _ = self.client(self.hosts["h2"], "probe", timeout=3)
                say(f"   h2 -> server : {'REACHABLE' if code == 0 else 'BLOCKED'}   (new rule installed by the controller)")
            else:
                say("   The switch did not change. Is the controller running with --policy "
                    f"{self.policy_path}?")
        finally:
            self.policy_path.write_text(original)
        say("   Restoring the original policy ...")
        if self.wait_rule(f"BLOCK {h2} -> {SERVER_IP}:{SERVICE_PORT}", present=False):
            code, _ = self.client(self.hosts["h2"], "probe", timeout=3)
            say(f"   h2 -> server : {'REACHABLE' if code == 0 else 'BLOCKED'}")

    def wait_rule(self, label, present, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            if (label in self.counters()) == present:
                time.sleep(0.5)
                return True
            time.sleep(0.5)
        return False

    def step_performance(self):
        limit = f"links limited to {self.args.bw:g} Mbit/s" if self.args.bw else "links not rate-limited"
        section(f"4. Performance: file size x simultaneous clients ({limit})")
        sizes = [parse_size(s) for s in self.args.sizes.split(",")]
        say(f"   {'phase':<9}{'size':>9}{'clients':>9}{'time/client':>13}{'per-client':>13}{'aggregate':>13}"
            f"   | {'file bytes':>11}{'switch bytes':>14}{'overhead':>10}")
        for size in sizes:
            source = self.work / f"payload-{size}.bin"
            with source.open("wb") as f:
                f.write(os.urandom(size))
            for count in (1, 2):
                self.measure(size, source, ["h1", "h2"][:count])

    def measure(self, size, source, names):
        control = Path(tempfile.mkdtemp(dir=self.work, prefix="ctl-"))
        procs = []
        for name in names:
            ip, user, password = CLIENT_HOSTS[name]
            log = open(control / f"{name}.log", "w")
            procs.append(self.hosts[name].popen(
                [PYTHON, str(HERE / "net_worker.py"), "--client-dir", str(self.client_dir),
                 "--host", SERVER_IP, "--port", str(SERVICE_PORT), "--user", user,
                 "--password", password, "--source", str(source),
                 "--name", f"perf-{size}-{len(names)}.bin", "--control-dir", str(control),
                 "--tag", name], stdout=log, stderr=subprocess.STDOUT))
        self.workers += procs
        try:
            if not self.wait_files([control / f"{n}.ready" for n in names], 60):
                say("   ! workers did not log in; see " + str(control))
                return
            for n in names:
                ready = json.loads((control / f"{n}.ready").read_text())
                if "error" in ready:
                    say(f"   ! {n}: {ready['error']}")
                    return

            for phase, trigger, result_name in (("upload", "go-upload", "upload.json"),
                                                ("download", "go-download", "download.json")):
                before = self.counters()
                (control / trigger).write_text("go")
                if not self.wait_files([control / f"{n}.{result_name}" for n in names], 240):
                    say(f"   ! {phase} timed out")
                    return
                time.sleep(0.4)                       # let the final ACKs be counted
                after = self.counters()
                rows = [json.loads((control / f"{n}.{result_name}").read_text()) for n in names]
                if any("error" in r for r in rows):
                    say(f"   ! {phase}: {[r['error'] for r in rows if 'error' in r][0]}")
                    return
                wall = max(r["t_end"] for r in rows) - min(r["t_start"] for r in rows)
                total = sum(r["bytes"] for r in rows)
                per = statistics.mean(r["mbit_per_s"] for r in rows)
                secs = statistics.mean(r["seconds"] for r in rows)
                agg = total * 8 / 1e6 / wall if wall > 0 else 0
                wanted = "to_server" if phase == "upload" else "from_server"
                switch_bytes = sum(after[l]["bytes"] - before.get(l, {"bytes": 0})["bytes"]
                                   for l, f in after.items()
                                   if f[wanted] and f["action"] != "drop")
                overhead = (switch_bytes / total - 1) * 100 if total else 0
                say(f"   {phase:<9}{format_size(size):>9}{len(names):>9}{secs:>12.2f}s{per:>9.1f} Mb/s{agg:>9.1f} Mb/s"
                    f"   | {total:>11}{switch_bytes:>14}{overhead:>9.1f}%")
            (control / "quit").write_text("bye")
        finally:
            for proc in procs:
                try:
                    proc.wait(15)
                except subprocess.TimeoutExpired:
                    proc.terminate()

    @staticmethod
    def wait_files(paths, timeout):
        end = time.time() + timeout
        while time.time() < end:
            if all(p.exists() for p in paths):
                return True
            time.sleep(0.01)
        return False

    def step_summary(self):
        section("5. Final switch counters")
        self.print_counters()
        say("""
   Why 'switch bytes' > 'file bytes': the switch counts whole Ethernet frames,
   so every packet also carries Ethernet + IP + TCP headers (about 66 bytes per
   packet of up to 1448 data bytes), and the totals include the login/command
   messages.  Throughput computed from the client's file bytes is therefore a
   little lower than the link's raw rate.  The returning ACK traffic is counted
   in the opposite-direction rule.""")

    # -- entry points -----------------------------------------------------------------------
    def demo(self):
        self.step_sdn_rules()
        self.step_access_control()
        if not self.args.skip_live_policy:
            self.step_live_policy()
        self.step_performance()
        self.step_summary()

    def cli(self):
        say(f"""
Network is up.  Try:
  mininet> h1 {PYTHON} {self.client_dir / 'client.py'} --host {SERVER_IP} --user alice --password alice123 shell
  mininet> h3 {PYTHON} {self.client_dir / 'client.py'} --host {SERVER_IP} probe      (blocked by the switch)
  mininet> sh ovs-ofctl -O OpenFlow10 dump-flows s1                                  (rule counters)
  mininet> exit
Server log: {self.logdir / 'server.log'}   Server data: {self.data_dir}""")
        CLI(self.net)


def main():
    parser = argparse.ArgumentParser(description="Mininet lab for the file-sharing project")
    parser.add_argument("mode", choices=["demo", "cli"])
    parser.add_argument("--server-dir", default=str(HERE.parent / "fileshare-server"))
    parser.add_argument("--client-dir", default=str(HERE.parent / "fileshare-client"))
    parser.add_argument("--policy", default=str(HERE / "policy.json"),
                        help="the SAME file the controller was started with")
    parser.add_argument("--controller-ip", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument("--bw", type=float, default=10,
                        help="link bandwidth in Mbit/s (0 = unlimited)")
    parser.add_argument("--sizes", default="1MB,5MB")
    parser.add_argument("--skip-live-policy", action="store_true")
    parser.add_argument("--logdir", default=str(HERE / "logs"))
    args = parser.parse_args()

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        sys.exit("Mininet needs root:  sudo python3 topology.py " + args.mode)
    setLogLevel("warning")
    lab = Lab(args)
    try:
        lab.start_network()
        lab.start_server()
        lab.demo() if args.mode == "demo" else lab.cli()
    except KeyboardInterrupt:
        say("\nInterrupted.")
    finally:
        lab.stop_network()


if __name__ == "__main__":
    main()
