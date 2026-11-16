#!/usr/bin/env python3
"""Performance evaluation: transfer files of different sizes with different
numbers of simultaneous clients, record size and time, calculate throughput.

    python3 benchmark.py --host 10.0.0.100 --user alice --password alice123
    python3 benchmark.py --host 127.0.0.1 --user alice --password alice123 \\
            --sizes 1MB,10MB,50MB --clients 1,2,4,8 --repeat 3 --csv results.csv --plot results.png

For every (file size, number of clients) pair it runs N clients at the same
moment (all are connected and logged in first; a barrier then releases them
together), once for UPLOAD and once for DOWNLOAD, and reports

    time per client ........ seconds to move one file
    per-client throughput .. bytes * 8 / seconds        (Mbit/s)
    aggregate throughput ... all bytes * 8 / (first start -> last finish)

Throughput = amount of data transferred per second.  Only the data transfer is
timed; connecting and logging in are excluded.

Notes
 * Downloads are received and checksum-verified but not written to disk
   (--save-downloads to write them), so disk speed does not distort results.
 * On one machine (127.0.0.1) the numbers measure Python and the CPU, not a
   network.  For network behaviour, run inside the Mininet topology where the
   links have a bandwidth limit.
 * --json prints one JSON line per client (used by the Mininet demo to merge
   results from several hosts); --start-at lets several processes start
   transferring at the same instant.
"""

import argparse
import csv
import json
import os
import statistics
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

from client import FileShareClient, FileShareError, format_size
from protocol import DEFAULT_PORT

UNITS = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3}


def parse_size(text):
    text = text.strip().upper().replace("IB", "B")
    for unit in ("GB", "MB", "KB", "B"):
        if text.endswith(unit):
            return int(float(text[:-len(unit)]) * UNITS[unit])
    return int(text)


def make_source_file(directory, size):
    """A file of `size` random bytes (random so nothing can compress it)."""
    path = Path(directory) / f"bench-source-{size}.bin"
    block = os.urandom(1024 * 1024)
    with path.open("wb") as f:
        left = size
        while left > 0:
            f.write(block[:min(left, len(block))])
            left -= len(block)
    return path


def sleep_until(epoch):
    while True:
        wait = epoch - time.time()
        if wait <= 0:
            return
        time.sleep(min(wait, 0.05))


def run_phase(args, count, action):
    """Run `action(client, index)` in `count` threads at the same moment."""
    rows = [None] * count
    barrier = threading.Barrier(count, timeout=120)

    def worker(i):
        client = None
        try:
            client = FileShareClient(args.host, args.port, tls=args.tls,
                                     cafile=args.cafile)
            client.connect()
            client.login(args.user, args.password)
            barrier.wait()                      # everyone is ready: go together
            if args.start_at:
                sleep_until(args.start_at)
            t_start = time.time()
            result = action(client, i)
            t_end = time.time()
            rows[i] = {**result, "t_start": t_start, "t_end": t_end}
        except threading.BrokenBarrierError:
            rows[i] = {"error": "another client failed before the start"}
        except (FileShareError, OSError, ValueError) as error:
            barrier.abort()
            rows[i] = {"error": str(error)}
        finally:
            if client:
                client.quit()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return rows


def cleanup(args, names):
    try:
        client = FileShareClient(args.host, args.port, tls=args.tls, cafile=args.cafile)
        client.connect()
        client.login(args.user, args.password)
        for name in names:
            try:
                client.delete(name)
            except FileShareError:
                pass
        client.quit()
    except (FileShareError, OSError):
        pass


def summarise(phase, size, count, run, rows):
    good = [r for r in rows if r and "error" not in r]
    errors = [r["error"] for r in rows if r and "error" in r]
    if not good:
        return None, errors
    wall = max(r["t_end"] for r in good) - min(r["t_start"] for r in good)
    total = sum(r["bytes"] for r in good)
    return {
        "phase": phase, "size": size, "clients": count, "run": run,
        "ok": len(good), "wall_s": wall,
        "mean_client_s": statistics.mean(r["seconds"] for r in good),
        "per_client_mbit": statistics.mean(r["mbit_per_s"] for r in good),
        "aggregate_mbit": (total * 8 / 1e6) / wall if wall > 0 else 0.0,
        "bytes": total,
    }, errors


def main():
    parser = argparse.ArgumentParser(description="Concurrent transfer benchmark")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", default=os.environ.get("FILESHARE_PASSWORD"))
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--cafile")
    parser.add_argument("--sizes", default="1MB,10MB",
                        help="comma-separated, e.g. 100KB,1MB,10MB,50MB")
    parser.add_argument("--clients", default="1,2,4",
                        help="comma-separated numbers of simultaneous clients")
    parser.add_argument("--repeat", type=int, default=3, help="runs per combination")
    parser.add_argument("--mode", choices=["both", "upload", "download"], default="both")
    parser.add_argument("--same-file", action="store_true",
                        help="download phase: every client fetches the same file")
    parser.add_argument("--save-downloads", action="store_true",
                        help="write downloads to disk instead of discarding them")
    parser.add_argument("--csv", help="write per-client rows to this CSV file")
    parser.add_argument("--plot", help="write a PNG chart (needs matplotlib)")
    parser.add_argument("--json", action="store_true",
                        help="print one JSON line per client instead of a table")
    parser.add_argument("--start-at", type=float, default=0,
                        help="epoch time at which to start transferring")
    args = parser.parse_args()
    if not args.password:
        sys.exit("Error: give --password or set FILESHARE_PASSWORD")

    sizes = [parse_size(s) for s in args.sizes.split(",")]
    counts = [int(c) for c in args.clients.split(",")]
    tag = uuid.uuid4().hex[:6]
    say = (lambda *a, **k: None) if args.json else print

    detail, summaries = [], []
    workdir = tempfile.mkdtemp(prefix="fileshare-bench-")
    try:
        for size in sizes:
            source = make_source_file(workdir, size)
            for count in counts:
                for run in range(1, args.repeat + 1):
                    names = [f"bench-{tag}-{size}-{count}-{run}-{i}.bin" for i in range(count)]
                    made = list(names)
                    plan = []
                    if args.mode in ("both", "upload"):
                        plan.append(("upload", lambda c, i: c.upload(source, name=names[i])))
                    if args.mode in ("both", "download"):
                        if args.mode == "download":     # files must exist first (untimed)
                            warm = run_phase(args, count, lambda c, i: c.upload(source, name=names[i]))
                            if any(r is None or "error" in r for r in warm):
                                print("Setup upload failed:", [r for r in warm if r and "error" in r][:1], file=sys.stderr)
                                cleanup(args, made)
                                continue
                        target = (lambda i: names[0]) if args.same_file else (lambda i: names[i])
                        plan.append(("download", lambda c, i: c.download(
                            f"{args.user}/{target(i)}", discard=not args.save_downloads,
                            dest_dir=os.path.join(workdir, "dl"))))
                    for phase, action in plan:
                        rows = run_phase(args, count, action)
                        summary, errors = summarise(phase, size, count, run, rows)
                        for i, r in enumerate(rows):
                            if r and "error" not in r:
                                row = {"phase": phase, "size": size, "clients": count,
                                       "run": run, "client": i, "bytes": r["bytes"],
                                       "seconds": round(r["seconds"], 6),
                                       "mbit_per_s": round(r["mbit_per_s"], 3),
                                       "t_start": r["t_start"], "t_end": r["t_end"],
                                       "verified": r["verified"]}
                                detail.append(row)
                                if args.json:
                                    print(json.dumps(row), flush=True)
                        if summary:
                            summaries.append(summary)
                        for e in errors[:1]:
                            print(f"  ! {phase} {format_size(size)} x{count}: {e}", file=sys.stderr)
                    cleanup(args, made)
    finally:
        for p in Path(workdir).glob("*"):
            if p.is_file():
                p.unlink(missing_ok=True)
        try:
            os.rmdir(workdir)
        except OSError:
            pass

    if args.csv and detail:
        with open(args.csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(detail[0].keys()))
            writer.writeheader()
            writer.writerows(detail)
        say(f"Per-client rows written to {args.csv}")

    if args.json:
        return

    # Table: average over the repeated runs.
    groups = {}
    for s in summaries:
        groups.setdefault((s["phase"], s["size"], s["clients"]), []).append(s)
    print()
    print(f"{'phase':<9}{'file size':>10}{'clients':>9}{'time/client (s)':>17}"
          f"{'per-client Mbit/s':>19}{'aggregate Mbit/s':>18}")
    table = []
    for (phase, size, count), runs in sorted(groups.items(), key=lambda kv: (kv[0][0] != "upload", kv[0][1], kv[0][2])):
        t = statistics.mean(r["mean_client_s"] for r in runs)
        per = statistics.mean(r["per_client_mbit"] for r in runs)
        agg = statistics.mean(r["aggregate_mbit"] for r in runs)
        table.append((phase, size, count, t, per, agg))
        print(f"{phase:<9}{format_size(size):>10}{count:>9}{t:>17.3f}{per:>19.1f}{agg:>18.1f}")

    if args.plot and table:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except ImportError:
            print("(matplotlib not installed; skipping --plot)")
            return
        phases = sorted({row[0] for row in table}, key=lambda p: p != "upload")
        fig, axes = plt.subplots(1, 2, figsize=(11, 4))
        for phase in phases:
            for size in sorted({row[1] for row in table}):
                pts = [(row[2], row[3], row[5]) for row in table if row[0] == phase and row[1] == size]
                label = f"{phase} {format_size(size)}"
                style = "-o" if phase == "upload" else "--s"
                axes[0].plot([p[0] for p in pts], [p[2] for p in pts], style, label=label)
                axes[1].plot([p[0] for p in pts], [p[1] for p in pts], style, label=label)
        axes[0].set(xlabel="simultaneous clients", ylabel="aggregate throughput (Mbit/s)",
                    title="Total throughput")
        axes[1].set(xlabel="simultaneous clients", ylabel="time per file (s)",
                    title="Transfer time per client")
        for ax in axes:
            ax.grid(alpha=0.3)
            ax.set_xticks(sorted({row[2] for row in table}))
        axes[0].legend(fontsize=8)
        fig.tight_layout()
        fig.savefig(args.plot, dpi=150)
        print(f"Chart written to {args.plot}")


if __name__ == "__main__":
    main()
