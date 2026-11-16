#!/usr/bin/env python3
"""Helper that runs on ONE Mininet host during the evaluation (started by topology.py).

It logs in, announces READY, then waits for "go" files so that several hosts can
start transferring at the same moment:

    <control-dir>/<tag>.ready          written when logged in
    <control-dir>/go-upload            orchestrator creates it -> upload now
    <control-dir>/<tag>.upload.json    result (bytes, seconds, Mbit/s, timestamps)
    <control-dir>/go-download          -> download the same file back
    <control-dir>/<tag>.download.json  result
    <control-dir>/quit                 -> delete the file, log out, exit
"""

import argparse
import json
import sys
import time
from pathlib import Path


def wait_for(path, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if path.exists():
            return True
        time.sleep(0.002)
    return False


def timed(call):
    started = time.time()
    try:
        result = call()
        result.update(t_start=started, t_end=time.time())
        return result
    except Exception as error:                       # report instead of hanging the demo
        return {"error": str(error)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--client-dir", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--control-dir", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args()

    sys.path.insert(0, args.client_dir)
    from client import FileShareClient

    control = Path(args.control_dir)

    def write(suffix, data):
        (control / f"{args.tag}.{suffix}").write_text(json.dumps(data))

    client = FileShareClient(args.host, args.port, connect_timeout=5, timeout=120)
    try:
        client.connect()
        client.login(args.user, args.password)
    except Exception as error:
        write("ready", {"error": str(error)})
        return
    write("ready", {"ok": True})

    try:
        if wait_for(control / "go-upload", args.timeout):
            write("upload.json", timed(lambda: client.upload(args.source, name=args.name)))
        if wait_for(control / "go-download", args.timeout):
            write("download.json", timed(lambda: client.download(
                f"{args.user}/{args.name}", discard=True)))
        wait_for(control / "quit", args.timeout)
    finally:
        try:
            client.delete(args.name)
        except Exception:
            pass
        client.quit()


if __name__ == "__main__":
    main()
