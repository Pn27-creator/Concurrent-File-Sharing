#!/usr/bin/env python3
"""Concurrent File Sharing System -- client.

One-shot commands (each logs in, does one thing, disconnects):

    python3 client.py --host 10.0.0.100 --user alice list
    python3 client.py --host 10.0.0.100 --user alice upload report.pdf
    python3 client.py --host 10.0.0.100 --user alice upload photo.jpg --public
    python3 client.py --host 10.0.0.100 --user bob   download alice/report.pdf
    python3 client.py --host 10.0.0.100 --user alice share report.pdf bob
    python3 client.py --host 10.0.0.100 --user alice unshare report.pdf bob
    python3 client.py --host 10.0.0.100 --user alice visibility report.pdf public
    python3 client.py --host 10.0.0.100 --user alice delete report.pdf
    python3 client.py --host 10.0.0.100 probe          # is the server reachable?

Interactive session (log in once, then type commands):

    python3 client.py --host 10.0.0.100 --user alice shell

The password is asked for (hidden), or taken from --password or the
FILESHARE_PASSWORD environment variable.

The FileShareClient class below is also used by benchmark.py.
"""

import argparse
import getpass
import hashlib
import os
import shlex
import socket
import ssl
import sys
import time
import uuid
from pathlib import Path

from protocol import (CHUNK, DEFAULT_PORT, MAX_FILE_SIZE, recv_msg, send_msg)


class FileShareError(Exception):
    """The server refused or failed a request (the session is still usable)."""

    def __init__(self, message, code="ERROR"):
        super().__init__(message)
        self.code = code


def format_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def mbit_per_s(nbytes, seconds):
    return (nbytes * 8 / 1e6) / seconds if seconds > 0 else 0.0


def unique_path(directory, name):
    """downloads/name, or downloads/name (1) if that already exists."""
    directory = Path(directory)
    path = directory / name
    stem, suffix, i = path.stem, path.suffix, 1
    while path.exists():
        path = directory / f"{stem} ({i}){suffix}"
        i += 1
    return path


class FileShareClient:
    """One TCP connection to the server = one login session."""

    def __init__(self, host, port=DEFAULT_PORT, tls=False, cafile=None,
                 connect_timeout=10, timeout=120):
        self.host, self.port = host, port
        self.tls, self.cafile = tls, cafile
        self.connect_timeout, self.timeout = connect_timeout, timeout
        self.sock = None
        self.greeting = None
        self.user = None
        self.role = None

    # -- connection ------------------------------------------------------
    def connect(self):
        raw = socket.create_connection((self.host, self.port),
                                       timeout=self.connect_timeout)
        raw.settimeout(self.timeout)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self.tls:
            context = ssl.create_default_context(cafile=self.cafile)
            self.sock = context.wrap_socket(raw, server_hostname=self.host)
        else:
            self.sock = raw
        greeting = recv_msg(self.sock)      # the server speaks first
        if not greeting.get("ok"):
            self.close()
            raise FileShareError(greeting.get("error", "Server refused the connection"),
                                 greeting.get("code", "ERROR"))
        self.greeting = greeting
        return greeting

    def login(self, user, password):
        send_msg(self.sock, {"op": "login", "user": user, "password": password})
        reply = self._expect_ok()
        self.user, self.role = reply["user"], reply["role"]

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def quit(self):
        """Polite goodbye, then close."""
        try:
            if self.sock is not None:
                send_msg(self.sock, {"op": "quit"})
                recv_msg(self.sock)
        except (OSError, ValueError):
            pass
        finally:
            self.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.quit()

    # -- plumbing --------------------------------------------------------
    def _expect_ok(self):
        reply = recv_msg(self.sock)
        if not reply.get("ok"):
            raise FileShareError(reply.get("error", "Server returned an error"),
                                 reply.get("code", "ERROR"))
        return reply

    def request(self, op, **fields):
        send_msg(self.sock, {"op": op, **fields})
        return self._expect_ok()

    # -- simple commands -------------------------------------------------
    def list_files(self):
        return self.request("list")["files"]

    def info(self, ref):
        return self.request("info", file=ref)["file"]

    def stats(self):
        return self.request("stats")["stats"]

    def whoami(self):
        return self.request("whoami")

    def delete(self, ref):
        self.request("delete", file=ref)

    def share(self, ref, user):
        self.request("share", file=ref, user=user)

    def unshare(self, ref, user):
        self.request("unshare", file=ref, user=user)

    def set_visibility(self, ref, visibility):
        self.request("visibility", file=ref, visibility=visibility)

    # -- upload ----------------------------------------------------------
    def upload(self, path, name=None, visibility="private", progress=None):
        """Send a file: header first (name, size), then the bytes in chunks."""
        path = Path(path)
        size = path.stat().st_size
        if size > MAX_FILE_SIZE:
            raise ValueError("This prototype accepts files up to 1 GiB")
        started = time.perf_counter()

        send_msg(self.sock, {"op": "upload", "name": name or path.name,
                             "size": size, "visibility": visibility})
        self._expect_ok()                    # server says "ready" (or refuses)

        digest = hashlib.sha256()
        buffer = bytearray(CHUNK)
        view = memoryview(buffer)
        sent = 0
        data_started = time.perf_counter()
        try:
            with path.open("rb") as source:
                while True:
                    n = source.readinto(buffer)
                    if not n:
                        break
                    self.sock.sendall(view[:n])
                    digest.update(view[:n])
                    sent += n
                    if progress:
                        progress(sent, size)
            final = self._expect_ok()        # server confirms it stored the file
        except FileShareError:
            raise
        except (OSError, ValueError):
            # The server may have explained itself before closing.
            explanation = None
            try:
                explanation = recv_msg(self.sock)
            except Exception:
                pass
            self.close()
            if explanation and not explanation.get("ok"):
                raise FileShareError(explanation.get("error", "Upload failed"),
                                     explanation.get("code", "ERROR"))
            raise
        done = time.perf_counter()

        seconds = done - data_started
        return {
            "ref": final["ref"], "bytes": size, "seconds": seconds,
            "elapsed": done - started, "mbit_per_s": mbit_per_s(size, seconds),
            "verified": final.get("sha256") == digest.hexdigest(),
        }

    # -- download --------------------------------------------------------
    def download(self, ref, dest=None, dest_dir="downloads", progress=None,
                 discard=False):
        """Fetch a file.  The server decides whether we are allowed to.

        discard=True receives and checks the bytes but does not save them
        (used by benchmark.py so disk speed does not distort network results).
        """
        started = time.perf_counter()
        send_msg(self.sock, {"op": "download", "file": ref})
        head = self._expect_ok()     # raises FileShareError("Access denied ...")
        size = head["size"]

        target = temporary = None
        if not discard:
            name = Path(head["name"]).name
            target = Path(dest) if dest else unique_path(dest_dir, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.part")

        digest = hashlib.sha256()
        buffer = bytearray(CHUNK)
        view = memoryview(buffer)
        received = 0
        data_started = time.perf_counter()
        output = None
        try:
            output = temporary.open("xb") if temporary else None
            while received < size:
                n = self.sock.recv_into(view, min(CHUNK, size - received))
                if n == 0:
                    raise ConnectionError("Download ended before the expected size")
                if output:
                    output.write(view[:n])
                digest.update(view[:n])
                received += n
                if progress:
                    progress(received, size)
            if output:
                output.close()
                output = None
        except BaseException:
            if output:
                output.close()
            if temporary:
                temporary.unlink(missing_ok=True)
            self.close()       # the byte stream is out of step; do not reuse it
            raise
        done = time.perf_counter()

        verified = digest.hexdigest() == head.get("sha256")
        if temporary:
            if verified:
                os.replace(temporary, target)
            else:
                temporary.unlink(missing_ok=True)
        if not verified:
            raise FileShareError("Checksum mismatch: the downloaded file is damaged",
                                 "CORRUPT")
        seconds = done - data_started
        return {
            "ref": ref, "path": str(target) if target else None, "bytes": size,
            "seconds": seconds, "elapsed": done - started,
            "mbit_per_s": mbit_per_s(size, seconds), "verified": True,
            "access": head.get("access"),
        }


# ---------------------------------------------------------------------------
# command-line front end
# ---------------------------------------------------------------------------
class Progress:
    """Tiny progress indicator, only for large files on a terminal."""

    def __init__(self, label):
        self.label, self.last = label, 0.0
        self.enabled = sys.stderr.isatty()

    def __call__(self, done, total):
        if not self.enabled or total < 4 * 1024 * 1024:
            return
        now = time.monotonic()
        if now - self.last > 0.1 or done == total:
            self.last = now
            print(f"\r  {self.label} {done * 100 // total:3d}%", end="",
                  file=sys.stderr, flush=True)
            if done == total:
                print(file=sys.stderr)


def print_files(files):
    if not files:
        print("(no files visible to you)")
        return
    header = f"{'FILE':<28}{'SIZE':>10}  {'VISIBILITY':<11}{'ACCESS':<7} {'UPLOADED':<20} SHARED WITH"
    print(header)
    for f in files:
        shared = ",".join(f.get("shared_with", [])) or "-"
        print(f"{f['ref']:<28}{format_size(f['size']):>10}  {f['visibility']:<11}"
              f"{f['access']:<7} {f['uploaded_at'].replace('T', ' ')[:19]:<20} {shared}")


def print_transfer(verb, result):
    check = "checksum OK" if result["verified"] else "CHECKSUM MISMATCH"
    where = f" -> {result['path']}" if result.get("path") else ""
    print(f"{verb} {result['ref']}{where}  {format_size(result['bytes'])} in "
          f"{result['seconds']:.2f} s ({result['mbit_per_s']:.1f} Mbit/s), {check}")


def get_password(args):
    return (args.password or os.environ.get("FILESHARE_PASSWORD")
            or getpass.getpass(f"Password for {args.user}: "))


def open_session(args):
    if not args.user:
        sys.exit("Error: --user is required for this command")
    client = FileShareClient(args.host, args.port, tls=args.tls, cafile=args.cafile,
                             connect_timeout=args.connect_timeout)
    client.connect()
    client.login(args.user, get_password(args))
    return client


def run_command(client, command, words):
    """Execute one command with already-split arguments.  Shared by the
    one-shot CLI and the interactive shell."""
    if command in ("list", "ls"):
        print_files(client.list_files())

    elif command in ("upload", "put"):
        public = "--public" in words
        words = [w for w in words if w != "--public"]
        if len(words) != 1:
            raise ValueError("usage: upload FILE [--public]")
        result = client.upload(words[0], visibility="public" if public else "private",
                               progress=Progress("uploading"))
        print_transfer("Uploaded", result)

    elif command in ("download", "get"):
        if not 1 <= len(words) <= 2:
            raise ValueError("usage: download FILE [DESTINATION]")
        result = client.download(words[0], dest=words[1] if len(words) > 1 else None,
                                 progress=Progress("downloading"))
        print_transfer("Downloaded", result)

    elif command in ("delete", "rm"):
        if len(words) != 1:
            raise ValueError("usage: delete FILE")
        client.delete(words[0])
        print(f"Deleted {words[0]}")

    elif command in ("share", "unshare"):
        if len(words) != 2:
            raise ValueError(f"usage: {command} FILE USER")
        getattr(client, command)(words[0], words[1])
        verb = "Shared" if command == "share" else "Stopped sharing"
        print(f"{verb} {words[0]} with {words[1]}")

    elif command in ("visibility", "vis"):
        if len(words) != 2 or words[1] not in ("public", "private"):
            raise ValueError("usage: visibility FILE public|private")
        client.set_visibility(words[0], words[1])
        print(f"{words[0]} is now {words[1]}")

    elif command == "info":
        if len(words) != 1:
            raise ValueError("usage: info FILE")
        for key, value in client.info(words[0]).items():
            print(f"{key:<12} {value}")

    elif command == "stats":
        for key, value in client.stats().items():
            print(f"{key:<20} {value}")

    elif command == "whoami":
        reply = client.whoami()
        print(f"{reply['user']} ({reply['role']}) connected from {reply['ip']}")

    else:
        raise ValueError(f"unknown command: {command}")


SHELL_HELP = """\
Commands:
  ls                         list files you may access
  put FILE [--public]        upload a file (private unless --public)
  get FILE [DESTINATION]     download (FILE is 'name' for yours, 'owner/name' for others')
  rm FILE                    delete one of your files
  share FILE USER            let USER download FILE
  unshare FILE USER          stop sharing FILE with USER
  vis FILE public|private    change who can see FILE
  info FILE                  show file metadata
  stats                      server statistics
  whoami                     show your login
  quit                       leave"""


def shell(client):
    print(f"Logged in as {client.user} ({client.role}).  Type 'help' for commands.")
    while True:
        try:
            line = input("fileshare> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        try:
            words = shlex.split(line)
        except ValueError as error:
            print(f"Error: {error}")
            continue
        command, words = words[0].lower(), words[1:]
        if command in ("quit", "exit"):
            break
        if command == "help":
            print(SHELL_HELP)
            continue
        try:
            run_command(client, command, words)
        except FileShareError as error:
            print(f"Error: {error}")
        except (ValueError, OSError) as error:
            print(f"Error: {error}")
            if client.sock is None:
                print("Connection lost; start the shell again.")
                return


def words_for(args):
    """Turn parsed command-line arguments into the word list run_command expects."""
    c = args.command
    if c in ("upload", "put"):
        return [args.file] + (["--public"] if args.public else [])
    if c in ("download", "get"):
        return [args.file] + ([args.destination] if args.destination else [])
    if c in ("delete", "rm", "info"):
        return [args.file]
    if c in ("share", "unshare"):
        return [args.file, args.target_user]
    if c in ("visibility", "vis"):
        return [args.file, args.value]
    return []


def main():
    parser = argparse.ArgumentParser(description="Concurrent file sharing client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--user", help="your username")
    parser.add_argument("--password", help="(otherwise asked, or FILESHARE_PASSWORD)")
    parser.add_argument("--tls", action="store_true", help="connect with TLS")
    parser.add_argument("--cafile", help="server certificate to trust (with --tls)")
    parser.add_argument("--connect-timeout", type=float, default=10,
                        help="seconds to wait for the TCP connection")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("probe", help="check that the server is reachable")
    commands.add_parser("list", aliases=["ls"])
    up = commands.add_parser("upload", aliases=["put"])
    up.add_argument("file")
    up.add_argument("--public", action="store_true")
    down = commands.add_parser("download", aliases=["get"])
    down.add_argument("file")
    down.add_argument("destination", nargs="?")
    rm = commands.add_parser("delete", aliases=["rm"])
    rm.add_argument("file")
    for name in ("share", "unshare"):
        p = commands.add_parser(name)
        p.add_argument("file")
        p.add_argument("target_user")
    vis = commands.add_parser("visibility", aliases=["vis"])
    vis.add_argument("file")
    vis.add_argument("value", choices=["public", "private"])
    info = commands.add_parser("info")
    info.add_argument("file")
    commands.add_parser("stats")
    commands.add_parser("whoami")
    commands.add_parser("shell", help="interactive session")

    args = parser.parse_args()
    command = args.command

    try:
        if command == "probe":
            client = FileShareClient(args.host, args.port, tls=args.tls,
                                     cafile=args.cafile,
                                     connect_timeout=args.connect_timeout)
            greeting = client.connect()
            client.close()
            print(f"Server {args.host}:{args.port} reachable "
                  f"(protocol {greeting['protocol']}, TLS {'on' if greeting['tls'] else 'off'})")
            return

        client = open_session(args)
        try:
            if command == "shell":
                shell(client)
            else:
                words = words_for(args)
                run_command(client, command, words)
        finally:
            client.quit()
    except FileShareError as error:
        sys.exit(f"Error: {error}")
    except socket.timeout:
        sys.exit("Error: timed out (is the host reachable? is the network blocking it?)")
    except (ConnectionError, ssl.SSLError, OSError, ValueError) as error:
        sys.exit(f"Error: {error}")


if __name__ == "__main__":
    main()
