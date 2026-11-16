#!/usr/bin/env python3
"""Concurrent File Sharing System -- server.

    python3 server.py                      # listens on 0.0.0.0:5000
    python3 server.py --port 6000 --max-clients 8
    python3 server.py --tls-cert cert.pem --tls-key key.pem   # optional TLS

How it works (see README.md for the full concept map)
-----------------------------------------------------
* A listening TCP socket (IP address + port) accepts connections.
* Each accepted connection gets its own worker thread, so one client can
  upload while another downloads.  A semaphore caps the number of
  simultaneous connections, because every connection costs memory, CPU
  time and disk access; extra clients are told "server busy".
* A connection is a *session*: the client logs in first (authentication),
  then sends commands.  Every command is checked against the file's
  permissions (authorization) before anything happens.
* Messages use the framing in protocol.py; files move in 64 KiB chunks.
"""

import argparse
import hashlib
import json
import logging
import os
import socket
import ssl
import sys
import threading
import time
import uuid
from pathlib import Path

from auth import UserStore, valid_username
from metadata import MetadataStore, RequestError, make_ref
from protocol import (CHUNK, MAX_FILE_SIZE, PROTOCOL_VERSION, recv_msg,
                      send_msg)

log = logging.getLogger("fileshare")

MAX_LOGIN_ATTEMPTS = 3


def safe_name(name):
    """A plain file name: no folders, no tricks like '..'."""
    if (not isinstance(name, str) or not name or len(name) > 180
            or name in {".", ".."} or "/" in name or "\\" in name
            or any(ord(c) < 32 for c in name)):
        raise RequestError("Use a simple file name without folders", "BAD_NAME")
    return name


def mbit_per_s(nbytes, seconds):
    return (nbytes * 8 / 1e6) / seconds if seconds > 0 else 0.0


class FileServer:
    def __init__(self, host, port, data_dir, max_clients, idle_timeout, tls_context=None):
        self.host, self.port = host, port
        self.idle_timeout = idle_timeout
        self.tls = tls_context

        self.data_dir = Path(data_dir)
        self.blob_dir = self.data_dir / "blobs"
        self.blob_dir.mkdir(parents=True, exist_ok=True)
        for leftover in self.blob_dir.glob(".incoming-*.part"):
            leftover.unlink(missing_ok=True)    # unfinished uploads from a crash

        self.users = UserStore(self.data_dir / "users.json")
        self.meta = MetadataStore(self.data_dir / "metadata.json")

        # Limit on simultaneous connections (resource protection).
        self.slots = threading.BoundedSemaphore(max_clients)
        self.max_clients = max_clients

        self._stats_lock = threading.Lock()
        self._stats = {"active": 0, "uploads": 0, "downloads": 0,
                       "bytes_up": 0, "bytes_down": 0, "started": time.time()}

        self._audit_lock = threading.Lock()
        self._audit_path = self.data_dir / "audit.log"

    # -- bookkeeping -----------------------------------------------------
    def bump(self, **deltas):
        with self._stats_lock:
            for key, value in deltas.items():
                self._stats[key] += value

    def snapshot(self):
        with self._stats_lock:
            s = dict(self._stats)
        return {
            "active_connections": s["active"], "max_connections": self.max_clients,
            "uploads": s["uploads"], "downloads": s["downloads"],
            "bytes_uploaded": s["bytes_up"], "bytes_downloaded": s["bytes_down"],
            "files_stored": self.meta.count(),
            "uptime_seconds": int(time.time() - s["started"]),
        }

    def audit(self, event, **fields):
        """Append one JSON line to data/audit.log (who did what, allowed or not)."""
        record = {"time": time.strftime("%Y-%m-%dT%H:%M:%S"), "event": event, **fields}
        with self._audit_lock, self._audit_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    # -- accept loop -----------------------------------------------------
    def serve_forever(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.host, self.port))
            listener.listen(self.max_clients)
            mode = "TLS" if self.tls else "plain TCP (no encryption)"
            log.info("File server listening on %s:%d  [%s, max %d clients]",
                     self.host, self.port, mode, self.max_clients)
            log.info("Data directory: %s", self.data_dir.resolve())

            while True:
                try:
                    sock, addr = listener.accept()
                except OSError as error:
                    log.warning("accept failed: %s", error)
                    time.sleep(0.1)
                    continue

                if not self.slots.acquire(blocking=False):
                    self.reject_busy(sock, addr)
                    continue
                self.bump(active=1)
                threading.Thread(target=self.worker, args=(sock, addr),
                                 daemon=True).start()

    def reject_busy(self, sock, addr):
        log.warning("%s rejected: server busy (%d clients)", addr[0], self.max_clients)
        try:
            with sock:
                if self.tls is None:    # with TLS the handshake would block us
                    sock.settimeout(2)
                    send_msg(sock, {"ok": False, "error": "Server is busy", "code": "BUSY"})
                    sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def worker(self, raw, addr):
        """Runs in its own thread: one connection = one worker."""
        sock = raw
        try:
            raw.settimeout(self.idle_timeout)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if self.tls is not None:
                sock = self.tls.wrap_socket(raw, server_side=True)  # handshake
            Session(self, sock, addr).run()
        except socket.timeout:
            log.info("%s: idle timeout, closing", addr[0])
        except (ConnectionError, ssl.SSLError, OSError) as error:
            log.info("%s: connection ended (%s)", addr[0], error)
        except ValueError as error:
            # Malformed header (bad length or bad JSON): drop this client only.
            log.warning("%s: protocol violation (%s), closing", addr[0], error)
        except Exception:
            log.exception("%s: unexpected error", addr[0])
        finally:
            try:
                sock.close()
            except OSError:
                pass
            self.bump(active=-1)
            self.slots.release()


class Session:
    """One client connection: login, then a loop of commands."""

    def __init__(self, server, sock, addr):
        self.server = server
        self.sock = sock
        self.ip = addr[0]
        self.user = None
        self.role = None

    # -- session flow ----------------------------------------------------
    def run(self):
        s = self.server
        send_msg(self.sock, {
            "ok": True, "server": "fileshare", "protocol": PROTOCOL_VERSION,
            "tls": s.tls is not None, "auth": "login",
            "max_file_size": MAX_FILE_SIZE,
        })
        if not self.login():
            return
        log.info("%s logged in as %s (%s)", self.ip, self.user, self.role)

        while True:
            try:
                request = recv_msg(self.sock)
            except ConnectionError:
                break                       # client hung up between commands
            if not self.dispatch(request):
                break
        log.info("%s (%s) disconnected", self.ip, self.user)

    def login(self):
        """AUTHENTICATION: verify the username and password."""
        s = self.server
        for _ in range(MAX_LOGIN_ATTEMPTS):
            request = recv_msg(self.sock)
            if request.get("op") == "quit":
                return False
            if request.get("op") != "login":
                send_msg(self.sock, {"ok": False, "error": "Please log in first",
                                     "code": "AUTH_REQUIRED"})
                continue
            ok, info = s.users.check_login(
                self.ip, request.get("user"), request.get("password"))
            if ok:
                self.user, self.role = request["user"], info
                send_msg(self.sock, {"ok": True, "user": self.user, "role": self.role})
                s.audit("login_ok", user=self.user, ip=self.ip)
                return True
            s.audit("login_failed", user=str(request.get("user"))[:40], ip=self.ip)
            log.warning("%s: failed login for %r", self.ip, str(request.get("user"))[:40])
            send_msg(self.sock, {"ok": False, "error": info, "code": "AUTH_FAILED"})
            if s.users.locked_for(self.ip):
                break
        return False

    def dispatch(self, request):
        """Run one command.  Returns False when the session should end."""
        op = request.get("op")
        handler = {
            "list": self.op_list, "info": self.op_info,
            "upload": self.op_upload, "download": self.op_download,
            "delete": self.op_delete, "share": self.op_share,
            "unshare": self.op_unshare, "visibility": self.op_visibility,
            "stats": self.op_stats, "whoami": self.op_whoami,
            "quit": self.op_quit,
        }.get(op) if isinstance(op, str) else None
        try:
            if handler is None:
                raise RequestError("Unknown operation", "BAD_OP")
            return handler(request) is not False
        except RequestError as error:
            # A problem with this one request; the connection is still fine.
            send_msg(self.sock, {"ok": False, "error": str(error), "code": error.code})
            return True

    # -- helpers ---------------------------------------------------------
    def parse_ref(self, ref):
        """'notes.txt' = my file;  'alice/notes.txt' = alice's file."""
        if not isinstance(ref, str) or not ref:
            raise RequestError("A file name is required", "BAD_NAME")
        if "/" in ref:
            owner, name = ref.split("/", 1)
            if not valid_username(owner):
                raise RequestError("Invalid file reference", "BAD_NAME")
        else:
            owner, name = self.user, ref
        return owner, safe_name(name)

    # -- commands ----------------------------------------------------------
    def op_whoami(self, request):
        send_msg(self.sock, {"ok": True, "user": self.user, "role": self.role,
                             "ip": self.ip})

    def op_quit(self, request):
        send_msg(self.sock, {"ok": True})
        return False

    def op_stats(self, request):
        send_msg(self.sock, {"ok": True, "stats": self.server.snapshot()})

    def op_list(self, request):
        files = self.server.meta.list_visible(self.user, self.role)
        send_msg(self.sock, {"ok": True, "files": files})

    def op_info(self, request):
        owner, name = self.parse_ref(request.get("file"))
        send_msg(self.sock, {"ok": True,
                             "file": self.server.meta.info(self.user, self.role, owner, name)})

    def op_upload(self, request):
        s = self.server
        name = safe_name(request.get("name"))
        size = request.get("size")
        if type(size) is not int or size < 0 or size > MAX_FILE_SIZE:
            raise RequestError("Invalid file size, or file exceeds 1 GiB", "BAD_SIZE")
        visibility = request.get("visibility", "private")
        if visibility not in ("public", "private"):
            raise RequestError("Visibility must be 'public' or 'private'")

        s.meta.reserve(self.user, name)      # fails if owner/name already exists
        temporary = s.blob_dir / f".incoming-{uuid.uuid4().hex}.part"
        file_id = uuid.uuid4().hex
        blob = s.blob_dir / file_id
        committed = False
        try:
            send_msg(self.sock, {"ok": True, "ready": True})
            started = time.perf_counter()
            digest = self.receive_file(temporary, size)
            os.replace(temporary, blob)
            record = s.meta.commit(self.user, name, file_id, size, digest, visibility)
            committed = True
        finally:
            if not committed:
                temporary.unlink(missing_ok=True)
                blob.unlink(missing_ok=True)
                s.meta.release(self.user, name)

        seconds = time.perf_counter() - started
        ref = make_ref(self.user, name)
        s.bump(uploads=1, bytes_up=size)
        s.audit("upload", user=self.user, ip=self.ip, file=ref, bytes=size)
        log.info("%s uploaded %s: %d bytes in %.2f s (%.1f Mbit/s)",
                 self.user, ref, size, seconds, mbit_per_s(size, seconds))
        send_msg(self.sock, {"ok": True, "ref": ref, "size": size,
                             "sha256": digest, "visibility": record["visibility"]})

    def receive_file(self, path, size):
        """Read exactly `size` bytes in chunks, saving and hashing as we go."""
        digest = hashlib.sha256()
        remaining = size
        buffer = bytearray(CHUNK)
        view = memoryview(buffer)
        with path.open("xb") as output:
            while remaining:
                n = self.sock.recv_into(view, min(CHUNK, remaining))
                if n == 0:
                    raise ConnectionError("Upload ended before the declared size")
                try:
                    output.write(view[:n])
                except OSError as error:
                    try:
                        send_msg(self.sock, {"ok": False, "code": "STORAGE",
                                             "error": f"Server could not store the file: {error}"})
                    except OSError:
                        pass
                    raise ConnectionError(f"disk error: {error}")
                digest.update(view[:n])
                remaining -= n
        return digest.hexdigest()

    def op_download(self, request):
        s = self.server
        owner, name = self.parse_ref(request.get("file"))
        ref = make_ref(owner, name)

        # AUTHORIZATION: may *this* user read *this* file?  Decided here, on
        # the server, for every single request.
        try:
            record, why = s.meta.begin_download(self.user, self.role, owner, name)
        except RequestError as error:
            s.audit("download_denied" if error.code == "ACCESS_DENIED" else "download_failed",
                    user=self.user, ip=self.ip, file=ref, reason=error.code)
            if error.code == "ACCESS_DENIED":
                log.warning("%s DENIED download of %s", self.user, ref)
            raise

        completed = False
        try:
            try:
                source = (s.blob_dir / record["id"]).open("rb")
            except FileNotFoundError:
                raise RequestError("File data is missing on the server", "MISSING")
            with source:
                size = os.fstat(source.fileno()).st_size
                if size != record["size"]:
                    raise RequestError("File is damaged on the server", "CORRUPT")
                send_msg(self.sock, {"ok": True, "size": size, "name": name,
                                     "owner": owner, "sha256": record["sha256"],
                                     "access": why})
                started = time.perf_counter()
                buffer = bytearray(CHUNK)
                view = memoryview(buffer)
                while True:
                    n = source.readinto(buffer)
                    if not n:
                        break
                    self.sock.sendall(view[:n])
            completed = True
        finally:
            s.meta.end_download(record["id"], completed)

        seconds = time.perf_counter() - started
        s.bump(downloads=1, bytes_down=size)
        s.audit("download", user=self.user, ip=self.ip, file=ref, bytes=size, access=why)
        log.info("%s downloaded %s [%s]: %d bytes in %.2f s (%.1f Mbit/s)",
                 self.user, ref, why, size, seconds, mbit_per_s(size, seconds))

    def op_delete(self, request):
        s = self.server
        owner, name = self.parse_ref(request.get("file"))
        file_id = s.meta.delete(self.user, self.role, owner, name)
        (s.blob_dir / file_id).unlink(missing_ok=True)
        s.audit("delete", user=self.user, ip=self.ip, file=make_ref(owner, name))
        send_msg(self.sock, {"ok": True})

    def op_share(self, request):
        self.change_sharing(request, share=True)

    def op_unshare(self, request):
        self.change_sharing(request, share=False)

    def change_sharing(self, request, share):
        s = self.server
        owner, name = self.parse_ref(request.get("file"))
        target = request.get("user")
        if not valid_username(target) or not s.users.exists(target):
            raise RequestError("No such user", "NO_USER")
        change = s.meta.share if share else s.meta.unshare
        change(self.user, self.role, owner, name, target)
        s.audit("share" if share else "unshare", user=self.user, ip=self.ip,
                file=make_ref(owner, name), target=target)
        send_msg(self.sock, {"ok": True})

    def op_visibility(self, request):
        owner, name = self.parse_ref(request.get("file"))
        value = request.get("visibility")
        self.server.meta.set_visibility(self.user, self.role, owner, name, value)
        self.server.audit("visibility", user=self.user, ip=self.ip,
                          file=make_ref(owner, name), visibility=value)
        send_msg(self.sock, {"ok": True})


def build_tls_context(cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    return context


def main():
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Concurrent file sharing server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--data-dir", default=str(here / "data"),
                        help="where users, metadata and file contents are kept")
    parser.add_argument("--max-clients", type=int, default=16,
                        help="maximum simultaneous connections")
    parser.add_argument("--idle-timeout", type=int, default=300,
                        help="seconds of silence before a connection is dropped")
    parser.add_argument("--tls-cert", help="PEM certificate (enables TLS)")
    parser.add_argument("--tls-key", help="PEM private key (enables TLS)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(message)s", datefmt="%H:%M:%S")

    tls = None
    if args.tls_cert or args.tls_key:
        if not (args.tls_cert and args.tls_key):
            parser.error("--tls-cert and --tls-key must be given together")
        tls = build_tls_context(args.tls_cert, args.tls_key)

    server = FileServer(args.host, args.port, args.data_dir,
                        args.max_clients, args.idle_timeout, tls)
    if not server.users.all_users():
        log.warning("No users yet. Create some first:  python3 manage_users.py demo-users")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down")
    except OSError as error:
        sys.exit(f"Cannot start server: {error}")


if __name__ == "__main__":
    main()
