# Concurrent File Sharing System: SERVER

Python 3.8+ , standard library only (no `pip install`).

```
fileshare-server/
  server.py        listener, one worker thread per connection, upload / download / sharing
  auth.py          authentication: users, salted password hashes, login lockout
  metadata.py      file metadata + authorization (access-control) rules
  protocol.py      message framing (identical copy lives in the client package)
  manage_users.py  create / list / remove users, change passwords
  make_cert.sh     optional: self-signed certificate for TLS
  data/            created on first run: users.json, metadata.json, audit.log, blobs/
```

## Run it

```bash
python3 manage_users.py demo-users        # alice, bob, carol (users) and admin (admin); passwords: <name>123
python3 server.py                         # listens on 0.0.0.0:5000
```

Real accounts: `python3 manage_users.py add alice` (asks for a password; `--role admin` for an admin).
Options: `--port`, `--max-clients 16`, `--data-dir`, `--idle-timeout 300`, `-v`.
The server re-reads `users.json` by itself, so adding users needs no restart.

## What the server does

**Connection = session.** A client connects, the server greets it, the client logs in, then sends commands
(`list`, `upload`, `download`, `share`, ...) until it quits. Each connection has its own thread, so
uploads and downloads from different clients run at the same time. A semaphore limits simultaneous
connections (`--max-clients`); client number N+1 is told "Server is busy". Idle connections time out.

**Framing.** TCP is a byte stream with no message boundaries, so every message is
`[4-byte length][JSON header]`, followed (for transfers) by exactly `size` raw bytes. Files move in 64 KiB chunks.
The server hashes every upload while receiving it (SHA-256) and the client checks every download against that
hash, so a damaged transfer is detected end to end.

**Files are addressed `owner/name`.** `report.pdf` means *my* file; `alice/report.pdf` means alice's. Two users can
therefore upload files with the same name.

**Metadata is separate from contents.** Bytes live in `data/blobs/<random id>`. Name, size, owner, upload
time, SHA-256, visibility, share list and download count live in `data/metadata.json`. Listing files and
checking permissions never read file contents.

### Access control (authorization), checked by the server on every request

| Who | May download | May share / change visibility / delete |
|---|---|---|
| owner of the file | yes | yes |
| `admin` role | yes | yes |
| anyone, if file is **public** | yes | no |
| a user in the file's **share list** | yes | no |
| everyone else | **denied** (`ACCESS_DENIED`) | no |

Authentication (who are you?) and authorization (what may you do?) are separate steps:
`auth.py` answers the first, `metadata.py` the second. Every login, denial, upload, download, share and
delete is appended to `data/audit.log` (JSON lines).

Other protections: passwords stored as salted PBKDF2-HMAC-SHA256 (200,000 rounds); 5 failed logins from one
IP in 60 s locks that IP out for 30 s; file names cannot contain `/`, `\`, or `..` (so no path traversal;
file bytes are stored under random ids anyway); a file being downloaded cannot be deleted; unfinished uploads
are discarded and never become visible.

## Optional TLS

Plain TCP does **not** encrypt anything, so on a plain connection the password and file bytes can be read by
anyone who can capture packets (try `tcpdump`/Wireshark in the lab). Keep plain mode to a trusted lab
network. To encrypt:

```bash
./make_cert.sh 10.0.0.100                 # add the server's IP(s); also valid for localhost
python3 server.py --tls-cert server-cert.pem --tls-key server-key.pem
# client machine: copy server-cert.pem, then   python3 client.py --tls --cafile server-cert.pem ...
```

## Concept map (your presentation script -> code)

| Concept in the script | Where |
|---|---|
| IP address + port, socket, listen/accept | `server.py` `FileServer.serve_forever`; client `connect()` |
| TCP is reliable but has no message boundaries -> framing | `protocol.py`, upload/download headers |
| Chunked transfer, counting bytes moved | `CHUNK`, `Session.receive_file`, `op_download`, `op_stats`, per-transfer log lines |
| Thread per connection, with limits | `FileServer.worker`, `BoundedSemaphore`, `reject_busy`, `--idle-timeout` |
| Metadata separate from file contents | `metadata.py` + `data/metadata.json` vs `data/blobs/` |
| Authentication | `auth.py`, `Session.login` |
| Authorization | `MetadataStore.access_level`, `begin_download` |
| No encryption in TCP -> TLS | `--tls-cert/--tls-key`, `make_cert.sh` |
| SDN, Mininet, OpenFlow, counters | the separate `fileshare-sdn` package |
| Throughput evaluation | `benchmark.py` in the client package; `topology.py` step 4 |

## Known limits (prototype)

Denial messages reveal that a file exists (clearer for demos; production systems often answer "not found").
Metadata is a JSON file rewritten on each change (fine for hundreds of files, not millions). No per-user
quotas. An `admin` can read every file. Lockout is per IP, so users behind one NAT share it.
