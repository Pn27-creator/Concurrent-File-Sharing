# Concurrent File Sharing System: CLIENT

Python 3.8+ , standard library only (`benchmark.py --plot` additionally uses matplotlib if installed).

```
fileshare-client/
  client.py                 command-line and interactive client (also a reusable library)
  benchmark.py              performance evaluation: file sizes x simultaneous clients
  demo_access_control.py    scripted walk-through of the access rules
  protocol.py               message framing (identical copy lives in the server package)
  samples/sample.txt        something small to upload
  downloads/                default place for downloaded files (created automatically)
```

## Everyday use

The server must be running and your account must exist (`manage_users.py` on the server).
The password is asked for (hidden); or use `--password`, or the `FILESHARE_PASSWORD` environment variable.

```bash
python3 client.py --host 192.168.1.20 --user alice list
python3 client.py --host 192.168.1.20 --user alice upload samples/sample.txt              # private
python3 client.py --host 192.168.1.20 --user alice upload photo.jpg --public              # anyone can download
python3 client.py --host 192.168.1.20 --user bob   download alice/photo.jpg               # -> downloads/photo.jpg
python3 client.py --host 192.168.1.20 --user bob   download alice/photo.jpg out/p.jpg     # choose the destination
python3 client.py --host 192.168.1.20 --user alice share samples/sample.txt bob           # let bob download it
python3 client.py --host 192.168.1.20 --user alice unshare sample.txt bob
python3 client.py --host 192.168.1.20 --user alice visibility sample.txt public           # or private
python3 client.py --host 192.168.1.20 --user alice info sample.txt
python3 client.py --host 192.168.1.20 --user alice delete sample.txt
python3 client.py --host 192.168.1.20 probe                                               # is the server reachable?
```

`name` means your own file, `owner/name` means someone else's. `list` shows only files you may access.
Downloads are verified with SHA-256 and written only when complete; a refused download leaves no file.

**Interactive session** (log in once): `python3 client.py --host 192.168.1.20 --user alice shell`, then
`ls`, `put FILE [--public]`, `get REF [DEST]`, `rm`, `share`, `unshare`, `vis`, `info`, `stats`, `whoami`, `help`, `quit`.

TLS (if the server uses it): add `--tls --cafile server-cert.pem`.

## Access-control demo

```bash
python3 demo_access_control.py --host 192.168.1.20     # needs the server's demo users
```

Runs private / public / shared / admin / non-owner scenarios against the real server and prints
ALLOWED / DENIED for each.

## Performance evaluation

```bash
python3 benchmark.py --host 192.168.1.20 --user alice --password alice123 \
        --sizes 100KB,1MB,10MB,50MB --clients 1,2,4,8 --repeat 3 --csv results.csv --plot results.png
```

For every (file size, clients) pair, N clients connect and log in first, then start together; the tool
times only the data transfer and reports time per client, per-client throughput (bits / seconds) and
aggregate throughput (all bytes / first start to last finish) for upload and download. Averages over
`--repeat` runs. `--mode upload|download`, `--same-file` (all clients fetch one file), `--save-downloads`.

Interpretation tips: on one machine (127.0.0.1) the numbers show your CPU and Python, not a network; run it
between two machines, or use the Mininet lab in `fileshare-sdn`, where links have a bandwidth limit and the
aggregate throughput visibly saturates as clients are added.
