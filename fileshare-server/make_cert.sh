#!/usr/bin/env bash
# Optional: create a self-signed TLS certificate for the file server.
#
#   ./make_cert.sh                  # valid for localhost and 127.0.0.1
#   ./make_cert.sh 10.0.0.100       # also valid for that IP (e.g. the Mininet server)
#
# Produces server-cert.pem and server-key.pem in the current directory.
#   server:  python3 server.py --tls-cert server-cert.pem --tls-key server-key.pem
#   client:  copy server-cert.pem to the client machine, then
#            python3 client.py --tls --cafile server-cert.pem --host <ip> ...
set -euo pipefail

san="DNS:localhost,IP:127.0.0.1"
for ip in "$@"; do san="$san,IP:$ip"; done

openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout server-key.pem -out server-cert.pem \
  -subj "/CN=fileshare-server" \
  -addext "subjectAltName=$san" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign" \
  -addext "extendedKeyUsage=serverAuth" \
  -addext "subjectKeyIdentifier=hash" \
  -addext "authorityKeyIdentifier=keyid:always" 2>/dev/null

chmod 600 server-key.pem
echo "Created server-cert.pem and server-key.pem (valid for: $san)"
