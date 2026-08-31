#!/usr/bin/env bash
# Create self-signed certificates for nginx and Postgres.
#
#   sudo ./scripts/gen-certs.sh 10.20.30.40 afrashodan.company.local
#
# Pass every address or hostname people will use to reach the platform; each one
# becomes a SAN entry, and a browser rejects a certificate that omits the name
# in the URL bar. If your company runs its own CA, skip this script and place
# the issued files at certs/server.crt and certs/server.key instead — the rest
# of the setup is identical.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ $# -eq 0 ]]; then
    echo "usage: $0 <ip-or-hostname> [more names...]" >&2
    exit 1
fi

# Build the SAN list: IPs and DNS names are declared differently.
sans=""
for name in "$@"; do
    if [[ "$name" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
        sans+="IP:$name,"
    else
        sans+="DNS:$name,"
    fi
done
sans+="DNS:localhost,IP:127.0.0.1"

mkdir -p certs/postgres

echo "==> nginx certificate for: $*"
openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
    -keyout certs/server.key -out certs/server.crt \
    -subj "/C=IR/O=Afranet/CN=$1" \
    -addext "subjectAltName=$sans" \
    -addext "keyUsage=digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" 2>/dev/null

chmod 644 certs/server.crt
chmod 600 certs/server.key

echo "==> postgres certificate"
openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
    -keyout certs/postgres/server.key -out certs/postgres/server.crt \
    -subj "/C=IR/O=Afranet/CN=postgres" \
    -addext "subjectAltName=DNS:postgres" 2>/dev/null

# Postgres refuses to start if its key is readable by anyone else. The container
# runs as uid 70, so the file is handed to that user through the bind mount.
chmod 644 certs/postgres/server.crt
chown 70:70 certs/postgres/server.key 2>/dev/null || \
    echo "    note: run this script as root so the postgres key gets the right owner"
chmod 600 certs/postgres/server.key

echo
echo "Certificates written to ./certs — they are gitignored."
echo "Run ./deploy.sh; it switches to HTTPS on its own now that certs/ exists."
