#!/usr/bin/env bash
set -euo pipefail

OUT="${1:-certs}"
HOST_IP="${HOST_IP:-}"

mkdir -p "$OUT"
chmod 700 "$OUT"
cd "$OUT"

gen_key() {
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null
	chmod 600 "$1"
}

SAN="DNS:localhost,IP:127.0.0.1"
if [ -n "$HOST_IP" ] && [ "$HOST_IP" != "127.0.0.1" ]; then
	SAN="$SAN,IP:$HOST_IP"
fi
if [ -n "${EXTRA_SAN:-}" ]; then
	SAN="$SAN,$EXTRA_SAN"
fi

gen_key ca.key
openssl req -x509 -new -key ca.key -sha256 -days 3650 \
	-subj "/CN=mtls-shield-demo-ca" \
	-addext "basicConstraints=critical,CA:TRUE" \
	-addext "keyUsage=critical,keyCertSign,cRLSign" \
	-out ca.crt

gen_key server.key
openssl req -new -key server.key \
	-subj "/CN=mtls-shield-server" -out server.csr
cat > server.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=$SAN
EOF
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
	-CAcreateserial -days 825 -sha256 -extfile server.ext \
	-out server.crt

gen_key client.key
cat > client.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EOF
openssl req -new -key client.key -subj "/CN=alice" -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
	-CAcreateserial -days 825 -sha256 -extfile client.ext \
	-out client.crt

gen_key rogue-ca.key
openssl req -x509 -new -key rogue-ca.key -sha256 -days 3650 \
	-subj "/CN=rogue-demo-ca" \
	-addext "basicConstraints=critical,CA:TRUE" \
	-addext "keyUsage=critical,keyCertSign,cRLSign" \
	-out rogue-ca.crt

gen_key rogue-client.key
openssl req -new -key rogue-client.key \
	-subj "/CN=mallory" -out rogue-client.csr
openssl x509 -req -in rogue-client.csr -CA rogue-ca.crt \
	-CAkey rogue-ca.key -CAcreateserial -days 825 -sha256 \
	-extfile client.ext -out rogue-client.crt

rm -f server.csr client.csr rogue-client.csr server.ext client.ext

echo "certificates written to $PWD"
echo "  server SAN: $SAN"
