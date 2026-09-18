#!/bin/bash
# build_certs.sh -- regenerate api/testdata/ certificates
#
# Run from the repository root:
#   bash api/testdata/build_certs.sh
#
# Requires: openssl (3.x recommended, also works with LibreSSL)
#
# Files regenerated:
#   ca-bundle.pem   root CA (CFSSL_TEST_CA, RSA-2048, SHA-256, 10yr)
#   ca_key.pem      private key for ca-bundle.pem / ca.pem
#   int-bundle.pem  intermediate CA signed by ca-bundle.pem (RSA-2048, SHA-256, 10yr)
#   leaf.pem        leaf cert signed by int-bundle (RSA-2048, SHA-256, 10yr)
#   leaf.key        private key for leaf.pem
#   leaf.badkey     a valid RSA-2048 key that does NOT match leaf.pem (for error-path tests)
#   ca.pem          secondary root (CFSSL TEST Root CA, RSA-2048, SHA-256, 10yr)
#   cert.pem        self-signed cert (Acme Co / 127.0.0.1, RSA-2048, SHA-256, 10yr)
#
# Files left untouched:
#   ca2.pem         (ECDSA-SHA256 root, used by separate ca2 tests)
#   ca2-key.pem     (private key for ca2.pem)
#   csr.pem         (CSR, not a certificate)
#   broken_csr.pem  (intentionally malformed, must stay broken)
#   broken.pem      (intentionally malformed, must stay broken)
#
# Chain produced:
#   ca-bundle.pem  (root, self-signed)
#     └─ int-bundle.pem  (intermediate, pathlen:1)
#          └─ leaf.pem   (leaf, SAN=cfssl-leaf.com)

set -e

SERIAL_DIR=$(mktemp -d /tmp/api_serial_XXXXXX)
trap 'rm -rf "$SERIAL_DIR"' EXIT

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTDATA="${SCRIPT_DIR}"
cd "$TESTDATA"
rm -f ca-bundle.srl int-bundle.srl inter.srl

echo "=== Regenerating api/testdata certificates ==="
echo "    Output directory: $TESTDATA"
echo ""

# Detect whether openssl genrsa supports -traditional (OpenSSL 3.x)
if openssl genrsa -traditional -out /dev/null 2048 >/dev/null 2>&1; then
    RSA_TRADITIONAL="-traditional"
else
    RSA_TRADITIONAL=""
fi

# ── 1. ca-bundle.pem + shared ca_key.pem ────────────────────────────────────
# Root CA for the main chain. DN preserved from original file.
# ca_key.pem is reused as the key for ca.pem (secondary root) below.
echo "--- ca-bundle.pem (root CA: CFSSL_TEST_CA, RSA-2048, SHA-256) ---"
openssl genrsa $RSA_TRADITIONAL -out ca_key.pem 2048 2>/dev/null

openssl req -new -x509 -key ca_key.pem -out ca-bundle.pem \
    -days 3650 -sha256 \
    -subj "/C=US/ST=California/L=San Francisco/O=CloudFlare/OU=DEV_TESTING/CN=CFSSL_TEST_CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" 2>/dev/null
openssl x509 -noout -subject -enddate -in ca-bundle.pem | sed 's/^/  /'

# ── 2. int-bundle.pem ───────────────────────────────────────────────────────
# Intermediate CA signed by ca-bundle.pem. DN preserved from original file.
echo ""
echo "--- int-bundle.pem (intermediate: cloudflare-inter.com, RSA-2048, SHA-256) ---"
openssl genrsa $RSA_TRADITIONAL -out inter.key 2048 2>/dev/null

INTER_EXT=$(mktemp /tmp/api_inter_XXXXXX.ext)
cat > "$INTER_EXT" << 'EXTEOF'
basicConstraints=critical,CA:TRUE,pathlen:1
keyUsage=critical,keyCertSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EXTEOF

openssl req -new -key inter.key -out inter.csr \
    -subj "/C=US/ST=California/L=San Francisco/O=CloudFlare/OU=Systems Engineering/CN=cloudflare-inter.com" \
    2>/dev/null

openssl x509 -req -in inter.csr -CA ca-bundle.pem -CAkey ca_key.pem \
    -CAserial "$SERIAL_DIR/root.srl" -CAcreateserial -out int-bundle.pem \
    -days 3650 -sha256 -extfile "$INTER_EXT" 2>/dev/null

rm -f "$INTER_EXT" inter.csr
openssl x509 -noout -subject -issuer -enddate -in int-bundle.pem | sed 's/^/  /'

# ── 3. leaf.pem + leaf.key ──────────────────────────────────────────────────
# Leaf cert signed by int-bundle.pem. DN and SAN preserved from original file.
echo ""
echo "--- leaf.pem (leaf: cloudflare-leaf.com, RSA-2048, SHA-256, SAN=cfssl-leaf.com) ---"
openssl genrsa $RSA_TRADITIONAL -out leaf.key 2048 2>/dev/null

LEAF_EXT=$(mktemp /tmp/api_leaf_XXXXXX.ext)
cat > "$LEAF_EXT" << 'EXTEOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
subjectAltName=DNS:cfssl-leaf.com
EXTEOF

openssl req -new -key leaf.key -out leaf.csr \
    -subj "/C=US/ST=California/L=San Francisco/O=CloudFlare/OU=Systems Engineering/CN=cloudflare-leaf.com" \
    2>/dev/null

openssl x509 -req -in leaf.csr -CA int-bundle.pem -CAkey inter.key \
    -CAserial "$SERIAL_DIR/intermediate.srl" -CAcreateserial -out leaf.pem \
    -days 3650 -sha256 -extfile "$LEAF_EXT" 2>/dev/null

rm -f "$LEAF_EXT" leaf.csr

openssl x509 -noout -subject -issuer -enddate -in leaf.pem | sed 's/^/  /'

# ── 4. leaf.badkey ──────────────────────────────────────────────────────────
# A valid RSA private key that intentionally does NOT match leaf.pem.
# Used by tests that expect a key-mismatch error.
echo ""
echo "--- leaf.badkey (RSA-2048 key, intentionally mismatched with leaf.pem) ---"
openssl genrsa $RSA_TRADITIONAL -out leaf.badkey 2048 2>/dev/null
echo "  generated (does not match leaf.pem)"

# ── 5. ca.pem (secondary root) ──────────────────────────────────────────────
# Used by api tests that reference a separate root independent of the main chain.
# DN preserved from original: CFSSL TEST Root CA with emailAddress.
# Original had pathlen:0; preserved here.
echo ""
echo "--- ca.pem (secondary root: CFSSL TEST Root CA, RSA-2048, SHA-256) ---"
openssl req -new -x509 -key ca_key.pem -out ca.pem \
    -days 3650 -sha256 \
    -subj "/C=US/ST=California/L=San Francisco/O=CFSSL TEST/CN=CFSSL TEST Root CA/emailAddress=test@test.local" \
    -addext "basicConstraints=CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" 2>/dev/null
openssl x509 -noout -subject -enddate -in ca.pem | sed 's/^/  /'

# ── 6. cert.pem ─────────────────────────────────────────────────────────────
# Self-signed cert used by api tests as a generic TLS/test certificate.
# Original DN: O=Acme Co, CN=127.0.0.1. Regenerate as SHA-256, RSA-2048.
echo ""
echo "--- cert.pem (self-signed: Acme Co / 127.0.0.1, RSA-2048, SHA-256) ---"
CERT_KEY=$(mktemp /tmp/api_certkey_XXXXXX.pem)
openssl genrsa $RSA_TRADITIONAL -out "$CERT_KEY" 2048 2>/dev/null
openssl req -new -x509 -key "$CERT_KEY" -out cert.pem \
    -days 3650 -sha256 \
    -subj "/O=Acme Co/CN=127.0.0.1" \
    -addext "basicConstraints=CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" 2>/dev/null
rm -f "$CERT_KEY"
openssl x509 -noout -subject -enddate -in cert.pem | sed 's/^/  /'

# ── 7. Cleanup intermediate files ───────────────────────────────────────────
rm -f inter.key

# ── 8. Verify the chain ─────────────────────────────────────────────────────
echo ""
echo "--- Chain verification ---"
if openssl verify -CAfile ca-bundle.pem -untrusted int-bundle.pem leaf.pem; then
    echo "  chain OK: leaf.pem -> int-bundle.pem -> ca-bundle.pem"
else
    echo "  ERROR: chain verification failed!" >&2
    exit 1
fi

echo ""
echo "=== Done. api/testdata regenerated in: $TESTDATA ==="
