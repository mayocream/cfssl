#!/bin/bash
# build_certs.sh -- regenerate ubiquity/testdata/ certificates
#
# Run from the repository root:
#   bash ubiquity/testdata/build_certs.sh
#
# Requires: openssl (3.x recommended)
#
# Certificate properties required by ubiquity_test.go:
#
#   rsa1024sha1  RSA-1024  SHA-1    expires 2034 (LATER than rsa2048/ecdsa256)
#   rsa2048sha2  RSA-2048  SHA-256  expires 2029 (same as ecdsa256)
#   rsa3072sha2  RSA-3072  SHA-256
#   rsa4096sha2  RSA-4096  SHA-256
#   ecdsa256sha2 ECDSA-256 SHA-256  expires 2029 (same as rsa2048)
#   ecdsa384sha2 ECDSA-384 SHA-384
#   ecdsa521sha2 ECDSA-521 SHA-512
#
# Keystore files (cert bytes must exactly match the certs above):
#   macrosoft.pem = rsa1024 + rsa2048 + ecdsa256   (3 certs, all platforms trust chain1/2/3)
#   godzilla.pem  = rsa1024 + rsa2048               (2 certs)
#   pineapple.pem = rsa1024                         (1 cert)
#
# Expiry ordering (required by TestChainExpiryUbiquity / TestCompareChainExpiry):
#   rsa1024 expires AFTER rsa2048 and ecdsa256
#   rsa2048 and ecdsa256 expire at the SAME time (both use -days 1096)

set -e

assert_signature_algorithm() {
    local cert="$1" expected="$2" details
    if ! details=$(openssl x509 -in "$cert" -noout -text); then
        echo "ERROR: unable to parse $cert" >&2
        return 1
    fi
    case "$details" in
        *"Signature Algorithm: $expected"*) ;;
        *)
            echo "ERROR: $cert was not signed with $expected" >&2
            return 1
            ;;
    esac
}

write_sha1_config() {
    cat >"$1" <<'CNFEOF'
[ req ]
distinguished_name = dn
[ dn ]
[ openssl_init ]
providers = provider_sect
alg_section = algorithm_sect
[ provider_sect ]
default = default_sect
legacy = legacy_sect
[ default_sect ]
activate = 1
[ legacy_sect ]
activate = 1
[ algorithm_sect ]
rh_allow_sha1_signatures = yes
CNFEOF
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTDATA="${SCRIPT_DIR}"
cd "$TESTDATA"

# Probe SHA-1 before replacing any managed fixture. Some systems reject SHA-1
# signing even when explicitly enabled in OpenSSL's configuration.
SHA1_PREFLIGHT_DIR=$(mktemp -d /tmp/cfssl_ubiquity_sha1_preflight_XXXXXX)
trap 'rm -rf -- "$SHA1_PREFLIGHT_DIR"' EXIT
write_sha1_config "$SHA1_PREFLIGHT_DIR/openssl.cnf"
openssl genrsa -out "$SHA1_PREFLIGHT_DIR/rsa1024.key" 1024 2>/dev/null
if ! OPENSSL_CONF="$SHA1_PREFLIGHT_DIR/openssl.cnf" openssl req -new -x509 \
        -key "$SHA1_PREFLIGHT_DIR/rsa1024.key" \
        -out "$SHA1_PREFLIGHT_DIR/rsa1024sha1.pem" \
        -days 1 -sha1 -subj "/CN=CFSSL SHA-1 preflight" 2>/dev/null; then
    echo "ERROR: SHA-1 signing is blocked by system policy; no fixtures were regenerated" >&2
    exit 1
fi
assert_signature_algorithm "$SHA1_PREFLIGHT_DIR/rsa1024sha1.pem" sha1

echo "=== Regenerating ubiquity/testdata certificates ==="
echo "    Output directory: $TESTDATA"
echo ""

# Detect whether openssl genrsa supports -traditional (OpenSSL 3.x)
if openssl genrsa -traditional -out /dev/null 2048 >/dev/null 2>&1; then
    RSA_TRADITIONAL="-traditional"
else
    RSA_TRADITIONAL=""
fi

# ── rsa1024sha1.pem ──────────────────────────────────────────────────────────
# RSA-1024, SHA-1 signed, expires 2034 (longer than rsa2048/ecdsa256).
# OpenSSL 3.x blocks SHA-1 by default; we use a temporary config to allow it.
echo "--- rsa1024sha1.pem (RSA-1024, SHA-1, expires 2034) ---"
openssl genrsa $RSA_TRADITIONAL -out rsa1024.key 1024 2>/dev/null

SHA1_CNF=$(mktemp /tmp/ubiq_sha1_XXXXXX.cnf)
SHA1_OUTPUT=$(mktemp /tmp/rsa1024_sha1_XXXXXX.pem)
write_sha1_config "$SHA1_CNF"

# Fail rather than substitute SHA-256 if system policy blocks SHA-1.
if ! OPENSSL_CONF="$SHA1_CNF" openssl req -new -x509 \
        -key rsa1024.key -out "$SHA1_OUTPUT" \
        -days 2920 -sha1 \
        -subj "/CN=rsa1024-sha1/O=CFSSL Ubiquity Test" 2>/dev/null; then
    rm -f "$SHA1_CNF" "$SHA1_OUTPUT"
    echo "ERROR: SHA-1 signing is blocked by system policy; rsa1024sha1.pem was not regenerated" >&2
    exit 1
fi
if ! assert_signature_algorithm "$SHA1_OUTPUT" sha1; then
    rm -f "$SHA1_CNF" "$SHA1_OUTPUT"
    exit 1
fi
mv "$SHA1_OUTPUT" rsa1024sha1.pem
rm -f "$SHA1_CNF"
echo "  rsa1024sha1.pem: SHA-1 signed"
openssl x509 -noout -enddate -in rsa1024sha1.pem | sed 's/^/  /'

# ── rsa2048sha2.pem ──────────────────────────────────────────────────────────
# RSA-2048, SHA-256.  Expires 2029.
# IMPORTANT: rsa2048 and ecdsa256 MUST share an identical notAfter timestamp.
# TestCompareChainExpiry asserts CompareChainExpiry([ecdsa256,rsa2048],[ecdsa256,rsa1024])==0.
# We generate rsa2048 first, extract its exact notAfter, then force ecdsa256 to
# use the same value via `openssl ca -enddate`.
echo ""
echo "--- rsa2048sha2.pem (RSA-2048, SHA-256, expires 2029) ---"
openssl genrsa $RSA_TRADITIONAL -out rsa2048.key 2048 2>/dev/null
openssl req -new -x509 -key rsa2048.key -out rsa2048sha2.pem \
    -days 1096 -sha256 \
    -subj "/CN=rsa2048-sha256/O=CFSSL Ubiquity Test" 2>/dev/null
openssl x509 -noout -enddate -in rsa2048sha2.pem | sed 's/^/  /'

# Extract rsa2048's notAfter in YYMMDDHHMMSSZ format for use with openssl ca -enddate
SHARED_ENDDATE=$(openssl x509 -noout -enddate -in rsa2048sha2.pem | cut -d= -f2)
SHARED_ENDDATE_FMT=$(python3 -c "
import datetime
dt = datetime.datetime.strptime('${SHARED_ENDDATE}'.strip(), '%b %d %H:%M:%S %Y %Z')
print(dt.strftime('%y%m%d%H%M%SZ'))
")

# ── rsa3072sha2.pem ──────────────────────────────────────────────────────────
echo ""
echo "--- rsa3072sha2.pem (RSA-3072, SHA-256) ---"
openssl genrsa $RSA_TRADITIONAL -out rsa3072.key 3072 2>/dev/null
openssl req -new -x509 -key rsa3072.key -out rsa3072sha2.pem \
    -days 3650 -sha256 \
    -subj "/CN=rsa3072-sha256/O=CFSSL Ubiquity Test" 2>/dev/null
openssl x509 -noout -enddate -in rsa3072sha2.pem | sed 's/^/  /'

# ── rsa4096sha2.pem ──────────────────────────────────────────────────────────
echo ""
echo "--- rsa4096sha2.pem (RSA-4096, SHA-256) ---"
openssl genrsa $RSA_TRADITIONAL -out rsa4096.key 4096 2>/dev/null
openssl req -new -x509 -key rsa4096.key -out rsa4096sha2.pem \
    -days 3650 -sha256 \
    -subj "/CN=rsa4096-sha256/O=CFSSL Ubiquity Test" 2>/dev/null
openssl x509 -noout -enddate -in rsa4096sha2.pem | sed 's/^/  /'

# ── ecdsa256sha2.pem ─────────────────────────────────────────────────────────
# ECDSA-256, SHA-256.  Must expire at the EXACT same second as rsa2048sha2.pem.
# Signed by rsa2048sha2 acting as a throwaway CA so we can force -enddate.
echo ""
echo "--- ecdsa256sha2.pem (ECDSA-256, SHA-256, same notAfter as rsa2048sha2) ---"
openssl ecparam -name prime256v1 -genkey -noout -out ecdsa256.key 2>/dev/null
openssl req -new -key ecdsa256.key -out ecdsa256.csr \
    -subj "/CN=ecdsa256-sha256/O=CFSSL Ubiquity Test" 2>/dev/null

TMPCA=$(mktemp -d /tmp/ubiq_ca_XXXXXX)
mkdir -p "$TMPCA/newcerts"
touch "$TMPCA/index.txt"
echo "01" > "$TMPCA/serial"
TMPCNF=$(mktemp /tmp/ubiq_cnf_XXXXXX.cnf)
cat > "$TMPCNF" << CAEOF
[ ca ]
default_ca = CA_default
[ CA_default ]
dir            = $TMPCA
certificate    = rsa2048sha2.pem
private_key    = rsa2048.key
new_certs_dir  = $TMPCA/newcerts
database       = $TMPCA/index.txt
serial         = $TMPCA/serial
default_md     = sha256
policy         = policy_anything
[ policy_anything ]
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional
CAEOF

openssl ca -batch -config "$TMPCNF" \
    -in ecdsa256.csr -out ecdsa256sha2.pem \
    -enddate "$SHARED_ENDDATE_FMT" -notext 2>/dev/null

rm -rf "$TMPCA" "$TMPCNF" ecdsa256.csr
openssl x509 -noout -enddate -in ecdsa256sha2.pem | sed 's/^/  /'
echo "  (must match rsa2048sha2 notAfter: ${SHARED_ENDDATE})"

# ── ecdsa384sha2.pem ─────────────────────────────────────────────────────────
echo ""
echo "--- ecdsa384sha2.pem (ECDSA-384, SHA-384) ---"
openssl ecparam -name secp384r1 -genkey -noout -out ecdsa384.key 2>/dev/null
openssl req -new -x509 -key ecdsa384.key -out ecdsa384sha2.pem \
    -days 3650 -sha384 \
    -subj "/CN=ecdsa384-sha384/O=CFSSL Ubiquity Test" 2>/dev/null
openssl x509 -noout -enddate -in ecdsa384sha2.pem | sed 's/^/  /'

# ── ecdsa521sha2.pem ─────────────────────────────────────────────────────────
echo ""
echo "--- ecdsa521sha2.pem (ECDSA-521, SHA-512) ---"
openssl ecparam -name secp521r1 -genkey -noout -out ecdsa521.key 2>/dev/null
openssl req -new -x509 -key ecdsa521.key -out ecdsa521sha2.pem \
    -days 3650 -sha512 \
    -subj "/CN=ecdsa521-sha512/O=CFSSL Ubiquity Test" 2>/dev/null
openssl x509 -noout -enddate -in ecdsa521sha2.pem | sed 's/^/  /'

# ── Keystore files ────────────────────────────────────────────────────────────
# These MUST be built from the certs generated above so the byte-comparison
# inside CrossPlatformUbiquity matches correctly.
echo ""
echo "--- Keystore PEM bundles ---"

# macrosoft.pem: all three certs (rsa1024 + rsa2048 + ecdsa256)
# Platforms with this store trust chain1, chain2, and chain3 in the test.
cat rsa1024sha1.pem rsa2048sha2.pem ecdsa256sha2.pem > macrosoft.pem
echo "  macrosoft.pem: $(grep -c 'BEGIN CERT' macrosoft.pem) certs (rsa1024 + rsa2048 + ecdsa256)"

# godzilla.pem: two certs (rsa1024 + rsa2048)
cat rsa1024sha1.pem rsa2048sha2.pem > godzilla.pem
echo "  godzilla.pem:  $(grep -c 'BEGIN CERT' godzilla.pem) certs (rsa1024 + rsa2048)"

# pineapple.pem: one cert (rsa1024 only)
cat rsa1024sha1.pem > pineapple.pem
echo "  pineapple.pem: $(grep -c 'BEGIN CERT' pineapple.pem) certs (rsa1024)"

# ── Cleanup ───────────────────────────────────────────────────────────────────
rm -f rsa1024.key rsa2048.key rsa3072.key rsa4096.key \
      ecdsa256.key ecdsa384.key ecdsa521.key

echo ""
echo "=== Done. ubiquity/testdata regenerated in: $TESTDATA ==="
