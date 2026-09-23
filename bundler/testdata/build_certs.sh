#!/usr/bin/env bash
# build_certs.sh — Regenerate cfssl bundler/testdata certificates.
#
# Run from the repository root:
#   bash bundler/testdata/build_certs.sh
#
# Requirements: openssl (3.x recommended). cfssl + cfssljson are optional;
# when absent, the script generates the same hierarchy with OpenSSL.
# All existing files in bundler/testdata/ that this script touches are
# overwritten in-place; files it does not manage (nss.pem, osx.pem,
# froyo.pem, etc.) are left alone.
#
# Certificate hierarchy produced
# ───────────────────────────────
#   ca.pem  (RSA-2048, self-signed, SHA-256, 20-year)
#     └─ inter-L1.pem          (RSA-4096, pathlen:1, SHA-256, 10-year)
#     │    └─ inter-L2.pem     (ECDSA-384, pathlen:0, SHA-512, 10-year)
#     │         ├─ cfssl-leaf-ecdsa256.pem
#     │         ├─ cfssl-leaf-ecdsa384.pem
#     │         ├─ cfssl-leaf-ecdsa521.pem
#     │         ├─ cfssl-leaf-rsa2048.pem
#     │         ├─ cfssl-leaf-rsa3072.pem
#     │         └─ cfssl-leaf-rsa4096.pem
#     │              └─ cfssl-leaflet-rsa4096.pem  (pathlen:0 exceeded → error)
#     │
#     └─ inter-L2-direct.pem  (inter-L2 CSR signed directly by ca, pathlen:0)
#     └─ inter-L1-expired.pem (inter-L1 CSR signed with -1 second validity)
#     └─ inter-L1-sha1.pem    (inter-L1 CSR signed with SHA-1 — kept for SHA1
#                               deprecation tests; sha1 signing is intentional)
#
# Composite files
#   intermediates.crt  = inter-L1.pem + inter-L2.pem
#   partial-bundle.pem = cfssl-leaf-ecdsa256.pem + inter-L2.pem
#   reverse-partial-bundle.pem = inter-L2.pem + cfssl-leaf-ecdsa256.pem
#   bad-bundle.pem     = cfssl-leaf-ecdsa256.pem + cfssl-leaf-ecdsa384.pem
#
# client-auth/ sub-hierarchy
#   client-auth/root.pem → client-auth/int.pem → leaf-server.pem
#                                               → leaf-client.pem

set -euo pipefail

TESTDATA="$(cd "$(dirname "$0")" && pwd)"
cd "$TESTDATA"

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || { echo "ERROR: '$1' not found in PATH"; exit 1; }
}
require_cmd openssl

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

assert_pathlen_zero() {
    local cert="$1" details
    if ! details=$(openssl x509 -in "$cert" -noout -text); then
        echo "ERROR: unable to parse $cert" >&2
        return 1
    fi
    case "$details" in
        *"CA:TRUE, pathlen:0"*|*"CA:TRUE, pathlen: 0"*) ;;
        *)
            echo "ERROR: $cert is missing the CA pathlen:0 constraint" >&2
            return 1
            ;;
    esac
}

write_sha1_config() {
    cat >"$1" <<'CONFEOF'
openssl_conf = openssl_init

[openssl_init]
alg_section = evp_properties

[evp_properties]
rh_allow_sha1_signatures = yes
default_properties = ""
CONFEOF
}

# Probe SHA-1 before replacing any managed fixture. Some systems reject SHA-1
# signing even when explicitly enabled in OpenSSL's configuration.
SHA1_PREFLIGHT_DIR=$(mktemp -d /tmp/cfssl_sha1_preflight_XXXXXX)
trap 'rm -rf -- "$SHA1_PREFLIGHT_DIR"' EXIT
write_sha1_config "$SHA1_PREFLIGHT_DIR/openssl.cnf"
openssl genrsa -out "$SHA1_PREFLIGHT_DIR/ca.key" 2048 2>/dev/null
openssl req -new -x509 -key "$SHA1_PREFLIGHT_DIR/ca.key" \
    -out "$SHA1_PREFLIGHT_DIR/ca.pem" -days 1 -sha256 \
    -subj "/CN=CFSSL SHA-1 preflight CA" 2>/dev/null
openssl genrsa -out "$SHA1_PREFLIGHT_DIR/intermediate.key" 2048 2>/dev/null
openssl req -new -key "$SHA1_PREFLIGHT_DIR/intermediate.key" \
    -out "$SHA1_PREFLIGHT_DIR/intermediate.csr" \
    -subj "/CN=CFSSL SHA-1 preflight intermediate" 2>/dev/null
if ! OPENSSL_CONF="$SHA1_PREFLIGHT_DIR/openssl.cnf" openssl x509 -req \
        -in "$SHA1_PREFLIGHT_DIR/intermediate.csr" \
        -CA "$SHA1_PREFLIGHT_DIR/ca.pem" -CAkey "$SHA1_PREFLIGHT_DIR/ca.key" \
        -CAserial "$SHA1_PREFLIGHT_DIR/ca.srl" -CAcreateserial \
        -out "$SHA1_PREFLIGHT_DIR/intermediate.pem" -days 1 -sha1 2>/dev/null; then
    echo "ERROR: SHA-1 signing is blocked by system policy; no fixtures were regenerated" >&2
    exit 1
fi
assert_signature_algorithm "$SHA1_PREFLIGHT_DIR/intermediate.pem" sha1

# OpenSSL 3.x changed the default RSA key output format from traditional
# PKCS#1 (BEGIN RSA PRIVATE KEY) to PKCS#8 (BEGIN PRIVATE KEY).
# cfssl serialises RSA keys back in PKCS#1 format when marshalling a Bundle
# to JSON, so TestBundleWithRSAKeyMarshalJSON fails if on-disk files are PKCS#8.
# The -traditional flag preserves PKCS#1; guard against older openssl builds
# that don't support it.
RSA_TRADITIONAL="-traditional"
openssl genrsa $RSA_TRADITIONAL -out /dev/null 512 2>/dev/null || RSA_TRADITIONAL=""

write_ca_config() {
    cat >ca-config.json <<'EOF'
{
  "signing": {
    "default": { "expiry": "87600h" },
    "profiles": {
      "intermediate": {
        "usages": ["cert sign","crl sign"],
        "expiry": "87600h",
        "ca_constraint": {"is_ca": true, "max_path_len": 1}
      },
      "intermediate-l2": {
        "usages": ["cert sign","crl sign"],
        "expiry": "87600h",
        "ca_constraint": {"is_ca": true, "max_path_len": 0, "max_path_len_zero": true}
      },
      "leaf": {
        "usages": ["signing","key encipherment","server auth"],
        "expiry": "87600h"
      },
      "leaflet": {
        "usages": ["signing","key encipherment","server auth"],
        "expiry": "87600h"
      },
      "client": {
        "usages": ["signing","key encipherment","client auth"],
        "expiry": "87600h"
      }
    }
  }
}
EOF
}

# ─── detect whether cfssl is available ───────────────────────────────────────
USE_CFSSL=0
if command -v cfssl >/dev/null 2>&1 && command -v cfssljson >/dev/null 2>&1; then
    USE_CFSSL=1
fi

# ─── openssl-only helpers (used when cfssl is absent, and for SHA-1 certs) ───

# Generate a self-signed RSA CA with openssl
openssl_selfsign_rsa_ca() {
    local key="$1" cert="$2" cn="$3" days="$4"
    openssl genrsa $RSA_TRADITIONAL -out "$key" 2048 2>/dev/null
    openssl req -new -x509 -key "$key" -out "$cert" \
        -days "$days" -sha256 \
        -subj "/CN=$cn/O=CFSSL Test/OU=Test" \
        -extensions v3_ca \
        -addext "basicConstraints=critical,CA:TRUE"
}

# Sign a CSR with openssl, producing a CA cert (pathlen controlled by ext file)
openssl_sign_ca() {
    local ca_cert="$1" ca_key="$2" csr="$3" out_cert="$4"
    local days="$5" sha="$6" pathlen="$7"
    local extfile
    extfile=$(mktemp /tmp/ext_XXXXXX.cnf)
    cat >"$extfile" <<EXTEOF
[ ext ]
basicConstraints = critical,CA:TRUE,pathlen:$pathlen
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EXTEOF
    openssl x509 -req -in "$csr" -CA "$ca_cert" -CAkey "$ca_key" \
        -CAcreateserial -out "$out_cert" \
        -days "$days" -"$sha" \
        -extfile "$extfile" -extensions ext 2>/dev/null
    rm -f "$extfile"
}

# Sign a leaf CSR with openssl
openssl_sign_leaf() {
    local ca_cert="$1" ca_key="$2" csr="$3" out_cert="$4"
    local days="$5"
    local extfile
    extfile=$(mktemp /tmp/ext_XXXXXX.cnf)
    cat >"$extfile" <<EXTEOF
[ ext ]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EXTEOF
    openssl x509 -req -in "$csr" -CA "$ca_cert" -CAkey "$ca_key" \
        -CAcreateserial -out "$out_cert" \
        -days "$days" -sha256 \
        -extfile "$extfile" -extensions ext 2>/dev/null
    rm -f "$extfile"
}

echo "=== Generating cfssl bundler testdata ==="
echo "Working directory: $TESTDATA"
echo "Using cfssl: $USE_CFSSL"

# ══════════════════════════════════════════════════════════════════════════════
# 1. Root CA  (ca.pem / ca.key)
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "--- 1. Root CA ---"

if [ $USE_CFSSL -eq 1 ]; then
    cat >ca-csr.json <<'EOF'
{
  "CN": "CFSSL TEST CA",
  "key": { "algo": "rsa", "size": 2048 },
  "names": [{"O":"CFSSL Test","OU":"Test"}],
  "ca": { "expiry": "175200h" }
}
EOF
    cfssl gencert -initca ca-csr.json | cfssljson -bare ca
    mv ca-key.pem ca.key
    rm -f ca.csr ca-csr.json
else
    openssl_selfsign_rsa_ca ca.key ca.pem "CFSSL TEST CA" 7300
fi

echo "  ca.pem and ca.key written"

# ══════════════════════════════════════════════════════════════════════════════
# 2. inter-L1  (RSA-4096, pathlen:1)
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "--- 2. inter-L1 (RSA-4096, pathlen:1) ---"

if [ $USE_CFSSL -eq 1 ]; then
    write_ca_config
    cat >inter-L1-csr.json <<'EOF'
{
  "CN": "CFSSL TEST Intermediate L1",
  "hosts": ["cfssl-inter-l1.test"],
  "key": { "algo": "rsa", "size": 4096 },
  "names": [{"O":"CFSSL Test","OU":"Test"}]
}
EOF
    cfssl gencert -ca ca.pem -ca-key ca.key \
        -config ca-config.json -profile intermediate \
        inter-L1-csr.json | cfssljson -bare inter-L1
    mv inter-L1-key.pem inter-L1.key
    rm -f inter-L1-csr.json
else
    # Generate key + CSR
    openssl genrsa $RSA_TRADITIONAL -out inter-L1.key 4096 2>/dev/null
    openssl req -new -key inter-L1.key -out inter-L1.csr \
        -subj "/CN=CFSSL TEST Intermediate L1/O=CFSSL Test/OU=Test"
    openssl_sign_ca ca.pem ca.key inter-L1.csr inter-L1.pem 3650 sha256 1
fi

echo "  inter-L1.pem, inter-L1.key, inter-L1.csr written"

# ══════════════════════════════════════════════════════════════════════════════
# 3. inter-L1-expired  (same CSR as inter-L1, but expired)
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "--- 3. inter-L1-expired ---"

# `openssl x509 -req` does not support custom start/end dates in OpenSSL 3.x.
# We use `openssl ca` which accepts -startdate / -enddate (YYMMDDHHMMSSZ).
# This requires a minimal CA database layout.

CADB=$(mktemp -d /tmp/cadb_XXXXXX)
mkdir -p "$CADB/newcerts"
touch "$CADB/index.txt"
echo "1000" > "$CADB/serial"

CACONF=$(mktemp /tmp/ca_XXXXXX.cnf)
cat >"$CACONF" <<CAEOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir            = $CADB
new_certs_dir  = \$dir/newcerts
database       = \$dir/index.txt
serial         = \$dir/serial
certificate    = ca.pem
private_key    = ca.key
default_md     = sha256
policy         = policy_loose
copy_extensions = copy

[ policy_loose ]
countryName            = optional
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[ v3_inter ]
basicConstraints = critical,CA:TRUE,pathlen:1
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
CAEOF

openssl ca -batch -config "$CACONF" \
    -in inter-L1.csr \
    -out inter-L1-expired.pem \
    -startdate 100101000000Z \
    -enddate   100101000001Z \
    -extensions v3_inter \
    -notext 2>/dev/null

rm -rf "$CADB" "$CACONF"

echo "  inter-L1-expired.pem written"

# ══════════════════════════════════════════════════════════════════════════════
# 4. inter-L1-sha1  (SHA-1 signed — intentional for deprecation tests)
#    openssl 3.x refuses SHA-1 by default; we force it via an OPENSSL_CONF
#    override. If system policy still blocks SHA-1, regeneration fails rather
#    than writing a certificate with different semantics under this filename.
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "--- 4. inter-L1-sha1 (SHA-1 signed, intentional) ---"

extfile_sha1=$(mktemp /tmp/ext_XXXXXX.cnf)
cat >"$extfile_sha1" <<EXTEOF
[ ext ]
basicConstraints = critical,CA:TRUE,pathlen:1
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EXTEOF

# Try with a temporary openssl.cnf that re-enables SHA-1 signing
TMPCONF=$(mktemp /tmp/openssl_XXXXXX.cnf)
SHA1_OUTPUT=$(mktemp /tmp/inter_L1_sha1_XXXXXX.pem)
write_sha1_config "$TMPCONF"

if ! OPENSSL_CONF="$TMPCONF" openssl x509 -req -in inter-L1.csr \
        -CA ca.pem -CAkey ca.key -CAcreateserial \
        -out "$SHA1_OUTPUT" \
        -days 3650 -sha1 \
        -extfile "$extfile_sha1" -extensions ext 2>/dev/null; then
    rm -f "$extfile_sha1" "$TMPCONF" "$SHA1_OUTPUT"
    echo "ERROR: SHA-1 signing is blocked by system policy; inter-L1-sha1.pem was not regenerated" >&2
    exit 1
fi
if ! assert_signature_algorithm "$SHA1_OUTPUT" sha1; then
    rm -f "$extfile_sha1" "$TMPCONF" "$SHA1_OUTPUT"
    exit 1
fi
mv "$SHA1_OUTPUT" inter-L1-sha1.pem
rm -f "$extfile_sha1" "$TMPCONF"
echo "  inter-L1-sha1.pem written (SHA-1)"

# ══════════════════════════════════════════════════════════════════════════════
# 5. inter-L2  (ECDSA-384, pathlen:0, signed by inter-L1)
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "--- 5. inter-L2 (ECDSA-384, pathlen:0) ---"

if [ $USE_CFSSL -eq 1 ]; then
    cat >inter-L2-csr.json <<'EOF'
{
  "CN": "CFSSL TEST Intermediate L2",
  "hosts": ["cfssl-inter-l2.test"],
  "key": { "algo": "ecdsa", "size": 384 },
  "names": [{"O":"CFSSL Test","OU":"Test"}]
}
EOF
    cfssl gencert -ca inter-L1.pem -ca-key inter-L1.key \
        -config ca-config.json -profile intermediate-l2 \
        inter-L2-csr.json | cfssljson -bare inter-L2
    mv inter-L2-key.pem inter-L2.key
    rm -f inter-L2-csr.json
else
    openssl ecparam -name secp384r1 -genkey -noout -out inter-L2.key 2>/dev/null
    openssl req -new -key inter-L2.key -out inter-L2.csr \
        -subj "/CN=CFSSL TEST Intermediate L2/O=CFSSL Test/OU=Test"
    openssl_sign_ca inter-L1.pem inter-L1.key inter-L2.csr inter-L2.pem 3650 sha512 0
fi

assert_pathlen_zero inter-L2.pem
assert_signature_algorithm inter-L2.pem sha512

echo "  inter-L2.pem, inter-L2.key, inter-L2.csr written"

# ══════════════════════════════════════════════════════════════════════════════
# 6. inter-L2-direct  (inter-L2 CSR signed directly by root CA)
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "--- 6. inter-L2-direct (inter-L2 CSR signed by root) ---"

openssl_sign_ca ca.pem ca.key inter-L2.csr inter-L2-direct.pem 3650 sha256 0
echo "  inter-L2-direct.pem written"

# ══════════════════════════════════════════════════════════════════════════════
# 7. Leaf certificates  (signed by inter-L2)
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "--- 7. Leaf certificates ---"

gen_leaf_ecdsa() {
    local curve="$1" bits="$2" name="$3"
    openssl ecparam -name "$curve" -genkey -noout \
        -out "cfssl-leaf-${name}.key" 2>/dev/null
    openssl req -new -key "cfssl-leaf-${name}.key" \
        -out "cfssl-leaf-${name}.csr" \
        -subj "/CN=cfssl-leaf-${name}.test/O=CFSSL Test/OU=Test"
    openssl_sign_leaf inter-L2.pem inter-L2.key \
        "cfssl-leaf-${name}.csr" "cfssl-leaf-${name}.pem" 3650
    echo "  cfssl-leaf-${name}.pem written"
}

gen_leaf_rsa() {
    local bits="$1" name="$2"
    openssl genrsa $RSA_TRADITIONAL -out "cfssl-leaf-${name}.key" "$bits" 2>/dev/null
    openssl req -new -key "cfssl-leaf-${name}.key" \
        -out "cfssl-leaf-${name}.csr" \
        -subj "/CN=cfssl-leaf-${name}.test/O=CFSSL Test/OU=Test"
    openssl_sign_leaf inter-L2.pem inter-L2.key \
        "cfssl-leaf-${name}.csr" "cfssl-leaf-${name}.pem" 3650
    echo "  cfssl-leaf-${name}.pem written"
}

gen_leaf_ecdsa prime256v1  256 ecdsa256
gen_leaf_ecdsa secp384r1   384 ecdsa384
gen_leaf_ecdsa secp521r1   521 ecdsa521
gen_leaf_rsa   2048            rsa2048
gen_leaf_rsa   3072            rsa3072

# cfssl-leaf-rsa4096 is intentionally a sub-CA (CA:TRUE, pathlen:0) signed by inter-L2.
# This means the chain root→inter-L1(pathlen:1)→inter-L2(pathlen:0)→leafRSA4096(pathlen:0)
# is valid when leafRSA4096 is the target. Appending cfssl-leaflet-rsa4096 makes
# leafRSA4096 an intermediate and violates inter-L2's pathlen:0 constraint.
# Tests that bundle leafRSA4096 as the submitted cert still get chain length 3
# (leafRSA4096 + inter-L2 + inter-L1) which is correct.
openssl genrsa $RSA_TRADITIONAL -out cfssl-leaf-rsa4096.key 4096 2>/dev/null
openssl req -new -key cfssl-leaf-rsa4096.key \
    -out cfssl-leaf-rsa4096.csr \
    -subj "/CN=cfssl-leaf-rsa4096.test/O=CFSSL Test/OU=Test"
openssl_sign_ca inter-L2.pem inter-L2.key cfssl-leaf-rsa4096.csr cfssl-leaf-rsa4096.pem 3650 sha256 0
echo "  cfssl-leaf-rsa4096.pem written (CA:TRUE, pathlen:0)"

# ══════════════════════════════════════════════════════════════════════════════
# 8. cfssl-leaflet-rsa4096
#    A true leaf signed by cfssl-leaf-rsa4096 (which is itself a sub-CA).
#    Without leafRSA4096 in the pool → error 1220 UnknownAuthority (signer unknown).
#    With leafRSA4096 added as extraIntermediates → chain is found but inter-L2's
#    pathlen:0 is violated by having leafRSA4096 below it →
#    error 1213 TooManyIntermediates.
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "--- 8. cfssl-leaflet-rsa4096 (pathlen violation chain) ---"

openssl genrsa $RSA_TRADITIONAL -out cfssl-leaflet-rsa4096.key 4096 2>/dev/null
openssl req -new -key cfssl-leaflet-rsa4096.key \
    -out cfssl-leaflet-rsa4096.csr \
    -subj "/CN=cfssl-leaflet-rsa4096.test/O=CFSSL Test/OU=Test"

extfile_leaflet=$(mktemp /tmp/ext_XXXXXX.cnf)
cat >"$extfile_leaflet" <<EXTEOF
[ ext ]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EXTEOF
openssl x509 -req -in cfssl-leaflet-rsa4096.csr \
    -CA cfssl-leaf-rsa4096.pem -CAkey cfssl-leaf-rsa4096.key \
    -CAcreateserial -out cfssl-leaflet-rsa4096.pem \
    -days 3650 -sha256 \
    -extfile "$extfile_leaflet" -extensions ext 2>/dev/null
rm -f "$extfile_leaflet" cfssl-leaflet-rsa4096.csr cfssl-leaflet-rsa4096.key

echo "  cfssl-leaflet-rsa4096.pem written"

# ══════════════════════════════════════════════════════════════════════════════
# 9. Composite / bundle files
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "--- 9. Composite files ---"

# intermediates.crt = inter-L1 + inter-L2
cat inter-L1.pem inter-L2.pem > intermediates.crt
echo "  intermediates.crt written"

# partial-bundle.pem = leaf-ecdsa256 + inter-L2 (partial chain, correct order)
cat cfssl-leaf-ecdsa256.pem inter-L2.pem > partial-bundle.pem
echo "  partial-bundle.pem written"

# reverse-partial-bundle.pem = inter-L2 + leaf-ecdsa256 (reversed)
cat inter-L2.pem cfssl-leaf-ecdsa256.pem > reverse-partial-bundle.pem
echo "  reverse-partial-bundle.pem written"

# bad-bundle.pem = leaf-ecdsa256 + leaf-ecdsa384 (non-verifying)
cat cfssl-leaf-ecdsa256.pem cfssl-leaf-ecdsa384.pem > bad-bundle.pem
echo "  bad-bundle.pem written"

# ══════════════════════════════════════════════════════════════════════════════
# 10. DSA test certs  (DSA is unsupported by cfssl — kept to test error paths)
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "--- 10. DSA certificates (unsupported key type test) ---"

# Only generate if openssl supports DSA (may be absent in some builds)
if openssl dsaparam -noout 2048 2>/dev/null | openssl gendsa -out dsa2048.key /dev/stdin 2>/dev/null; then
    echo "  (DSA via pipe not reliable, trying explicit approach)"
fi

# More reliable approach
if openssl dsaparam -out dsa_param.pem 2048 2>/dev/null && \
   openssl gendsa -out dsa2048.key dsa_param.pem 2>/dev/null; then
    openssl req -new -x509 -key dsa2048.key -out dsa2048.pem \
        -days 3650 -subj "/CN=dsa2048.test/O=CFSSL Test" 2>/dev/null
    rm -f dsa_param.pem
    echo "  dsa2048.pem and dsa2048.key written"
else
    echo "  WARNING: DSA not available in this openssl build."
    echo "  dsa2048.pem / dsa2048.key not regenerated — keeping existing files."
    rm -f dsa_param.pem
fi

# ══════════════════════════════════════════════════════════════════════════════
# 11. client-auth sub-hierarchy
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "--- 11. client-auth hierarchy ---"

mkdir -p client-auth

# Root
openssl genrsa $RSA_TRADITIONAL -out client-auth/root.key 2048 2>/dev/null
openssl req -new -x509 -key client-auth/root.key \
    -out client-auth/root.pem \
    -days 7300 -sha256 \
    -subj "/CN=client-auth-root/O=CFSSL Test" \
    -addext "basicConstraints=critical,CA:TRUE"

# Intermediate
openssl genrsa $RSA_TRADITIONAL -out client-auth/int.key 2048 2>/dev/null
openssl req -new -key client-auth/int.key \
    -out client-auth/int.csr \
    -subj "/CN=client-auth-int/O=CFSSL Test"

extfile_ca=$(mktemp /tmp/ext_XXXXXX.cnf)
cat >"$extfile_ca" <<EXTEOF
[ ext ]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EXTEOF
openssl x509 -req -in client-auth/int.csr \
    -CA client-auth/root.pem -CAkey client-auth/root.key \
    -CAcreateserial -out client-auth/int.pem \
    -days 3650 -sha256 \
    -extfile "$extfile_ca" -extensions ext 2>/dev/null
rm -f "$extfile_ca" client-auth/int.csr

# leaf-server (serverAuth EKU)
openssl genrsa $RSA_TRADITIONAL -out client-auth/leaf-server.key 2048 2>/dev/null
openssl req -new -key client-auth/leaf-server.key \
    -out client-auth/leaf-server.csr \
    -subj "/CN=client-auth-server/O=CFSSL Test"
extfile_srv=$(mktemp /tmp/ext_XXXXXX.cnf)
cat >"$extfile_srv" <<EXTEOF
[ ext ]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EXTEOF
openssl x509 -req -in client-auth/leaf-server.csr \
    -CA client-auth/int.pem -CAkey client-auth/int.key \
    -CAcreateserial -out client-auth/leaf-server.pem \
    -days 3650 -sha256 \
    -extfile "$extfile_srv" -extensions ext 2>/dev/null
rm -f "$extfile_srv" client-auth/leaf-server.csr

# leaf-client (clientAuth EKU)
openssl genrsa $RSA_TRADITIONAL -out client-auth/leaf-client.key 2048 2>/dev/null
openssl req -new -key client-auth/leaf-client.key \
    -out client-auth/leaf-client.csr \
    -subj "/CN=client-auth-client/O=CFSSL Test"
extfile_cli=$(mktemp /tmp/ext_XXXXXX.cnf)
cat >"$extfile_cli" <<EXTEOF
[ ext ]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
EXTEOF
openssl x509 -req -in client-auth/leaf-client.csr \
    -CA client-auth/int.pem -CAkey client-auth/int.key \
    -CAcreateserial -out client-auth/leaf-client.pem \
    -days 3650 -sha256 \
    -extfile "$extfile_cli" -extensions ext 2>/dev/null
rm -f "$extfile_cli" client-auth/leaf-client.csr

echo "  client-auth/{root,int,leaf-server,leaf-client}.pem written"

# ══════════════════════════════════════════════════════════════════════════════
# 12. empty.pem  (must exist and be empty)
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "--- 12. empty.pem ---"
: > empty.pem
echo "  empty.pem written"

# ══════════════════════════════════════════════════════════════════════════════
# 13. ca-bundle.pem + int-bundle.pem
#
# These are the root/intermediate pools used by newBundler() in the test suite.
# Previously they contained real-world GoDaddy certs signed with SHA-1WithRSA,
# which Go >= 1.24 hard-rejects.  We replace them with a locally-generated
# SHA-256 pair whose fields match the updated assertions in bundler_test.go:
#
#   Root   CN: CFSSL Test Root CA  /C=US/O=CFSSL Test CA
#   Inter  CN: CFSSL Test Intermediate CA
#          /C=US/ST=California/L=San Francisco/O=CFSSL Test/OU=Test PKI
#          OCSP:  http://ocsp.cfssl.test
#          CRL:   http://crl.cfssl.test/root.crl
#          Expiry: 2035-01-01T00:00:00Z  (fixed via openssl ca -startdate/-enddate)
#          Key:   RSA 2048
#          Sig:   SHA256WithRSA
#
# The intermediate is written to int-bundle.pem so newBundler() can find it as
# the intermediate pool when bundling the intermediate cert itself.
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "--- 13. ca-bundle.pem + int-bundle.pem (SHA-256 test fixtures) ---"

# Root key + self-signed cert
openssl genrsa $RSA_TRADITIONAL -out cabundle_root.key 2048 2>/dev/null
openssl req -new -x509 -key cabundle_root.key -out ca-bundle.pem \
    -days 7300 -sha256 \
    -subj "/C=US/O=CFSSL Test CA/CN=CFSSL Test Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"

# Intermediate key + CSR
openssl genrsa $RSA_TRADITIONAL -out cabundle_inter.key 2048 2>/dev/null
openssl req -new -key cabundle_inter.key -out cabundle_inter.csr \
    -subj "/C=US/ST=California/L=San Francisco/O=CFSSL Test/OU=Test PKI/CN=CFSSL Test Intermediate CA"

# Sign with fixed dates so tests can hard-code the expiry string
CADB13=$(mktemp -d /tmp/cadb13_XXXXXX)
mkdir -p "$CADB13/newcerts"
touch "$CADB13/index.txt"
echo "1000" > "$CADB13/serial"

CACONF13=$(mktemp /tmp/ca13_XXXXXX.cnf)
cat >"$CACONF13" <<CAEOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir            = $CADB13
new_certs_dir  = \$dir/newcerts
database       = \$dir/index.txt
serial         = \$dir/serial
certificate    = ca-bundle.pem
private_key    = cabundle_root.key
default_md     = sha256
policy         = policy_loose
copy_extensions = copy

[ policy_loose ]
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied

[ v3_inter ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
authorityInfoAccess = OCSP;URI:http://ocsp.cfssl.test
crlDistributionPoints = URI:http://crl.cfssl.test/root.crl
CAEOF

openssl ca -batch -config "$CACONF13" \
    -in cabundle_inter.csr \
    -out int-bundle.pem \
    -startdate 250101000000Z \
    -enddate   350101000000Z \
    -extensions v3_inter \
    -notext 2>/dev/null

rm -rf "$CADB13" "$CACONF13" cabundle_inter.csr cabundle_root.key cabundle_inter.key

echo "  ca-bundle.pem written (SHA-256 test root)"
echo "  int-bundle.pem written (SHA-256 test intermediate, expiry 2035-01-01)"

# self-signed.pem: used by TestBundleFromPEM to exercise error 1100 (unknown authority).
# Must be valid (not expired) but NOT in ca-bundle.pem.
openssl genrsa $RSA_TRADITIONAL -out selfsigned.key 2048 2>/dev/null
openssl req -new -x509 -key selfsigned.key -out self-signed.pem \
    -days 3650 -sha256 \
    -subj "/CN=cfssl-test-selfsigned/O=CFSSL Test/C=US"
rm -f selfsigned.key
echo "  self-signed.pem written"

# ══════════════════════════════════════════════════════════════════════════════
# Cleanup
# ══════════════════════════════════════════════════════════════════════════════
rm -f ca-config.json ca.srl inter-L1.srl inter-L2.srl \
      cfssl-leaf-rsa4096.srl client-auth/root.srl client-auth/int.srl \
      ./*.srl 2>/dev/null || true

# ══════════════════════════════════════════════════════════════════════════════
# Summary verification
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== Verification ==="

verify_chain() {
    local leaf="$1"; local chain="$2"; local root="$3"
    if openssl verify -CAfile "$root" -untrusted "$chain" "$leaf" >/dev/null 2>&1; then
        echo "  OK  $leaf"
    else
        echo "  FAIL $leaf"
        openssl verify -CAfile "$root" -untrusted "$chain" "$leaf" 2>&1 | sed 's/^/       /'
    fi
}

verify_chain cfssl-leaf-ecdsa256.pem intermediates.crt ca.pem
verify_chain cfssl-leaf-ecdsa384.pem intermediates.crt ca.pem
verify_chain cfssl-leaf-ecdsa521.pem intermediates.crt ca.pem
verify_chain cfssl-leaf-rsa2048.pem  intermediates.crt ca.pem
verify_chain cfssl-leaf-rsa3072.pem  intermediates.crt ca.pem
verify_chain cfssl-leaf-rsa4096.pem  intermediates.crt ca.pem

# leaflet chain: root + inter-L1 + inter-L2 + leafRSA4096 as untrusted chain
# NOTE: this is *expected* to fail with "path length constraint exceeded" —
# that is precisely the error (1213 TooManyIntermediates) the test asserts.
cat inter-L1.pem inter-L2.pem cfssl-leaf-rsa4096.pem > /tmp/leaflet_chain.pem
if openssl verify -CAfile ca.pem -untrusted /tmp/leaflet_chain.pem \
        cfssl-leaflet-rsa4096.pem >/dev/null 2>&1; then
    echo "  WARN cfssl-leaflet-rsa4096.pem verified OK — pathlen violation not triggered (unexpected)"
else
    echo "  OK  cfssl-leaflet-rsa4096.pem correctly fails openssl verify (pathlen exceeded — expected)"
fi
rm -f /tmp/leaflet_chain.pem

# inter-L2-direct should verify directly against root
verify_chain inter-L2-direct.pem ca.pem ca.pem

# inter-L1-expired should NOT verify (expected)
if ! openssl verify -CAfile ca.pem inter-L1-expired.pem >/dev/null 2>&1; then
    echo "  OK  inter-L1-expired.pem correctly does not verify (expired)"
else
    echo "  WARN inter-L1-expired.pem verified — expiry may not have worked correctly"
fi

echo ""
echo "=== Done. All testdata regenerated in: $TESTDATA ==="
