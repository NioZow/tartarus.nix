#!/usr/bin/env bash
# tartarus-certs — standalone X.509 certificate tooling (no Nix, no tartarus).
#
# This is the shell counterpart of `src/tartarus/ca.py` (the X509 half). It
# mints the same material in the same on-disk layout and with the same
# extended-key-usage OIDs, so a CA and its leaves are interchangeable between
# the CLI (`tartarus ...`) and this script:
#
#   <root>/ca/tartarus.key|.crt          the root CA
#   <root>/host/server.key|.crt          the host server certificate
#   <root>/machines/<kind>/<name>/client.key|.crt   a guest client certificate
#   <root>/machines/<kind>/<name>/ca.crt            a copy of the root CA
#
# Private keys are 0600, certificates/ca.crt are 0644. Everything is
# idempotent: an existing key/cert is reused unless --force is given.
#
# Usage:
#   tartarus-certs init-ca     --out DIR [--days N] [--bits N] [--force]
#   tartarus-certs issue-server --out DIR --cn NAME [--service SVC]
#                              [--days N] [--bits N] [--force]
#   tartarus-certs issue-client --out DIR --name NAME [--kind K] [--service SVC]
#                              [--days N] [--bits N] [--force]
#   tartarus-certs show        --out DIR
#   tartarus-certs install     --out DIR (--server | --name NAME) --dest DIR
#   tartarus-certs verify      --out DIR (--server | --name NAME) [--service SVC]
#
# `--service` is one of ssh-agent | sudo | clipboard. When omitted the
# certificate carries all three service OIDs, exactly like ca.py; when given,
# it is restricted to that service's OID (plus the standard serverAuth /
# clientAuth EKU).
set -euo pipefail

SERVICE=""
OUT="."
NAME=""
CN=""
KIND="microvm"
DAYS=""
BITS=""
FORCE=0
ROLE=""
DEST=""

die() {
  echo "tartarus-certs: $*" >&2
  exit 1
}

usage() {
  sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

# OID maps, mirroring src/tartarus/ca.py.
oid_server() {
  case "$1" in
    ssh-agent) echo "1.3.6.1.4.1.99999.2.1" ;;
    sudo)      echo "1.3.6.1.4.1.99999.1.1" ;;
    clipboard) echo "1.3.6.1.4.1.99999.3.1" ;;
    *) die "unknown service '$1' (ssh-agent|sudo|clipboard)" ;;
  esac
}
oid_client() {
  case "$1" in
    ssh-agent) echo "1.3.6.1.4.1.99999.2.2" ;;
    sudo)      echo "1.3.6.1.4.1.99999.1.2" ;;
    clipboard) echo "1.3.6.1.4.1.99999.3.2" ;;
    *) die "unknown service '$1' (ssh-agent|sudo|clipboard)" ;;
  esac
}

server_ekus() {
  if [ -n "$SERVICE" ]; then
    echo "serverAuth,$(oid_server "$SERVICE")"
  else
    echo "serverAuth,$(oid_server ssh-agent),$(oid_server sudo),$(oid_server clipboard)"
  fi
}

client_ekus() {
  if [ -n "$SERVICE" ]; then
    echo "clientAuth,$(oid_client "$SERVICE")"
  else
    echo "clientAuth,$(oid_client ssh-agent),$(oid_client sudo),$(oid_client clipboard)"
  fi
}

ca_key() { echo "$OUT/ca/tartarus.key"; }
ca_crt() { echo "$OUT/ca/tartarus.crt"; }
host_key() { echo "$OUT/host/server.key"; }
host_crt() { echo "$OUT/host/server.crt"; }
client_dir() { echo "$OUT/machines/$KIND/$NAME"; }

require_ca() {
  [ -f "$(ca_key)" ] && [ -f "$(ca_crt)" ] || die "no CA in $OUT (run 'init-ca' first)"
}

cmd_init_ca() {
  mkdir -p "$OUT/ca"
  local key crt
  key="$(ca_key)"
  crt="$(ca_crt)"
  if [ -f "$key" ] && [ "$FORCE" -eq 0 ]; then
    echo "CA key already exists: $key"
  else
    [ "$FORCE" -eq 1 ] && rm -f "$key" "$crt" || true
    echo "Generating root CA key: $key"
    openssl genrsa -out "$key" "${BITS:-4096}"
  fi
  chmod 600 "$key"
  if [ -f "$crt" ] && [ "$FORCE" -eq 0 ]; then
    echo "CA certificate already exists: $crt"
    return
  fi
  echo "Generating root CA certificate: $crt"
  openssl req -new -x509 -key "$key" -sha256 -days "${DAYS:-3650}" \
    -subj "/C=US/O=Tartarus/CN=tartarus-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$crt"
  chmod 644 "$crt"
}

cmd_issue_server() {
  [ -n "$CN" ] || die "issue-server requires --cn"
  require_ca
  mkdir -p "$OUT/host"
  local key crt csr ext
  key="$(host_key)"
  crt="$(host_crt)"
  if [ -f "$key" ] && [ "$FORCE" -eq 0 ]; then
    echo "Server key already exists: $key"
  else
    [ "$FORCE" -eq 1 ] && rm -f "$key" "$crt" || true
    echo "Generating server key: $key"
    openssl genrsa -out "$key" "${BITS:-2048}"
  fi
  chmod 600 "$key"
  if [ -f "$crt" ] && [ "$FORCE" -eq 0 ]; then
    echo "Server certificate already exists: $crt"
    return
  fi
  csr="$(mktemp)"
  ext="$(mktemp)"
  echo "Signing server certificate for CN=$CN: $crt"
  openssl req -new -key "$key" -subj "/C=US/O=Tartarus/CN=$CN" -out "$csr"
  printf '[v3_ext]\nextendedKeyUsage = %s\n' "$(server_ekus)" > "$ext"
  openssl x509 -req -in "$csr" -CA "$(ca_crt)" -CAkey "$(ca_key)" \
    -CAcreateserial -sha256 -days "${DAYS:-365}" \
    -extfile "$ext" -extensions v3_ext -out "$crt"
  chmod 644 "$crt"
  rm -f "$csr" "$ext"
}

cmd_issue_client() {
  [ -n "$NAME" ] || die "issue-client requires --name"
  require_ca
  local dir key crt csr ext ca_copy
  dir="$(client_dir)"
  mkdir -p "$dir"
  key="$dir/client.key"
  crt="$dir/client.crt"
  if [ -f "$key" ] && [ "$FORCE" -eq 0 ]; then
    echo "Client key already exists: $key"
  else
    [ "$FORCE" -eq 1 ] && rm -f "$key" "$crt" || true
    echo "Generating client key for $NAME ($KIND): $key"
    openssl genrsa -out "$key" "${BITS:-2048}"
  fi
  chmod 600 "$key"
  if [ -f "$crt" ] && [ "$FORCE" -eq 0 ]; then
    echo "Client certificate already exists: $crt"
  else
    csr="$(mktemp)"
    ext="$(mktemp)"
    echo "Signing client certificate for CN=$NAME: $crt"
    openssl req -new -key "$key" -subj "/C=US/O=Tartarus/CN=$NAME" -out "$csr"
    printf '[v3_ext]\nextendedKeyUsage = %s\n' "$(client_ekus)" > "$ext"
    openssl x509 -req -in "$csr" -CA "$(ca_crt)" -CAkey "$(ca_key)" \
      -CAcreateserial -sha256 -days "${DAYS:-365}" \
      -extfile "$ext" -extensions v3_ext -out "$crt"
    chmod 644 "$crt"
    rm -f "$csr" "$ext"
  fi
  ca_copy="$dir/ca.crt"
  cp -f "$(ca_crt)" "$ca_copy"
  chmod 644 "$ca_copy"
  echo "Client material ready in $dir"
}

cmd_show() {
  local files=()
  [ -f "$(ca_crt)" ] && files+=("$(ca_crt)")
  [ -f "$(host_crt)" ] && files+=("$(host_crt)")
  if [ -n "$NAME" ]; then
    files+=("$(client_dir)/client.crt")
  else
    while IFS= read -r f; do files+=("$f"); done < <(find "$OUT/machines" -name client.crt 2>/dev/null | sort)
  fi
  [ "${#files[@]}" -gt 0 ] || die "no certificates found under $OUT"
  for f in "${files[@]}"; do
    [ -f "$f" ] || continue
    echo "== $f"
    openssl x509 -in "$f" -noout -subject -issuer -dates 2>/dev/null || echo "  (not a certificate)"
    openssl x509 -in "$f" -noout -ext extendedKeyUsage 2>/dev/null | sed 's/^/  /' || true
  done
}

cmd_install() {
  [ -n "$DEST" ] || die "install requires --dest"
  require_ca
  mkdir -p "$DEST"
  if [ "$ROLE" = "server" ]; then
    cp -f "$(host_key)" "$DEST/server.key"
    cp -f "$(host_crt)" "$DEST/server.crt"
    chmod 600 "$DEST/server.key"
    chmod 644 "$DEST/server.crt"
  else
    [ -n "$NAME" ] || die "install requires --server or --name"
    cp -f "$(client_dir)/client.key" "$DEST/client.key"
    cp -f "$(client_dir)/client.crt" "$DEST/client.crt"
    chmod 600 "$DEST/client.key"
    chmod 644 "$DEST/client.crt"
  fi
  cp -f "$(ca_crt)" "$DEST/ca.crt"
  chmod 644 "$DEST/ca.crt"
  echo "Installed material into $DEST"
}

cmd_verify() {
  require_ca
  local cert
  if [ "$ROLE" = "server" ]; then
    cert="$(host_crt)"
  else
    [ -n "$NAME" ] || die "verify requires --server or --name"
    cert="$(client_dir)/client.crt"
  fi
  [ -f "$cert" ] || die "certificate not found: $cert"
  openssl verify -CAfile "$(ca_crt)" "$cert"
  if [ -n "$SERVICE" ]; then
    local want
    if [ "$ROLE" = "server" ]; then want="$(oid_server "$SERVICE")"; else want="$(oid_client "$SERVICE")"; fi
    if openssl x509 -in "$cert" -noout -ext extendedKeyUsage | grep -q "$want"; then
      echo "OK: $cert carries OID $want"
    else
      die "$cert is missing OID $want"
    fi
  fi
}

COMMAND="${1:-}"
[ -n "$COMMAND" ] || usage 1
shift || true

while [ $# -gt 0 ]; do
  case "$1" in
    --service) SERVICE="${2:?--service needs a value}"; shift 2 ;;
    --out) OUT="${2:?--out needs a value}"; shift 2 ;;
    --name) NAME="${2:?--name needs a value}"; shift 2 ;;
    --cn) CN="${2:?--cn needs a value}"; shift 2 ;;
    --kind) KIND="${2:?--kind needs a value}"; shift 2 ;;
    --dest) DEST="${2:?--dest needs a value}"; shift 2 ;;
    --days) DAYS="${2:?--days needs a value}"; shift 2 ;;
    --bits) BITS="${2:?--bits needs a value}"; shift 2 ;;
    --force) FORCE=1; shift ;;
    --server) ROLE="server"; shift ;;
    -h|--help) usage 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

OUT="${OUT/#\~/$HOME}"

case "$COMMAND" in
  init-ca) cmd_init_ca ;;
  issue-server) cmd_issue_server ;;
  issue-client) cmd_issue_client ;;
  show) cmd_show ;;
  install) cmd_install ;;
  verify) cmd_verify ;;
  *) die "unknown command: $COMMAND (init-ca|issue-server|issue-client|show|install|verify)" ;;
esac
