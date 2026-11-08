#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Certificates for SIEMstress's TLS syslog listener, signed by a private CA.
#
#   make-certs.sh DIR ca                  create the CA (once)
#   make-certs.sh DIR server NAME [IP]    certificate for the machine running SIEMstress
#   make-certs.sh DIR client NAME         certificate for a machine that sends logs;
#                                         NAME is the host name its events get
#
# Keep ca.key private (ideally offline). Each client needs ca.crt, NAME.crt, NAME.key.
# Keys are unencrypted (mode 0600); the CA lasts 10 years, leaf certificates 825 days and
# there is no revocation list, so re-issue before expiry and replace the CA to revoke.
set -euo pipefail

usage() { sed -n '4,11p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
[[ $# -ge 2 ]] || usage
dir=$1 cmd=$2
mkdir -p "$dir"
cd "$dir"
umask 077

new_key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }

case $cmd in
  ca)
    [[ -e ca.key ]] && { echo "ca.key already exists in $dir" >&2; exit 1; }
    new_key ca.key
    openssl req -x509 -new -key ca.key -days 3650 -subj "/CN=SIEMstress CA" -out ca.crt \
      -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -addext "subjectKeyIdentifier=hash"
    ;;
  server | client)
    [[ $# -ge 3 ]] || usage
    name=$3
    # NAME ends up in the certificate subject and SAN: allow only host-name characters.
    [[ $name =~ ^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$ ]] \
      || { echo "NAME must be a host name (letters, digits, '.', '-', '_')" >&2; exit 1; }
    if [[ -n ${4:-} ]]; then
      [[ $cmd == server && $4 =~ ^[0-9A-Fa-f.:]+$ ]] \
        || { echo "the optional IP is for server certificates and must be an address" >&2; exit 1; }
    fi
    san="DNS:$name${4:+,IP:$4}"
    purpose=$([[ $cmd == server ]] && echo serverAuth || echo clientAuth)
    new_key "$name.key"
    openssl req -new -key "$name.key" -subj "/CN=$name" -out "$name.csr"
    openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 825 \
      -out "$name.crt" 2>/dev/null \
      -extfile <(printf '%s\n' "basicConstraints=critical,CA:FALSE" \
        "keyUsage=critical,digitalSignature" "extendedKeyUsage=$purpose" \
        "subjectAltName=$san" "subjectKeyIdentifier=hash" "authorityKeyIdentifier=keyid")
    rm "$name.csr"
    ;;
  *) usage ;;
esac
echo "wrote to $dir: $(ls -1 | tr '\n' ' ')"
