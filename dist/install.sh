#!/bin/sh
# Installer for termotp.
# This script is bundled with the releases and should not be executed directly.

set -eu

readonly PREFIX="/usr/local"

die() {
  echo >&2 "${ERR} ${*}"
  exit 1
}

main() {
  uid="$(id -u)"
  if [ "${uid}" -ne 0 ]; then
    die "Please run this program as root (using sudo)"
  fi

  bindir="${PREFIX}/bin"

  mkdir -p "${bindir}"
  cp termotp  "${bindir}"
  chmod 755 "${bindir}/termotp"
}

main "${@}"
