#!/bin/sh
# See http://github.com/marcopaganini/termotp
# for details on how to use this script.

set -eu

readonly DEFAULT_INSTALL_DIR="/usr/local/bin"
readonly PROGRAM="${0##*/}"
readonly OK="✅"
readonly ERR="❌"

# go_arch retrieves the go equivalent architecture for this machine.
go_arch() {
  arch="$(uname -m)"
  case "${arch}" in
    aarch64_be|aarch64|arm64|armv8b|armv8l)
      echo "arm64" ;;
    arm)
      echo "arm" ;;
    i386|i686)
      echo "386" ;;
    mips)
      echo "mips" ;;
    mips64)
      echo "mips64" ;;
    s390|s390x)
      echo "s390x" ;;
    x86_64)
      echo "amd64" ;;
  esac
}

# os_name returns the os_name.
os_name() {
  os="$(uname -o)"
  # Windows not supported for now.
  case "${os}" in
    "GNU/Linux")
      echo "linux" ;;
    "Darwin")
      echo "darwin" ;;
  esac
}

# tempname returns a temporary directory name. This is a crude workaround for
# systems that don't have mktemp and rudimentary date commands.
tempname() {
  echo "/tmp/${PROGRAM}-$$"
}

die() {
  echo >&2 "${ERR} ${*}"
  exit 1
}

main() {
  # First argument = github username/repo.
  if [ $# -lt 1 ]; then
    die "Use: install.sh username/repo [destination_dir]"
  fi

  # Second argument (optional) installation directory.
  install_dir="${DEFAULT_INSTALL_DIR}"
  if [ $# -eq 2 ]; then
    install_dir="${2}"
  fi

  readonly repo="${1}"
  readonly release_name="${repo##*/}"
  readonly releases_url="https://api.github.com/repos/${repo}/releases"

  os="$(os_name)"
  arch="$(go_arch)"

  [ -z "${os}" ] && die "Unknown OS. Please send the result of 'uname -o' and 'uname -m' to the author."
  [ -z "${arch}" ] && die "Unknown processor architecture. Please send the result of 'uname -m' to the author."

  echo "${OK} Your OS is: ${os}"
  echo "${OK} Your architecture is: ${arch}"
  echo "${OK} Install directory: ${install_dir}"

  tgz="${release_name}_[0-9].[0-9].[0-9]_${os}_${arch}.tar.gz"

  # Retrieve the list releases from github (this is hacky but we don't
  # want to force people to have a proper JSON parser installed.)
  latest="$(wget -q -O- "${releases_url}" | grep browser_download_url | grep -o "https://.*${tgz}" | sort -g | tail -1)"
  [ -z "${latest}" ] && die "Unable to find any releases."
  echo "${OK} Latest release: ${latest}"

  # Download and install
  tmp="$(tempname)"
  out="${tmp}/${release_name}.tar.gz"

  rm -rf "${tmp}"
  mkdir -p "${tmp}"
  echo "${OK} Downloading latest release."
  if ! wget -q "${latest}" -O "${out}"; then
    die "Error downloading: ${latest}"
  fi

  cwd="$(pwd)"
  cd "${tmp}"
  echo "${OK} Unpacking local installation file."
  if ! gzip -d -c "${out}" | tar x; then
    die "Error unpacking local release ($out)."
  fi

  mv "${tmp}/${release_name}" "${install_dir}" || die "Installation failed."
  chmod 755 "${install_dir}/${release_name}"

  cd "${cwd}"
  rm -rf "${tmp}"
  echo "${OK} Installation finished! Please make sure ${install_dir} is in your PATH."
}

main "${@}"
