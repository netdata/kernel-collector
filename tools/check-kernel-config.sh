#!/bin/bash

parse_version() {
  r="${1}"
  if echo "${r}" | grep -q '^v.*'; then
    # shellcheck disable=SC2001
    # XXX: Need a regex group subsitutation here.
    r="$(echo "${r}" | sed -e 's/^v\(.*\)/\1/')"
  fi

  read -r -a p <<< "$(echo "${r}" | tr '-' ' ')"

  v="${p[0]}"
  b="${p[1]}"
  _="${p[2]}" # ignore the SHA

  if [[ ! "${b}" =~ ^[0-9]+$ ]]; then
    b="0"
  fi

  read -r -a pp <<< "$(echo "${v}" | tr '.' ' ')"
  printf "%03d%03d%03d%03d" "${pp[0]}" "${pp[1]}" "${pp[2]}" "${b}"
}

if [ "$(uname -s)" != "Linux" ]; then
  echo "This does not appear to be a Linux system."
  exit 1
fi

KERNEL_VERSION="$(uname -r)"

# This insane looking condition is checking the kernel version as a floating point number.
if [ "$(parse_version "${KERNEL_VERSION}")" -lt "$(parse_version 4.14)" ]; then
  echo "Your kernel appears to be older than 4.11. This may still work in some cases, but probably won't."
fi

CONFIG_PATH=""
MODULE_LOADED=""

if modprobe configs 2> /dev/null; then
  MODULE_LOADED=1
fi

if [ -r /proc/config.gz ]; then
  CONFIG_PATH="/proc/config.gz"
elif [ -r "/lib/modules/${KERNEL_VERSION}/source/.config" ]; then
  CONFIG_PATH="/lib/modules/${KERNEL_VERSION}/source/.config"
elif [ -n "$(find /boot -name "config-${KERNEL_VERSION}*")" ]; then
  CONFIG_PATH="$(find /boot -name "config-${KERNEL_VERSION}*" | head -n 1)"
fi

if [ -n "${CONFIG_PATH}" ]; then
  GREP='grep'

  if echo "${CONFIG_PATH}" | grep -q '.gz'; then
    GREP='zgrep'
  fi

  if "${GREP}" -qv "CONFIG_KPROBES=y" "${CONFIG_PATH}" ||
    "${GREP}" -qv "CONFIG_KPROBES_ON_FTRACE=y" "${CONFIG_PATH}" ||
    "${GREP}" -qv "CONFIG_HAVE_KPROBES=y" "${CONFIG_PATH}" ||
    "${GREP}" -qv "CONFIG_HAVE_KPROBES_ON_FTRACE=y" "${CONFIG_PATH}" ||
    "${GREP}" -qv "CONFIG_KPROBE_EVENTS=y" "${CONFIG_PATH}"; then
    echo "Required kernel config options not found."
    exit 1
  fi
fi

if [ -n "${MODULE_LOADED}" ]; then
  modprobe -r configs 2> /dev/null
fi
