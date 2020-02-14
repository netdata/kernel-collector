#!/bin/bash

function get_kernel_version() {
  r="$(uname -r | cut -f 1 -d '-')"

  read -r -a p <<< "$(echo "${r}" | tr '.' ' ')"

  printf "%03d%03d%03d" "${p[0]}" "${p[1]}" "${p[2]}"
}

if [ "$(uname -s)" != "Linux" ]; then
  echo >&2 "This does not appear to be a Linux system."
  exit 1
fi

KERNEL_VERSION="$(uname -r)"

if [ "$(get_kernel_version)" -lt 004014000 ]; then
  echo >&2 "Your kernel appears to be older than 4.11. This may still work in some cases, but probably won't."
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

  REQUIRED_CONFIG="KPROBES KPROBES_ON_FTRACE HAVE_KPROBES HAVE_KPROBES_ON_FTRACE KPROBE_EVENTS"

  for required_config in ${REQUIRED_CONFIG}; do
    if ! "${GREP}" -q "CONFIG_${required_config}=y" "${CONFIG_PATH}"; then
      echo >&2 " Missing Kernel Config: ${required_config}"
      exit 1
    fi
  done
fi

if [ -n "${MODULE_LOADED}" ]; then
  modprobe -r configs 2> /dev/null
fi
