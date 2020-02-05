#!/bin/sh

if [ "$(uname -s)" != "Linux" ] ; then
    echo "This does not appear to be a Linux system."
    exit 1
fi

KERNEL_VERSION="$(uname -r)"
KERNEL_VERSION_MAJOR="$(uname -r | cut -f 1 -d '.')"
KERNEL_VERSION_MINOR="$(uname -r | cut -f 2 -d '.')"

# This insane looking condition is checking the kernel version as a floating point number.
if [ "$(echo "${KERNEL_VERSION_MAJOR}.${KERNEL_VERSION_MINOR}" 4.11 | awk '{if ($1 < $2) print $1; else print $2}')" != "4.11" ] ; then
    echo "Your kernel appears to be older than 4.11. This may still work in some cases, but probably won't."
fi

CONFIG_PATH=""

if [ -r /proc/config.gz ] || modprobe configs 2> /dev/null ; then
    CONFIG_PATH="/proc/config.gz"
elif [ -r "/lib/modules/${KERNEL_VERSION}/source/.config" ] ; then
    CONFIG_PATH="/lib/modules/${KERNEL_VERSION}/source/.config"
elif [ -n "$(find /boot -name "config-${KERNEL_VERSION}*")" ] ; then
    CONFIG_PATH="$(find /boot -name "config-${KERNEL_VERSION}*" | head -n 1)"
fi

if [ -n "${CONFIG_PATH}" ] ; then
    if echo "${CONFIG_PATH}" | grep -q '.gz' ; then
        zcat "${CONFIG_PATH}" > /tmp/config
        CONFIG_PATH=/tmp/config
    fi

    if grep -qv "CONFIG_KPROBES=y" "${CONFIG_PATH}" || \
       grep -qv "CONFIG_KPROBES_ON_FTRACE=y" "${CONFIG_PATH}" || \
       grep -qv "CONFIG_HAVE_KPROBES=y" "${CONFIG_PATH}" || \
       grep -qv "CONFIG_HAVE_KPROBES_ON_FTRACE=y" "${CONFIG_PATH}" || \
       grep -qv "CONFIG_KPROBE_EVENTS=y" "${CONFIG_PATH}"
    then
        echo "Required kernel config options not found."
        exit 1
    fi

    if [ "${CONFIG_PATH}" = /tmp/config ] ; then
        rm /tmp/config
    fi
fi
