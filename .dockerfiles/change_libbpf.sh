#!/bin/bash

KMAJOR=
KMINOR=

if [ -z "$1" ] || [ -z "$2" ]; then
    VER=$(uname -r)
    KMAJOR=$(echo "${VER}" | cut -d. -f1)
    KMINOR=$(echo "${VER}" | cut -d. -f2)
    echo "Kernel parameters not given, we will use dist values ${KMAJOR}.${KMINOR}"
else
    KMAJOR="${1}"
    KMINOR="${2}"
fi

parse_kernel_version() {
    R="${1}.${2}"

    read -r -a P <<< "$(echo "${R}" | tr '.' ' ')"

    printf "%03d%03d" "${P[0]}" "${P[1]}"
}

KVER=$(parse_kernel_version "${KMAJOR}" "${KMINOR}")

VER3_10_0="003010"

if [ "${KVER}" -eq "${VER3_10_0}" ]; then
    git checkout netdata-patch
fi
