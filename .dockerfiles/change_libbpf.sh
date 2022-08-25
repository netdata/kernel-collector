#!/bin/bash

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Give kernel as parameter: kernel major version, kernel minor version"
    exit 1
fi

parse_kernel_version() {
    R="${1}.${2}"

    read -r -a P <<< "$(echo "${R}" | tr '.' ' ')"

    printf "%03d%03d" "${P[0]}" "${P[1]}"
}

KVER=$(parse_kernel_version "${1}" "${2}")

VER3_10_0="003010"

if [ "${KVER}" -eq "${VER3_10_0}" ]; then
    cd /kernel-collector && git submodule update --init --recursive && cd /kernel-collector/libbpf && git fetch origin && git checkout netdata-patch && cd ..
fi