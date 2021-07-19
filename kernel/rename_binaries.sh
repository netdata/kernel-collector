#!/bin/bash

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "Give kernel as parameter: kernel major version, kernel minor version, and function name"
    exit 1
fi

parse_kernel_version() {
    R="${1}.${2}"

    read -r -a P <<< "$(echo "${R}" | tr '.' ' ')"

    printf "%03d%03d" "${P[0]}" "${P[1]}"
}

select_kernel_version() {
    KVER=$(parse_kernel_version "${1}" "${2}")

    VER5_11_0="005011"
    VER5_10_0="005010"
    VER4_18_0="004018"
    VER4_17_0="004017"
    VER4_15_0="004015"
    VER4_11_0="004011"
    VER3_10_0="003010"

    if [ "${KVER}" -eq "${VER3_10_0}" ]; then
        KSELECTED="3.10";
    elif [ "${KVER}" -eq "${VER4_18_0}" ]; then
        KSELECTED="4.18";
    elif [ "${KVER}" -ge "${VER5_11_0}" ]; then
        KSELECTED="5.11";
    elif [ "${KVER}" -ge "${VER5_10_0}" ]; then
        KSELECTED="5.10";
    elif [ "${KVER}" -ge "${VER4_17_0}" ]; then
        KSELECTED="5.4";
    elif [ "${KVER}" -ge "${VER4_15_0}" ]; then
        KSELECTED="4.16";
    elif [ "${KVER}" -ge "${VER4_11_0}" ]; then
        KSELECTED="4.14";
    fi

    echo "${KSELECTED}"
}

OBJECTNAME="$3"
NAME=${OBJECTNAME%_*}

KNAME=$(select_kernel_version "${1}" "${2}")

cp "r${NAME}_kern.o" "../rnetdata_ebpf_${NAME}.${KNAME}.o"
cp "p${NAME}_kern.o" "../pnetdata_ebpf_${NAME}.${KNAME}.o"
