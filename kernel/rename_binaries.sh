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
    FORCE_RHF="${3:-}"
    FULL_KERNEL_VERSION="${4:-${1}.${2}}"
    VER6_12_0="006012"
    VER7_0_0="007000"
    VER6_8_0="006008"
    VER5_17_0="005017"
    VER5_16_0="005016"
    VER5_15_0="005015"
    VER5_14_0="005014"
    VER5_11_0="005011"
    VER5_10_0="005010"
    VER4_18_0="004018"
    VER4_17_0="004017"
    VER4_15_0="004015"
    VER4_12_0="004012"
    VER3_10_0="003010"
    ISRH=""

    if [ "${FULL_KERNEL_VERSION}" = "6.16.2" ]; then
        KSELECTED="6.16.2";
    elif [ "${KVER}" -eq "${VER3_10_0}" ]; then
        KSELECTED="3.10";
    elif [ "${KVER}" -ge "${VER7_0_0}" ]; then
        KSELECTED="7.0";
    elif [ "${KVER}" -eq "${VER4_18_0}" ]; then
        KSELECTED="4.18";
    elif [ "${KVER}" -ge "${VER6_12_0}" ]; then
        KSELECTED="6.12";
    elif [ "${KVER}" -ge "${VER6_8_0}" ]; then
        KSELECTED="6.8";
    elif [ "${KVER}" -ge "${VER5_17_0}" ]; then
        KSELECTED="5.17";
    elif [ "${KVER}" -ge "${VER5_16_0}" ]; then
        KSELECTED="5.16";
    elif [ "${KVER}" -ge "${VER5_15_0}" ]; then
        KSELECTED="5.15";
    elif [ "${KVER}" -ge "${VER5_14_0}" ]; then
        KSELECTED="5.14";
    elif [ "${KVER}" -ge "${VER5_11_0}" ]; then
        KSELECTED="5.11";
    elif [ "${KVER}" -ge "${VER5_10_0}" ]; then
        KSELECTED="5.10";
    elif [ "${KVER}" -ge "${VER4_17_0}" ]; then
        KSELECTED="5.4";
    elif [ "${KVER}" -ge "${VER4_15_0}" ]; then
        KSELECTED="4.16";
    elif [ "${KVER}" -ge "${VER4_12_0}" ]; then
        KSELECTED="4.14";
    fi

    if [ -z "${KSELECTED}" ]; then
        echo "Unsupported kernel version ${1}.${2}: only 3.10 and 4.12 or newer are supported." >&2
        exit 1
    fi

    if [ -f /etc/redhat-release ] || [ "${FORCE_RHF}" = ".rhf" ]; then
        ISRH=".rhf"
    fi

    echo "${KSELECTED}${ISRH}"
}

OBJECTNAME="$3"
NAME=${OBJECTNAME%_*}
KVER=$(parse_kernel_version "$1" "$2")

KNAME=$(select_kernel_version "${1}" "${2}" "${4:-}" "${5:-}")

cp "r${NAME}_kern.o" "../rnetdata_ebpf_${NAME}.${KNAME}.o"
cp "p${NAME}_kern.o" "../pnetdata_ebpf_${NAME}.${KNAME}.o"

