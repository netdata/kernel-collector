#!/bin/bash

parse_kernel_version() {
  local release="${1}"

  if [[ ! "${release}" =~ ^([0-9]+)\.([0-9]+)(\.([0-9]+))? ]]; then
    return 1
  fi

  printf "%03d%03d%03d" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[4]:-0}"
}

first_kernel() {
    kver=$(parse_kernel_version "${1}")

    ver5_10_0="005010000"
    ver5_11_0="005011000"
    ver7_0_0="007000000"
    ver4_18_0="004018000"
    ver4_17_0="004017000"
    ver4_15_0="004015000"
    ver4_11_0="004011000"
    ver3_10_0="003010000"

    if [ "${kver}" -eq "${ver3_10_0}" ]; then
        kpkg="3.10";
    elif [ "${kver}" -eq "${ver4_18_0}" ]; then
        kpkg="4.18";
    elif [ "${kver}" -ge "${ver7_0_0}" ]; then
        kpkg="7.0";
    elif [ "${kver}" -ge "${ver5_11_0}" ]; then
        kpkg="5.11";
    elif [ "${kver}" -ge "${ver5_10_0}" ]; then
        kpkg="5.10";
    elif [ "${kver}" -ge "${ver4_17_0}" ]; then
        kpkg="4.17";
    elif [ "${kver}" -ge "${ver4_15_0}" ]; then
        kpkg="4.15";
    elif [ "${kver}" -ge "${ver4_11_0}" ]; then
        kpkg="4.11";
    fi

    echo "${kpkg}"
}

first_kernel "${1}"
