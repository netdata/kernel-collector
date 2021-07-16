#!/bin/bash

parse_kernel_version() {
  r="${1}"

  read -r -a p <<< "$(echo "${r}" | tr '.' ' ')"

  printf "%03d%03d%03d" "${p[0]}" "${p[1]}" "${p[2]}"
}

first_kernel() {
    kver=$(parse_kernel_version "${1}")

    ver5_10_0="005010000"
    ver5_11_0="005011000"
    ver4_18_0="004018000"
    ver4_17_0="004017000"
    ver4_15_0="004015000"
    ver4_11_0="004011000"
    ver3_10_0="003010000"

    if [ "${kver}" -eq "${ver3_10_0}" ]; then
        kpkg="3.10";
    elif [ "${kver}" -eq "${ver4_18_0}" ]; then
        kpkg="4.18";
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
