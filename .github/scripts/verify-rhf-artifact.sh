#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
archive=${1:?usage: verify-rhf-artifact.sh <artifact archive> [rhf|generic] [4.18.0|5.4.17|5.14.0|6.12.0|6.16.2]}
family=${2:-rhf}
kernel_version=${3:-6.12.0}
case "$kernel_version" in
    4.18.0) object_version=4.18 ;;
    5.4.17) object_version=5.4 ;;
    5.14.0) object_version=5.14 ;;
    6.12.0) object_version=6.12 ;;
    6.16.2) object_version=6.16.2 ;;
    *) printf 'unsupported artifact kernel version: %s\n' "$kernel_version" >&2; exit 1 ;;
esac
[[ -f "$archive" ]] || { printf 'artifact not found: %s\n' "$archive" >&2; exit 1; }
case "$family" in
    rhf) rhf_suffix='.rhf'; make_rhf='.rhf' ;;
    generic) rhf_suffix=''; make_rhf='' ;;
    *) printf 'unknown artifact family: %s\n' "$family" >&2; exit 1 ;;
esac

inventory=$(make -s -C "$repo_root/kernel" \
    --eval='print-ebpf-inventory:;@printf "%s\\n%s\\n%s\\nEND\\n" "$(NETDATA_APPS)" "$(NETDATA_RINGBUF_APPS)" "$(NETDATA_ARENA_APPS)"' \
    print-ebpf-inventory KERNEL_VERSION="$kernel_version" RHF="$make_rhf")
mapfile -t app_families <<< "$inventory"
((${#app_families[@]} == 4)) && [[ ${app_families[3]} == END ]] || {
    printf 'could not read expected object families from kernel/Makefile\n' >&2
    exit 1
}

archive_list=$(tar -tf "$archive" | sed 's#^\./##')
expected_object_count=0
for family in "${app_families[@]:0:3}"; do
    read -r -a apps <<< "$family"
    expected_object_count=$((expected_object_count + ${#apps[@]}))
    for app in "${apps[@]}"; do
        for prefix in p r; do
            object="${prefix}netdata_ebpf_${app}.${object_version}${rhf_suffix}.o"
            grep -Fxq "$object" <<< "$archive_list" || { printf 'missing object: %s\n' "$object" >&2; exit 1; }
        done
    done
done
((expected_object_count > 0)) || { printf 'expected object inventory is empty for kernel %s\n' "$kernel_version" >&2; exit 1; }
