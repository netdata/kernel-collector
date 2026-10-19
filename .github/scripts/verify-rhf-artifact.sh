#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
archive=${1:?usage: verify-rhf-artifact.sh <6.12.rhf archive>}
family=${2:-rhf}
[[ -f "$archive" ]] || { printf 'artifact not found: %s\n' "$archive" >&2; exit 1; }
case "$family" in
    rhf) rhf_suffix='.rhf'; make_rhf='.rhf' ;;
    generic) rhf_suffix=''; make_rhf='' ;;
    *) printf 'unknown artifact family: %s\n' "$family" >&2; exit 1 ;;
esac

inventory=$(make -s -C "$repo_root/kernel" \
    --eval='print-ebpf-inventory:;@printf "%s\\n%s\\n%s\\n" "$(NETDATA_APPS)" "$(NETDATA_RINGBUF_APPS)" "$(NETDATA_ARENA_APPS)"' \
    print-ebpf-inventory KERNEL_VERSION=6.12.0 RHF="$make_rhf")
mapfile -t app_families <<< "$inventory"
((${#app_families[@]} == 3)) || { printf 'could not read expected object families from kernel/Makefile\n' >&2; exit 1; }

archive_list=$(tar -tf "$archive")
for family in "${app_families[@]}"; do
    read -r -a apps <<< "$family"
    for app in "${apps[@]}"; do
        for prefix in p r; do
            object="${prefix}netdata_ebpf_${app}.6.12${rhf_suffix}.o"
            grep -Fxq "$object" <<< "$archive_list" || { printf 'missing object: %s\n' "$object" >&2; exit 1; }
        done
    done
done
