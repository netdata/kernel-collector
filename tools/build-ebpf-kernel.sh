#!/bin/sh

log() {
  printf "%s\n" "${1}"
}

error() {
  log "ERROR: ${1}"
}

fail() {
  log "FATAL: ${1}"
  exit 1
}

debug() {
  log "Dropping into a shell for debugging ..."
  exec /bin/sh
}

config() {
  if grep "CONFIG_$2" .config; then
    sed -i "s|.*CONFIG_$2.*|CONFIG_$2=$1|" .config
  else
    echo "CONFIG_$2=$1" >> .config
  fi
}

if [ "$#" -eq 0 ]; then
  log "Usage: $(basename "$0") <kernel_version>"
  exit 1
fi

REQUIRED_KERNEL_CONFIG="KPROBES KPROBES_ON_FTRACE HAVE_KPROBES HAVE_KPROBES_ON_FTRACE KPROBE_EVENTS PERF_EVENT HAVE_PERF_EVENT FTRACE BPF_SYSCALL"

KERNEL_VERSION="${1}"
shift

test -d /usr/src || mkdir -p /usr/src
cd /usr/src || exit 1
if [ ! -f linux-"${KERNEL_VERSION}".tar.xz ]; then
  wget -q https://cdn.kernel.org/pub/linux/kernel/v"$(echo "$KERNEL_VERSION" | cut -f 1 -d '.')".x/linux-"${KERNEL_VERSION}".tar.xz
fi
if [ ! -d linux-"${KERNEL_VERSION}" ]; then
  tar -xf linux-"${KERNEL_VERSION}".tar.xz
fi
rm linux
ln -s linux-"${KERNEL_VERSION}" linux

cd /usr/src/linux || exit 1
zcat /proc/config.gz > .config

for required_kernel_config in ${REQUIRED_KERNEL_CONFIG}; do
  config y "${required_kernel_config}"
done

yes "" | make oldconfig

make
make modules_install

cp arch/x86/boot/bzImage /boot/vmlinuz
cp System.map /boot/System.map
lilo
