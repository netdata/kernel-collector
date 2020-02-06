#!/bin/sh

set -e

prepare() {
  (
    apk add --no-cache -U \
      build-base \
      autoconf \
      automake \
      coreutils \
      pkgconfig \
      bc \
      \
      elfutils-dev \
      clang \
      clang-dev \
      llvm \
      rsync \
      bison \
      flex \
      tar \
      xz #libelf-dev \

    mkdir -p /usr/src
    cd /usr/src || exit 1

    # 5.4.x
    #wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.4.17.tar.xz
    #tar -xvf linux-5.4.17.tar.xz
    #ln -s linux-5.4.17 linux

    # 4.19.x
    wget https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.19.101.tar.xz
    tar -xvf linux-4.19.101.tar.xz
    ln -s linux-4.19.101 linux

    cd linux || exit 1
    make defconfig
    make prepare
    make scripts
    make headers_install
  ) || return 1
}

build() {
  (
    cd user || exit 1
    make CFLAGS='-fno-stack-protector -I /usr/src/linux/usr/include'
  ) || return 1
}

if ! prepare; then
  echo "ERROR: Prepration failed ..."
  if [ -t 1 ]; then
    echo "Dropping into a shell ..."
    exec /bin/sh
  fi
fi

if ! build; then
  echo "ERROR: Build failed ..."
  if [ -t 1 ]; then
    echo "Dropping into a shell ..."
    exec /bin/sh
  fi
fi
