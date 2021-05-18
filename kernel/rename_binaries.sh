#!/bin/sh

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "Give kernel as parameter: kernel major version, kernel minor version, and function name"
    exit 1
fi

VER_MAJOR="$1"
VER_MINOR="$2"
OBJECTNAME="$3"
NAME=${OBJECTNAME%_*}

cp "r${NAME}_kern.o" "../rnetdata_ebpf_${NAME}.${VER_MAJOR}.${VER_MINOR}.o"
cp "p${NAME}_kern.o" "../pnetdata_ebpf_${NAME}.${VER_MAJOR}.${VER_MINOR}.o"
