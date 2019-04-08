#!/bin/bash
src=$1
tgt=$2
if [ -e build.ninja ]; then
  rm -rf ./*
fi
export LDFLAGS="-Os -Wl,--gc-sections -s"
export CFLAGS="-I${src}/shim -Wno-unused-command-line-argument -Os -ffunction-sections -fdata-sections"
meson --prefix="${tgt}/libfuse" --default-library=static -Dutils=false "${src}/libfuse"
