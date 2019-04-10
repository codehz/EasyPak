#!/bin/bash
src=$1
tgt=$2
if [ -e build.ninja ]; then
  rm -rf ./*
fi
export CC="musl-gcc"
export AR="gcc-ar"
export NM="gcc-nm"
export RANLIB="gcc-ranlib"
export LDFLAGS="-Os -Wl,--gc-sections -s -Wl,-flto"
export CFLAGS="-Wno-unused-command-line-argument -Os -flto -Wl,-flto -ffunction-sections -fdata-sections"
meson --prefix="${tgt}/libfuse" --default-library=static -Dutils=false -Dexamples=false "${src}/libfuse"
