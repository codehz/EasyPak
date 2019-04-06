#!/bin/bash
src=$1
tgt=$2
if [ -e build.ninja ]; then
  rm -rf ./*
fi
CFLAGS="-I${src}/shim -Os" meson --prefix="${tgt}/libfuse" --default-library=static -Dutils=false "${src}/libfuse"
