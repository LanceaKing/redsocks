#!/bin/sh
set -eu
src=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/redsocks-sni.XXXXXX")
trap 'rm -rf "$build"' EXIT HUP INT TERM
"${CC:-clang}" -std=c99 -Wall -Wextra -Werror -g -O1 \
    -fsanitize=address,undefined -fno-omit-frame-pointer \
    -I"$src" "$src/tls-sni.c" "$src/tests/test_tls_sni.c" -o "$build/test_tls_sni"
"$build/test_tls_sni"
