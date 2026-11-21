#!/bin/bash
# Binary size of citius-rust as a C client sees it (docs/performance.md F11).
#
#   benches/size/measure.sh [OUT_DIR]
#
# Builds the library in three release profiles (default; fat LTO with one
# codegen unit; the same with opt-level=s), links two C clients statically
# with dead-stripping (benches/size/min_aead.c: one AEAD encrypt; the bench
# harness: every operation), and compares them with a RustCrypto-only
# baseline (benches/size/baseline: AES-GCM only, and the same algorithms as
# our provider). Prints file, stripped and __text sizes; macOS (size -m).
set -eu
cd "$(dirname "$0")/../.."
OUT=${1:-target/size}
mkdir -p "$OUT/link"
I=../citius-c-api/include/agc
NATIVE=(-liconv -lSystem -lc -lm) # cargo rustc --crate-type staticlib -- --print native-static-libs
cargo build --release -q
CARGO_PROFILE_RELEASE_LTO=fat CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 cargo build --release -q --target-dir "$OUT/lto"
CARGO_PROFILE_RELEASE_LTO=fat CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 CARGO_PROFILE_RELEASE_OPT_LEVEL=s \
    cargo build --release -q --target-dir "$OUT/lto-s"
sizes() { cp "$2" "$2.stripped"; strip "$2.stripped" 2>/dev/null || strip -x "$2.stripped"
    printf "%-34s file %9d  stripped %9d  __text %9d\n" "$1" "$(stat -f%z "$2")" "$(stat -f%z "$2.stripped")" \
        "$(size -m "$2" | awk '/Section __text/{print $3}')"; }
for v in default:target/release lto:$OUT/lto/release lto-s:$OUT/lto-s/release; do
    n=${v%%:*}; d=${v#*:}
    cp "$d/libagilecrypto.dylib" "$OUT/link/lib-$n.dylib"
    sizes "$n libagilecrypto.dylib" "$OUT/link/lib-$n.dylib"
    for p in min_aead bench; do
        src=benches/size/min_aead.c; [ $p = bench ] && src=benches/c/bench.c
        cc -std=c11 -O2 -I $I -o "$OUT/link/$p-$n" $src "$d/libagilecrypto.a" "${NATIVE[@]}" -Wl,-dead_strip -pthread 2>/dev/null
        sizes "$n static $p" "$OUT/link/$p-$n"
    done
done
(cd benches/size/baseline && cargo build --release -q --target-dir "../../../$OUT/baseline" && cp "../../../$OUT/baseline/release/librcbase.a" "../../../$OUT/link/librc-aes.a" \
    && cargo build --release -q --features all --target-dir "../../../$OUT/baseline" && cp "../../../$OUT/baseline/release/librcbase.a" "../../../$OUT/link/librc-all.a")
for p in aes all; do
    cc -O2 -o "$OUT/link/c_$p" benches/size/baseline/c_$p.c "$OUT/link/librc-$p.a" "${NATIVE[@]}" -Wl,-dead_strip 2>/dev/null
    sizes "RustCrypto only, $p" "$OUT/link/c_$p"
done
echo; python3 -I benches/size/crate_sizes.py target/release/libagilecrypto.dylib __text __data
