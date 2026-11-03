#!/usr/bin/env bash
#
# Builds the FastNetMon collector libraries (NetFlow v5/v9, IPFIX, sFlow v5 parsers plus the traffic
# logic behind them) three times: sanitized+coverage for the libFuzzer targets, sanitized for the
# standalone reproducers, and with normal flags for the gtest oracle that mayhem/test.sh runs.
#
# Upstream's CMake needs libelf/libbpf/capnp/mongo and friends for the full daemon; the parsers do not,
# so the sources are compiled directly. Nothing is fetched: protobuf/gRPC code is generated locally.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS SRC

cd "$SRC"

BUILD="$SRC/src/build/mayhem"
GEN="$BUILD/gen"
PB="$GEN/traffic_output_formats/protobuf"
mkdir -p "$PB"

# fast_platform.hpp is normally produced by CMake from fast_platform.h.template
sed -e 's/\${FASTNETMON_APPLICATION_VERSION}/1.2.10/' \
    -e 's#\${FASTNETMON_PID_PATH}#/var/run/fastnetmon.pid#' \
    -e 's#\${FASTNETMON_CONFIGURATION_PATH}#/etc/fastnetmon.conf#' \
    -e 's#\${FASTNETMON_LOG_FILE_PATH}#/var/log/fastnetmon.log#' \
    -e 's#\${FASTNETMON_ATTACK_DETAILS_FOLDER}#/var/log/fastnetmon_attacks#' \
    -e 's#\${FASTNETMON_NOTIFY_SCRIPT_PATH_DEFAULT}#/usr/local/bin/notify_about_attack.sh#' \
    -e 's#\${FASTNETMON_NETWORK_WHITELIST_PATH}#/etc/networks_whitelist#' \
    -e 's#\${FASTNETMON_NETWORKS_LIST_PATH}#/etc/networks_list#' \
    -e 's#\${FASTNETMON_BACKTRACE_PATH}#/var/log/fastnetmon_backtrace.dump#' \
    -e 's#\${FASTNETMON_WHITELIST_RULES_PATH}#/etc/whitelist_rules#' \
    src/fast_platform.h.template > "$GEN/fast_platform.hpp"

protoc -I src/traffic_output_formats/protobuf --cpp_out="$PB" src/traffic_output_formats/protobuf/traffic_data.proto
protoc -I src --cpp_out="$GEN" --grpc_out="$GEN" --plugin=protoc-gen-grpc="$(command -v grpc_cpp_plugin)" \
    src/fastnetmon_internal_api.proto

LIB_SRCS=(
    libpatricia/patricia.cpp fast_library.cpp ipfix_fields/ipfix_rfc.cpp
    netflow_plugin/ipfix_collector.cpp netflow_plugin/netflow_v9_collector.cpp
    netflow_plugin/netflow_v5_collector.cpp netflow_plugin/netflow.cpp netflow_plugin/netflow_template.cpp
    netflow_plugin/netflow_template_storage.cpp netflow_plugin/netflow_collector.cpp
    bgp_protocol.cpp iana_ip_protocols.cpp bgp_protocol_flow_spec.cpp fastnetmon_logic.cpp
    network_data_structures.cpp speed_counters.cpp simple_packet_parser_ng.cpp libsflow/libsflow.cpp
    sflow_plugin/sflow_collector.cpp example_plugin/example_collector.cpp actions/exabgp_action.cpp
    traffic_output_formats/protobuf/protobuf_traffic_format.cpp filter.cpp api.cpp
    metrics/graphite.cpp metrics/influxdb.cpp
)
GEN_SRCS=(
    "$GEN/fastnetmon_internal_api.pb.cc" "$GEN/fastnetmon_internal_api.grpc.pb.cc"
    "$PB/traffic_data.pb.cc"
)

INCLUDES=(-I"$GEN" -I"$PB" -I"$SRC/src")
LIBS=(-lboost_system -lboost_thread -lboost_regex -lboost_program_options -lboost_serialization -llog4cpp
      $(pkg-config --libs grpc++ protobuf) -lpthread)

# The parsers read network-order integers through casted packet pointers (misaligned loads, harmless on
# x86/arm64), which would halt every run on the first one and hide the memory-safety bugs behind them, so the
# UBSan alignment check is relaxed for the library. patricia.cpp also allocates IPv4 prefixes as the shorter
# prefix4_t and reads them as prefix_t, which trips the object-size check on every prefix; relaxed there only.
# build_objects <outdir> <flags...>: compile the library once with the given flags. fastnetmon.cpp
# supplies the daemon's global state that the logic objects reference; its main() is renamed away.
build_objects() {
    local out="$1"; shift
    mkdir -p "$out"
    {
        for s in "${LIB_SRCS[@]}"; do printf '%s\n' "$SRC/src/$s"; done
        printf '%s\n' "${GEN_SRCS[@]}"
    } | OUT="$out" FLAGS="$*" xargs -P "$MAYHEM_JOBS" -I{} bash -c \
        'RELAX=-fno-sanitize=alignment; case "$1" in */libpatricia/patricia.cpp) RELAX="$RELAX,object-size";; esac
         $CXX -std=c++20 -w $FLAGS $RELAX "${@:2}" -c "$1" -o "$OUT/$(basename "$1").o"' _ {} "${INCLUDES[@]}"
    $CXX -std=c++20 -w "$@" -include abstract_subnet_counters.hpp -Dmain=fastnetmon_original_main \
        "${INCLUDES[@]}" -c "$SRC/src/fastnetmon.cpp" -o "$out/fastnetmon_globals.o"
}

# 1) libFuzzer binaries: sanitized + coverage-instrumented project code
FUZZ_OBJ="$BUILD/obj-fuzz"
rm -rf "$FUZZ_OBJ"
build_objects "$FUZZ_OBJ" $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$BUILD/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$BUILD/standalone_main.o"

# 2) standalone reproducers: same harnesses, sanitized, no libFuzzer runtime
STANDALONE_OBJ="$BUILD/obj-standalone"
rm -rf "$STANDALONE_OBJ"
build_objects "$STANDALONE_OBJ" $SANITIZER_FLAGS $DEBUG_FLAGS -O1

for t in fuzz_netflow fuzz_sflow_v5; do
    $CXX -std=c++20 -w $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1 "${INCLUDES[@]}" \
        "$SRC/mayhem/$t.cpp" "$FUZZ_OBJ"/*.o "$BUILD/lsan_off.o" $LIB_FUZZING_ENGINE "${LIBS[@]}" \
        -o "$SRC/$t"
    $CXX -std=c++20 -w $SANITIZER_FLAGS $DEBUG_FLAGS -O1 "${INCLUDES[@]}" \
        "$SRC/mayhem/$t.cpp" "$STANDALONE_OBJ"/*.o "$BUILD/lsan_off.o" "$BUILD/standalone_main.o" "${LIBS[@]}" \
        -o "$SRC/$t-standalone"
done

# 3) gtest oracle with the project's normal flags: upstream's own tests plus known-answer parser tests.
#    upstream's fastnetmon_tests.cpp defines its own `logger`, which the daemon globals already provide.
TEST_OBJ="$BUILD/obj-test"
rm -rf "$TEST_OBJ"
build_objects "$TEST_OBJ" -O2 $COVERAGE_FLAGS
$CXX -std=c++20 -w -O2 $COVERAGE_FLAGS -Dlogger=upstream_test_logger "${INCLUDES[@]}" \
    -c "$SRC/src/fastnetmon_tests.cpp" -o "$BUILD/upstream_tests.o"
$CXX -std=c++20 -w -O2 $COVERAGE_FLAGS "${INCLUDES[@]}" -c "$SRC/mayhem/parser_tests.cpp" -o "$BUILD/parser_tests.o"
$CXX -O2 $COVERAGE_FLAGS "$BUILD/upstream_tests.o" "$BUILD/parser_tests.o" "$TEST_OBJ"/*.o \
    -lgtest -lgtest_main "${LIBS[@]}" -o "$BUILD/fastnetmon_gtests"
