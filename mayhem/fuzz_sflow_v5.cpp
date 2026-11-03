// Feeds a raw sFlow v5 datagram to the collector's parser; decoded samples go to the real
// process_packet() of fastnetmon_logic.
#include "../src/fastnetmon_logic.hpp"
#include "daemon_state.hpp"
#include "../src/sflow_plugin/sflow_collector.hpp"

extern process_packet_pointer sflow_process_func_ptr;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 4) {
        return -1;
    }

    init_daemon_state_once();

    sflow_process_func_ptr = process_packet;
    parse_sflow_v5_packet(data, size, 128);
    return 0;
}
