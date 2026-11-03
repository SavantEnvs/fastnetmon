// Feeds a raw NetFlow v5/v9 or IPFIX datagram to the collector's parser; decoded flows go to the
// real process_packet() of fastnetmon_logic.
#include <string>
#include <vector>

#include "../src/fastnetmon_logic.hpp"
#include "daemon_state.hpp"
#include "../src/netflow_plugin/netflow_collector.hpp"

extern process_packet_pointer netflow_process_func_ptr;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // The parser reads the 16-bit version field unconditionally
    if (size < 2) {
        return -1;
    }

    init_daemon_state_once();

    netflow_process_func_ptr = process_packet;

    std::string client_ip = "192.168.0.1";
    std::vector<uint8_t> packet(data, data + size);
    process_netflow_packet(packet.data(), packet.size(), client_ip, 128);
    return 0;
}
