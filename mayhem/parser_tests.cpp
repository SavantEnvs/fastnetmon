// Known-answer tests for the NetFlow v5/v9/IPFIX and sFlow v5 parsers: each fixture packet in the
// fuzz seed directories is fed through the real parser and the decoded simple_packet_t fields are
// compared with the values the fixture was built from (see gen_seeds.py).
#include <gtest/gtest.h>

#include <arpa/inet.h>

#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "../src/fastnetmon_types.hpp"
#include "../src/netflow_plugin/netflow_collector.hpp"
#include "../src/sflow_plugin/sflow_collector.hpp"

extern process_packet_pointer netflow_process_func_ptr;
extern process_packet_pointer sflow_process_func_ptr;

// Fixtures are the fuzz seeds; test.sh runs from the repository root.
static const char* FIXTURE_DIR = "mayhem";

static std::vector<simple_packet_t> captured;

static void capture(simple_packet_t& packet) {
    captured.push_back(packet);
}

static std::vector<uint8_t> load(const std::string& target, const std::string& name) {
    std::ifstream in(std::string(FIXTURE_DIR) + "/" + target + "/testsuite/" + name, std::ios::binary);
    EXPECT_TRUE(in.good()) << "missing fixture " << name;
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

static uint32_t addr(const char* text) {
    return inet_addr(text);
}

static bool feed_netflow(const std::string& name) {
    captured.clear();
    netflow_process_func_ptr = capture;
    std::vector<uint8_t> packet = load("fuzz_netflow", name);
    std::string client = "192.0.2.1";
    return process_netflow_packet(packet.data(), packet.size(), client, addr("192.0.2.1"));
}

TEST(netflow_v5, two_flows_are_decoded) {
    ASSERT_TRUE(feed_netflow("v5_two_flows.bin"));
    ASSERT_EQ(captured.size(), 2u);

    EXPECT_EQ(captured[0].src_ip, addr("10.0.0.1"));
    EXPECT_EQ(captured[0].dst_ip, addr("192.168.1.1"));
    EXPECT_EQ(captured[0].source_port, 1234);
    EXPECT_EQ(captured[0].destination_port, 80);
    EXPECT_EQ(captured[0].protocol, (unsigned)IPPROTO_TCP);
    EXPECT_EQ(captured[0].number_of_packets, 10u);
    EXPECT_EQ(captured[0].length, 1500u);
    EXPECT_EQ(captured[0].flags, 0x12);
    EXPECT_EQ(captured[0].src_asn, 65001u);
    EXPECT_EQ(captured[0].dst_asn, 65002u);

    EXPECT_EQ(captured[1].src_ip, addr("10.0.0.2"));
    EXPECT_EQ(captured[1].dst_ip, addr("192.168.1.2"));
    EXPECT_EQ(captured[1].source_port, 53);
    EXPECT_EQ(captured[1].destination_port, 5353);
    EXPECT_EQ(captured[1].protocol, (unsigned)IPPROTO_UDP);
    EXPECT_EQ(captured[1].number_of_packets, 3u);
    EXPECT_EQ(captured[1].length, 300u);
}

TEST(netflow_v5, truncated_packet_is_rejected) {
    std::vector<uint8_t> packet = load("fuzz_netflow", "v5_two_flows.bin");
    packet.resize(60);
    captured.clear();
    netflow_process_func_ptr = capture;
    std::string client = "192.0.2.1";
    EXPECT_FALSE(process_netflow_packet(packet.data(), packet.size(), client, addr("192.0.2.1")));
    EXPECT_EQ(captured.size(), 0u);
}

TEST(netflow_v9, template_then_data_is_decoded) {
    ASSERT_TRUE(feed_netflow("v9_template_and_data.bin"));
    ASSERT_EQ(captured.size(), 1u);
    EXPECT_EQ(captured[0].src_ip, addr("10.0.0.1"));
    EXPECT_EQ(captured[0].dst_ip, addr("192.168.1.1"));
    EXPECT_EQ(captured[0].source_port, 1234);
    EXPECT_EQ(captured[0].destination_port, 80);
    EXPECT_EQ(captured[0].protocol, (unsigned)IPPROTO_TCP);
    EXPECT_EQ(captured[0].number_of_packets, 10u);
    EXPECT_EQ(captured[0].length, 1500u);
}

TEST(netflow_v9, template_alone_yields_no_flows) {
    feed_netflow("v9_template_only.bin");
    EXPECT_EQ(captured.size(), 0u);
}

TEST(ipfix, template_then_data_is_decoded) {
    ASSERT_TRUE(feed_netflow("ipfix_template_and_data.bin"));
    ASSERT_EQ(captured.size(), 1u);
    EXPECT_EQ(captured[0].src_ip, addr("10.0.0.2"));
    EXPECT_EQ(captured[0].dst_ip, addr("192.168.1.2"));
    EXPECT_EQ(captured[0].source_port, 5353);
    EXPECT_EQ(captured[0].destination_port, 53);
    EXPECT_EQ(captured[0].protocol, (unsigned)IPPROTO_UDP);
    EXPECT_EQ(captured[0].number_of_packets, 10u);
    EXPECT_EQ(captured[0].length, 1500u);
}

TEST(sflow_v5, raw_header_sample_is_decoded) {
    captured.clear();
    sflow_process_func_ptr = capture;
    std::vector<uint8_t> datagram = load("fuzz_sflow_v5", "flow_sample_raw_udp.bin");
    parse_sflow_v5_packet(datagram.data(), datagram.size(), addr("172.16.0.1"));
    ASSERT_EQ(captured.size(), 1u);
    EXPECT_EQ(captured[0].src_ip, addr("10.0.0.2"));
    EXPECT_EQ(captured[0].dst_ip, addr("192.168.1.2"));
    EXPECT_EQ(captured[0].source_port, 5353);
    EXPECT_EQ(captured[0].destination_port, 53);
    EXPECT_EQ(captured[0].protocol, (unsigned)IPPROTO_UDP);
    EXPECT_EQ(captured[0].sample_ratio, 2048u);
}
