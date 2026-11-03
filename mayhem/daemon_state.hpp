// The collectors hand decoded flows to process_packet(), which assumes the daemon's main() already built
// the monitored-network lookup trees and preallocated the per-host counters. Do the same here, once,
// with a few small networks (the ones the seed packets use) so flows reach the accounting code.
#pragma once

#include "../src/fast_library.hpp"
#include "../src/libpatricia/patricia.hpp"

extern patricia_tree_t *lookup_tree_ipv4, *whitelist_tree_ipv4;
extern patricia_tree_t *lookup_tree_ipv6, *whitelist_tree_ipv6;

void subnet_vectors_allocator(prefix_t* prefix, void* data);

static void init_daemon_state_once() {
    static bool initialized = false;

    if (initialized) {
        return;
    }

    initialized = true;

    lookup_tree_ipv4    = New_Patricia(32);
    whitelist_tree_ipv4 = New_Patricia(32);
    lookup_tree_ipv6    = New_Patricia(128);
    whitelist_tree_ipv6 = New_Patricia(128);

    make_and_lookup(lookup_tree_ipv4, "10.0.0.0/24");
    make_and_lookup(lookup_tree_ipv4, "192.168.1.0/24");
    make_and_lookup_ipv6(lookup_tree_ipv6, "2001:db8::/32");

    patricia_process(lookup_tree_ipv4, subnet_vectors_allocator);
}
