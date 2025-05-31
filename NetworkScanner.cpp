//NetworkScanner.cpp
// Created by HomePC on 5/23/2025.
//
#include "NetworkScanner.h"
#include "PacketStructs.h" // Assumed to define ether_header, arp_header
#include <iostream>
#include <chrono>
#include <thread>
#include <sstream>
#include <iomanip>
#include <algorithm> // For std::transform, std::copy_n
#include <array>     // For std::array<u_char, 6>

// Include the necessary headers for network functions and types
#ifdef _WIN32
#include <winsock2.h> // For inet_addr, inet_ntoa, htons etc.
#include <ws2tcpip.h> // For inet_ntop in a more modern approach
#else
#include <arpa/inet.h>  // For ntohs, ntohl, inet_ntop etc.
#include <netinet/in.h> // For INET_ADDRSTRLEN
#endif

// Define constants used in NetworkScanner.cpp
#define ETHER_TYPE_ARP    0x0806
#define ETHER_TYPE_IP     0x0800 // Not directly used in arpHandler but good for context
#define ARP_PRO_IP        0x0800
#define ARP_HRD_ETHER     1
#define ARP_OP_REPLY      2
#define ARP_OP_REQUEST    1

// Helper function to convert a MAC address array to a string
std::string macToString(const std::array<u_char, 6> &mac) {
    std::ostringstream ss;
    for (size_t i = 0; i < mac.size(); ++i) {
        if (i != 0) ss << ":";
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
    }
    std::string mac_str = ss.str();
    std::transform(mac_str.begin(), mac_str.end(), mac_str.begin(), ::tolower);
    return mac_str;
}

// Constructor for NetworkScanner
NetworkScanner::NetworkScanner() {
    std::cout<< "NetworkScanner::NetworkScanner()"<<std::endl;
}

// Destructor for NetworkScanner
NetworkScanner::~NetworkScanner() {
    std::cout<< "NetworkScanner::~NetworkScanner()"<<std::endl;
};

// Performs an ARP scan over a specified IP range
bool NetworkScanner::performArpScan(pcap_t *pcap_handle, const std::vector<u_char> &source_mac, const std::string source_ip_str, const std::string network_prefix, int start_host_ip, int end_host_ip) {
    // Input validation
    if (!pcap_handle) {
        std::cerr << "Error performing ARP scan. pcap_handle is null" << std::endl;
        return false;
    }
    if (source_mac.size() != 6) {
        std::cerr << "Error performing ARP scan. source_mac is not 6 bytes" << std::endl;
        return false;
    }
    if (start_host_ip > end_host_ip) {
        std::cerr << "Error performing ARP scan. start_host_ip (" << start_host_ip << ") is greater than end_host_ip (" << end_host_ip << ")" << std::endl;
        return false;
    }
    discovered_hosts_.clear(); // Clear previously discovered hosts

    std::cout << "\nNetworkScanner: Starting ARP scan for " << network_prefix << "."
              << start_host_ip << " to " << network_prefix << "." << end_host_ip << "..." << std::endl;

    // Apply filter to capture only ARP replies to our MAC
    // This filter helps reduce the number of packets processed by arpHandler
    std::array<u_char, 6> src_mac_arr;
    std::copy(source_mac.begin(), source_mac.end(), src_mac_arr.begin());
    std::string filter_str = "arp and ether dst host " + macToString(src_mac_arr); // Filter for packets destined to our MAC

    struct bpf_program filter;
    char errbuf[PCAP_ERRBUF_SIZE]; // Not used here, pcap_geterr provides error

    // Compile and apply the ARP filter
    if (pcap_compile(pcap_handle, &filter, filter_str.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling ARP filter: " << pcap_geterr(pcap_handle) << std::endl;
        return false;
    }

    if (pcap_setfilter(pcap_handle, &filter) == -1) {
        std::cerr << "Error setting ARP filter: " << pcap_geterr(pcap_handle) << std::endl;
        pcap_freecode(&filter);
        return false;
    }

    pcap_freecode(&filter); // Free the filter code after it's applied

    u_char* user_data = reinterpret_cast<u_char*>(this); // Pass 'this' pointer as user data to arpHandler

    // Send ARP requests to each host in the specified range
    for (int i = start_host_ip; i <= end_host_ip; ++i) {
        std::string target_ip = network_prefix + "." + std::to_string(i);
        std::vector<u_char> arp_packet_buffer;
        if (buildArpRequestPacket(source_mac, source_ip_str, target_ip, arp_packet_buffer)) {
            if (pcap_sendpacket(pcap_handle, arp_packet_buffer.data(), arp_packet_buffer.size()) == -1) {
                std::cerr << "Error sending ARP request packet for " << target_ip << ": " << pcap_geterr(pcap_handle) << std::endl;
                // Log the error and continue to the next IP
            }
            // std::cout << "Sent ARP request for " << target_ip << std::endl; // Too verbose, uncomment for debugging
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Small delay to avoid overwhelming the network
    }

    std::cout << "NetworkScanner: Listening for ARP replies (using pcap_dispatch with timeout)..." << std::endl;

    // Use pcap_dispatch for a non-blocking or timed packet processing.
    // The read timeout set in pcap_open_live determines how long pcap_dispatch waits for packets.
    // We'll loop for a total duration (e.g., 2 seconds) to collect replies.
    auto start_time = std::chrono::high_resolution_clock::now();
    const auto scan_timeout = std::chrono::seconds(2); // Listen for 2 seconds for replies

    // Loop until timeout or enough packets are processed
    int packets_processed;
    do {
        // -1 means process all packets currently in the buffer or until timeout
        packets_processed = pcap_dispatch(pcap_handle, -1, arpHandler, user_data);
        if (packets_processed == -1) {
            std::cerr << "Error in pcap_dispatch: " << pcap_geterr(pcap_handle) << std::endl;
            break; // Exit loop on dispatch error
        }
        // Small sleep to yield control and allow other threads/processes to run
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    } while (std::chrono::high_resolution_clock::now() - start_time < scan_timeout);

    // Clear the filter after the ARP scan is complete to capture all packets again
    struct bpf_program empty_filter;
    const char* empty_filter_str = ""; // Match all packets

    if (pcap_compile(pcap_handle, &empty_filter, empty_filter_str, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling empty filter: " << pcap_geterr(pcap_handle) << std::endl;
    } else {
        if (pcap_setfilter(pcap_handle, &empty_filter) == -1) {
            std::cerr << "Error clearing filter: " << pcap_geterr(pcap_handle) << std::endl;
        }
        pcap_freecode(&empty_filter); // Free the filter code
    }

    std::cout << "NetworkScanner: ARP scan finished." << std::endl;
    return true;
}

// Prints the discovered hosts
void NetworkScanner::printDiscoveredHosts() {
    if (discovered_hosts_.empty()) {
        std::cout << "No hosts discovered during ARP scan." << std::endl;
        return;
    }
    std::cout<<"\nDiscovered hosts:"<<std::endl;
    std::cout << std::left << std::setw(18) << "IP Address" << "MAC Address" << std::endl;
    std::cout << std::string(30, '-') << std::endl;
    for (const auto &host : discovered_hosts_) {
        std::cout <<std::left<<std::setw(18) << host.first << " (" << host.second << ")" << std::endl;
    }
    std::cout << std::string(30, '-') << std::endl;
}

std::map<std::string, std::string> NetworkScanner::getDiscoveredHosts() {
    if (discovered_hosts_.empty()) {
        std::cout << "No hosts discovered during ARP scan." << std::endl;
    }
    return discovered_hosts_;
}


// Builds an ARP request packet
bool NetworkScanner::buildArpRequestPacket(const std::vector<u_char> &source_mac, const std::string &source_ip_str,
                                           const std::string &target_ip_str, std::vector<u_char> &packet_buffer)
{
    // Resize buffer to fit Ethernet header + ARP header
    packet_buffer.resize(sizeof(ether_header) + sizeof(arp_header));
    ether_header *eth = reinterpret_cast<ether_header *>(packet_buffer.data());
    arp_header *arp = reinterpret_cast<arp_header *>(packet_buffer.data() + sizeof(ether_header));

    // Ethernet header
    memset(eth->ether_dhost, 0xff, 6); // Broadcast MAC address
    memcpy(eth->ether_shost, source_mac.data(), 6); // Source MAC address
    eth->ether_type = htons(ETHER_TYPE_ARP); // ARP ethertype (0x0806)

    // ARP header
    arp->arp_hrd = htons(ARP_HRD_ETHER); // Hardware type: Ethernet (1)
    arp->arp_pro = htons(ARP_PRO_IP); // Protocol type: IPv4 (0x0800)
    arp->arp_hln = 6; // Hardware address length: 6 bytes (MAC)
    arp->arp_pln = 4; // Protocol address length: 4 bytes (IPv4)
    arp->arp_op = htons(ARP_OP_REQUEST); // Operation: ARP Request (1)

    memcpy(arp->arp_sha, source_mac.data(), 6); // Sender hardware address (MAC)
    // Convert source IP string to binary and copy
    if (inet_pton(AF_INET, source_ip_str.c_str(), arp->arp_spa) != 1) {
        std::cerr << "Invalid source IP: " << source_ip_str << std::endl;
        return false; // Invalid source IP
    }
    memset(arp->arp_tha, 0, 6); // Target hardware address (unknown for request, set to 0)
    // Convert target IP string to binary and copy
    if (inet_pton(AF_INET, target_ip_str.c_str(), arp->arp_tpa) != 1) {
        std::cerr << "Invalid target IP: " << target_ip_str << std::endl;
        return false; // Invalid target IP
    }

    return true;
}

// Callback function for pcap_dispatch to handle captured packets
void NetworkScanner::arpHandler(u_char *user_data, const pcap_pkthdr *pkthdr, const u_char *packet) {
    NetworkScanner *scanner = reinterpret_cast<NetworkScanner*>(user_data);

    // Ensure packet is long enough for at least an Ethernet header
    if (pkthdr->caplen < sizeof(ether_header)) {
        std::cerr << "ARP Handler: Packet too short for Ethernet header. caplen: " << pkthdr->caplen << std::endl;
        return;
    }

    const ether_header *eth_h = reinterpret_cast<const ether_header *>(packet);
    // std::cout << "ETH packet received: " << static_cast<const void*>(eth_h) << ", packet data: "
    //           << static_cast<const void*>(packet) << ", caplen: " << pkthdr->caplen << std::endl; // Debugging line

    u_short eth_type = ntohs(eth_h->ether_type);
    size_t ethernet_header_len = sizeof(ether_header); // Initial assumed length

    // Check for 802.1Q VLAN tag (EtherType 0x8100)
    if (eth_type == 0x8100) {
        // The actual EtherType is located 4 bytes after the standard ether_type field.
        // We need to ensure the packet is long enough to contain the VLAN tag and the subsequent EtherType.
        if (pkthdr->caplen < sizeof(ether_header) + 4) {
            std::cerr << "ARP Handler: Packet too short for VLAN tag and subsequent EtherType. caplen: " << pkthdr->caplen << std::endl;
            return;
        }
        // Advance the pointer past the original ether_header to read the VLAN tag and then the true eth_type.
        // The true EtherType is at offset sizeof(ether_header) + 2 (after the TCI field of the VLAN header).
        const u_char *vlan_packet_ptr = packet + sizeof(ether_header);
        eth_type = ntohs(*reinterpret_cast<const u_short *>(vlan_packet_ptr + 2)); // Read the true EtherType after the VLAN TCI
        ethernet_header_len += 4; // Add 4 bytes for the VLAN tag
    }

    // Now, check the (potentially adjusted) Ethernet type
    if (eth_type != ETHER_TYPE_ARP) {
        // std::cerr << "ARP Handler: Ethernet type is not ARP (after VLAN check). eth_type: " << eth_type << std::endl; // Debugging line
        return; // Not an ARP packet
    }

    // Ensure the packet is long enough for the full Ethernet and ARP headers
    if (pkthdr->caplen < ethernet_header_len + sizeof(arp_header)) {
        std::cerr << "Error processing ARP packet. Packet length is less than minimum ARP packet length (after VLAN check)" << std::endl;
        return;
    }

    const arp_header *arp_h = reinterpret_cast<const arp_header *>(packet + ethernet_header_len);

    // std::cout << "ARP packet received: " << static_cast<const void*>(arp_h)
    //           << ", packet data: " << static_cast<const void*>(packet) << std::endl; // Debugging line

    // Check if it's an ARP Reply (opcode 2)
    if (ntohs(arp_h->arp_op) != ARP_OP_REPLY) {
        return; // Not an ARP Reply
    }

    // It's an ARP reply, extract sender IP and MAC
    char sender_ip_str[INET_ADDRSTRLEN]; // Buffer for IP address string
    // Convert sender IP from binary to string
    if (inet_ntop(AF_INET, arp_h->arp_spa, sender_ip_str, INET_ADDRSTRLEN) == nullptr) {
        std::cerr << "Error converting sender IP to string in arpHandler." << std::endl;
        return;
    }
    const std::string sender_ip = sender_ip_str;

    std::array<u_char, 6> sender_mac_arr; // Array for MAC address
    std::copy_n(arp_h->arp_sha, 6, sender_mac_arr.begin()); // Copy sender MAC
    const std::string sender_mac = macToString(sender_mac_arr); // Convert MAC to string

    // Add to discovered hosts map if not already present
    if (scanner->discovered_hosts_.find(sender_ip) == scanner->discovered_hosts_.end()) {
        scanner->discovered_hosts_[sender_ip] = sender_mac;
        std::cout << "NetworkScanner: Discovered Device: IP=" << sender_ip << ", MAC=" << sender_mac << std::endl;
    }
}
