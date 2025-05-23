//
// Created by HomePC on 5/22/2025.
// Packetparser.cpp
//
#include "PacketParser.h"
#include <sstream>
#include <iomanip>
#include <vector> // Required for std::vector<u_char>

// Include the necessary headers for network functions and types
#ifdef _WIN32
#include <winsock2.h> // For u_char, u_short, u_int, in_addr (Windows)
#include <ws2tcpip.h> // For inet_ntop
#else
#include <arpa/inet.h>  // For ntohs, ntohl, inet_ntop etc.
#include <netinet/in.h> // For INET6_ADDRSTRLEN
#endif

// Prefer constexpr over #define for type safety and scoping
constexpr u_short ETHER_TYPE_IP_V4    = 0x0800;
constexpr u_short ETHER_TYPE_ARP      = 0x0806;
constexpr u_short ETHER_TYPE_IPV6     = 0x86DD;
constexpr u_short ETHER_TYPE_VLAN     = 0x8100;
constexpr u_short ETHER_TYPE_REVARP   = 0x8035; // Corrected RE_VARP definition

constexpr u_char IP_PROTOCOL_TCP   = 0x06;
constexpr u_char IP_PROTOCOL_UDP   = 0x11;
constexpr u_char IP_PROTOCOL_ICMP  = 0x01;

constexpr int ETHER_ADDR_LEN_C = 6;

constexpr u_int IP_FLAG_RESERVED = 0x4;  // bit 2
constexpr u_int IP_FLAG_DF       = 0x2;  // bit 1 (Don't Fragment)
constexpr u_int IP_FLAG_MF       = 0x1;  // bit 0 (More Fragments)
// Define TCP flags if not already defined
constexpr u_char TH_FIN_C  = 0x01;
constexpr u_char TH_SYN_C  = 0x02;
constexpr u_char TH_RST_C  = 0x04;
constexpr u_char TH_PSH_C  = 0x08;
constexpr u_char TH_ACK_C  = 0x10;
constexpr u_char TH_URG_C  = 0x20;
constexpr u_char TH_ECE_C  = 0x40;
constexpr u_char TH_CWR_C  = 0x80;

PacketParser::PacketParser() = default;

// Helper to get ICMP type name
const char *PacketParser::getIcmpTypeName(u_char type, u_char code) {
    switch (type) {
        case 0: return "Echo Reply";
        case 3: return "Destination Unreachable";
        case 4: return "Source Quench";
        case 5: return "Redirect";
        case 8: return "Echo Request";
        case 9: return "Router Advertisement";
        case 10: return "Router Solicitation";
        case 11: return "Time Exceeded";
        case 12: return "Parameter Problem";
        case 13: return "Timestamp Request";
        case 14: return "Timestamp Reply";
        case 15: return "Information Request";
        case 16: return "Information Reply";
        case 17: return "Address Mask Request";
        case 18: return "Address Mask Reply";
        default: return "Unknown";
    }
}

// Helper to get ARP opcode name
const char *PacketParser::getArpOpcode(u_char opcode) {
    switch (ntohs(opcode)) {
        case 1: return "Request";
        case 2: return "Reply";
        case 3: return "Request Reverse"; // RARP Request
        case 4: return "Reply Reverse"; // RARP Reply
        default: return "Unknown";
    }
}


void PacketParser::printMacAddress(const u_char *mac, std::ostream &os) {
    os << std::hex << std::setfill('0');
    for (int i = 0; i < ETHER_ADDR_LEN_C; ++i) { // Use constexpr length
        os << std::setw(2) << static_cast<int>(mac[i]);
        if (i < ETHER_ADDR_LEN_C - 1) {
            os << ":";
        }
    }
    os << std::dec << std::setfill(' ');
}

void PacketParser::printIpAddress(const u_char *ip, std::ostream &os) {
    os << static_cast<int>(ip[0]) << "." << static_cast<int>(ip[1]) << "." << static_cast<int>(ip[2]) << "." << static_cast<int>(ip[3]);
}

void PacketParser::printHex(const u_char *data, int len, std::ostream &os) {
    os << std::hex << std::setfill('0');
    for (int i = 0; i < len; ++i) {
        os << std::setw(2) << static_cast<int>(data[i]);
    }
    os << std::dec << std::setfill(' ');
}

void PacketParser::parseEthernet(const u_char *packet, const u_int packet_len, std::ostream &os) {
    if (packet_len < ETHER_HDR_LEN_C) { // Use constexpr
        os << "  Packet too short for Ethernet header." << std::endl;
        return;
    }

    const auto eth_header = reinterpret_cast<const struct ether_header*>(packet);

    // Lambda for formatting MAC - good!
    auto formatMAC = [](const u_char *mac) {
        std::ostringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < ETHER_ADDR_LEN_C; ++i) { // Use constexpr length
            if (i > 0) ss << ":";
            ss << std::setw(2) << static_cast<int>(mac[i]);
        }
        return ss.str();
    };

    os << "Ethernet Header" << std::endl;
    os << "  Destination MAC: " << formatMAC(eth_header->ether_dhost) << std::endl;
    os << "  Source MAC:      " << formatMAC(eth_header->ether_shost) << std::endl;

    const u_short eth_type = ntohs(eth_header->ether_type);
    os << "  EtherType:       0x" << std::hex << eth_type << std::dec;

    switch (eth_type) {
        case ETHER_TYPE_IP_V4:    os << " (IPv4)"; break;
        case ETHER_TYPE_IPV6:     os << " (IPv6)"; break;
        case ETHER_TYPE_ARP:      os << " (ARP)";  break;
        case ETHER_TYPE_REVARP:   os << " (Reverse ARP)"; break; // Use corrected name
        case ETHER_TYPE_VLAN:     os << " (VLAN-tagged)"; break;
        default:                  os << " (Unknown)"; break;
    }
    os << std::endl;
}


const char* protocolName(u_char p) {
    switch (p) {
        case IP_PROTOCOL_TCP:  return "TCP";
        case IP_PROTOCOL_UDP:  return "UDP";
        case IP_PROTOCOL_ICMP: return "ICMP";
        default:              return "Unknown";
    }
}


void PacketParser::parseIPv4(const u_char *packet, u_int packet_len, std::ostream &os) {
    if (packet_len < ETHER_HDR_LEN_C + sizeof(struct ip_header)) {
        os << "Packet too short to be an IPv4 packet" << std::endl;
        return;
    }

    const auto ip_h = reinterpret_cast<const struct ip_header *>(packet + ETHER_HDR_LEN_C);

    // Extract IP version and header length
    const u_int version = ip_h->ip_vhl >> 4;
    const u_int ihl = ip_h->ip_vhl & 0x0F;
    const u_int ip_header_len = ihl * 4;

    if (version != 4) {
        os << "Not an IPv4 packet (version = " << version << ")" << std::endl;
        return;
    }

    if (packet_len < ETHER_HDR_LEN_C + ip_header_len) {
        os << "Packet too short for full IPv4 header based on length field." << std::endl;
        return;
    }

    os << "IPv4 header" << std::endl;
    os << "  Version:         " << version << std::endl;
    os << "  Header length:   " << ip_header_len << " bytes (" << ihl << " 32-bit words)" << std::endl;
    os << "  Type of service: " << static_cast<int>(ip_h->ip_tos) << std::endl;
    os << "  Total length:    " << ntohs(ip_h->ip_len) << " bytes" << std::endl;
    os << "  Identification:  0x" << std::hex << ntohs(ip_h->ip_id) << std::dec << std::endl;

    const u_int flags = (ntohs(ip_h->ip_off) >> 13) & 0x7;
    os << "  Flags: 0x" << std::hex << flags << std::dec << " (";
    if (flags & IP_FLAG_RESERVED) os << "Reserved ";
    if (flags & IP_FLAG_DF)       os << "DF ";
    if (flags & IP_FLAG_MF)       os << "MF ";
    os << ")" << std::endl;

    const u_int frag_offset = ntohs(ip_h->ip_off) & 0x1FFF;
    os << "  Fragment Offset: " << frag_offset << std::endl;
    os << "  TTL:             " << static_cast<int>(ip_h->ip_ttl) << std::endl;
    os << "  Protocol:        " << static_cast<int>(ip_h->ip_p) << " (" << protocolName(ip_h->ip_p) << ")" << std::endl;
    os << "  Header checksum: 0x" << std::hex << ntohs(ip_h->ip_sum) << std::dec << std::endl;
    os << "  Source address:  ";
    printIpAddress(ip_h->ip_src, os);
    os << std::endl;
    os << "  Destination address: ";
    printIpAddress(ip_h->ip_dst, os);
    os << std::endl;

    // Delegate to appropriate protocol parser
    const u_char* next_header_ptr = packet + ETHER_HDR_LEN_C + ip_header_len;
    u_int remaining_packet_len = packet_len - (ETHER_HDR_LEN_C + ip_header_len);

    switch (ip_h->ip_p) {
        case IP_PROTOCOL_TCP:
            parseTCP(next_header_ptr, remaining_packet_len, os);
            break;
        case IP_PROTOCOL_UDP:
            parseUDP(next_header_ptr, remaining_packet_len, os);
            break;
        case IP_PROTOCOL_ICMP:
            parseICMP(next_header_ptr, remaining_packet_len, os);
            break;
        default:
            os << "  Unknown IP Protocol: " << static_cast<int>(ip_h->ip_p) << std::endl;
            break;
    }
}
void PacketParser::parseTCP(const u_char *packet, u_int packet_len, std::ostream &os) {
    if (packet_len < sizeof(struct tcp_header)) {
        os << "TCP packet too short for base TCP header." << std::endl;
        return;
    }
    const tcp_header *tcp_h = reinterpret_cast<const tcp_header *>(packet);

    // TCP header length is (th_offx2 >> 4) * 4
    const u_int tcp_header_len = (tcp_h->th_offx2 >> 4) * 4;

    if (packet_len < tcp_header_len) {
        os << "TCP packet too short for full TCP header based on offset field." << std::endl;
        return;
    }

    os << "TCP header" << std::endl;
    os << "  Source port:        " << ntohs(tcp_h->th_sport) << std::endl;
    os << "  Destination port:   " << ntohs(tcp_h->th_dport) << std::endl;
    os << "  Sequence number:    " << ntohl(tcp_h->th_seq) << std::endl;
    os << "  Acknowledgment number: " << ntohl(tcp_h->th_ack) << std::endl;
    os << "  Header length:      " << tcp_header_len << " bytes" << std::endl;
    os << "  Flags:              0x" << std::hex << static_cast<int>(tcp_h->th_flags) << std::dec << std::endl;
    os << "    ";
    if (tcp_h->th_flags & TH_FIN_C) os << "FIN ";
    if (tcp_h->th_flags & TH_SYN_C) os << "SYN ";
    if (tcp_h->th_flags & TH_RST_C) os << "RST ";
    if (tcp_h->th_flags & TH_PSH_C) os << "PSH ";
    if (tcp_h->th_flags & TH_ACK_C) os << "ACK ";
    if (tcp_h->th_flags & TH_URG_C) os << "URG ";
    if (tcp_h->th_flags & TH_ECE_C) os << "ECE ";
    if (tcp_h->th_flags & TH_CWR_C) os << "CWR ";
    os << std::endl;
    os << "  Window size:        " << ntohs(tcp_h->th_win) << std::endl;
    os << "  Checksum:           0x" << std::hex << ntohs(tcp_h->th_sum) << std::dec << std::endl;
    os << "  Urgent pointer:     " << ntohs(tcp_h->th_urp) << std::endl;
    // You can parse TCP options here if tcp_header_len > sizeof(tcp_header)
}


void PacketParser::parseUDP(const u_char *packet, u_int packet_len, std::ostream &os) {
    if (packet_len < sizeof(struct udp_header)) {
        os << "UDP packet too short for base UDP header." << std::endl;
        return;
    }
    const udp_header *udp_h = reinterpret_cast<const udp_header *>(packet);
    os << "UDP header" << std::endl;
    os << "  Source port:      " << ntohs(udp_h->uh_sport) << std::endl;
    os << "  Destination port: " << ntohs(udp_h->uh_dport) << std::endl;
    os << "  Length:           " << ntohs(udp_h->uh_len) << " bytes" << std::endl;
    os << "  Checksum:         0x" << std::hex << ntohs(udp_h->uh_sum) << std::dec << std::endl;
}

void PacketParser::parseICMP(const u_char *packet, u_int packet_len, std::ostream &os) {
    if (packet_len < sizeof(struct icmp_header)) {
        os << "ICMP packet too short for base ICMP header." << std::endl;
        return;
    }
    const icmp_header *icmp_h = reinterpret_cast<const icmp_header *>(packet);

    os << "ICMP header" << std::endl;
    os << "  Type:     " << static_cast<int>(icmp_h->icmp_type) << " (" << getIcmpTypeName(icmp_h->icmp_type, icmp_h->icmp_code) << ")"<< std::endl;
    os << "  Code:     " << static_cast<int>(icmp_h->icmp_code) << std::endl;
    os << "  Checksum: 0x" << std::hex << ntohs(icmp_h->icmp_checksum) << std::dec << std::endl; // ICMP checksum is 16-bit

    switch (icmp_h->icmp_type) {
        case 0: // Echo Reply
        case 8: // Echo Request
            if (packet_len >= sizeof(struct icmp_header)) { // Check if echo fields are accessible
                os << "  ID:       " << ntohs(icmp_h->echo.icmp_id) << std::endl;
                os << "  Sequence: " << ntohs(icmp_h->echo.icmp_seq) << std::endl;
            } else {
                os << "  (Echo fields truncated)" << std::endl;
            }
            break;
        default:
            // Assuming icmp_void is for other types, or might need more specific parsing
            // Check packet_len for other union members too if used
            if (packet_len >= sizeof(struct icmp_header)) {
                 os << "  Union Data: 0x" << std::hex << static_cast<u_long>(ntohl(icmp_h->icmp_void)) << std::dec << std::endl;
            } else {
                os << "  (ICMP union data truncated)" << std::endl;
            }
            break;
    }
}

void PacketParser::parseIPv6(const u_char *packet, u_int packet_len, std::ostream &os) {
    if (packet_len < sizeof(ipv6_header)) {
        os << "IPv6 packet too short for base IPv6 header." << std::endl;
        return;
    }

    const ipv6_header* ip6_h = reinterpret_cast<const ipv6_header*>(packet);

    uint32_t ver_tc_fl = ntohl(ip6_h->ver_tc_fl); // Correct byte order for 32-bit field
    int version = (ver_tc_fl >> 28) & 0xF;
    int traffic_class = (ver_tc_fl >> 20) & 0xFF; // 8 bits
    int flow_label = ver_tc_fl & 0xFFFFF; // 20 bits

    os << "IPv6 header" << std::endl;
    os << "  Version:         " << version << std::endl;
    os << "  Traffic class:   " << traffic_class << std::endl;
    os << "  Flow label:      0x" << std::hex << flow_label << std::dec << std::endl;
    os << "  Payload length:  " << ntohs(ip6_h->payload_len) << std::endl;
    os << "  Next header:     " << static_cast<int>(ip6_h->next_header) << std::endl;
    os << "  Hop limit:       " << static_cast<int>(ip6_h->hop_limit) << std::endl;

    char src_str[INET6_ADDRSTRLEN];
    char dst_str[INET6_ADDRSTRLEN];
    // Ensure winsock2.h and ws2tcpip.h (Windows) or arpa/inet.h (Linux/macOS) are included
    if (inet_ntop(AF_INET6, ip6_h->src, src_str, INET6_ADDRSTRLEN) == nullptr) {
        os << "  Source address:      (Error converting IPv6 address)" << std::endl;
    } else {
        os << "  Source address:      " << src_str << std::endl;
    }

    if (inet_ntop(AF_INET6, ip6_h->dst, dst_str, INET6_ADDRSTRLEN) == nullptr) {
        os << "  Destination address: (Error converting IPv6 address)" << std::endl;
    } else {
        os << "  Destination address: " << dst_str << std::endl;
    }

    // You would typically parse the next header here
    const u_char* next_header_ptr = packet + sizeof(ipv6_header);
    u_int remaining_packet_len = packet_len - sizeof(ipv6_header);
    // Add parsing for next_header, similar to IPv4 protocol parsing
}


void PacketParser::parseARP(const u_char *packet, u_int packet_len, std::ostream &os) {
    if (packet_len < sizeof(struct arp_header)) {
        os << "ARP packet too short for base ARP header." << std::endl;
        return;
    }
    const arp_header *arp_h = reinterpret_cast<const arp_header *>(packet);

    os << "ARP Header" << std::endl; // Consistent capitalization
    os << "  Hardware type:           " << ntohs(arp_h->arp_hrd) << std::endl; // Network byte order
    os << "  Protocol type:           0x" << std::hex << ntohs(arp_h->arp_pro) << std::dec << std::endl; // Network byte order
    os << "  Hardware address length: " << static_cast<int>(arp_h->arp_hln) << std::endl;
    os << "  Protocol address length: " << static_cast<int>(arp_h->arp_pln) << std::endl;
    os << "  Operation:               " << ntohs(arp_h->arp_op) << " (" << getArpOpcode(arp_h->arp_op) << ")" << std::endl; // Network byte order
    os << "  Source hardware/MAC address:      ";
    printMacAddress(arp_h->arp_sha, os);
    os << std::endl;
    os << "  Source protocol/IP address:       ";
    printIpAddress(arp_h->arp_spa, os);
    os << std::endl;
    os << "  Destination hardware/MAC address: ";
    printMacAddress(arp_h->arp_tha, os);
    os << std::endl;
    os << "  Destination protocol/IP address:  ";
    printIpAddress(arp_h->arp_tpa, os);
    os << std::endl;
    // The last print of arp_spa was redundant and removed
}

// Main parsing function
void PacketParser::parseAndPrint(const pcap_pkthdr *pkthdr, const std::vector<u_char> *packet_data_vec, std::ostream &os) {
    if (!pkthdr || !packet_data_vec || packet_data_vec->empty()) {
        os << "  Invalid packet data or header." << std::endl;
        return;
    }

    const u_char *packet = packet_data_vec->data(); // Get raw pointer to data
    const u_int packet_len = pkthdr->caplen;        // Use captured length

    os << "\n--- Packet Start ---" << std::endl;
    os << "  Timestamp: " << pkthdr->ts.tv_sec << "." << std::setfill('0') << std::setw(6) << pkthdr->ts.tv_usec << std::setfill(' ') << std::endl;
    os << "  Captured Length: " << pkthdr->caplen << std::endl;
    os << "  Original Length: " << pkthdr->len << std::endl;

    // Parse Ethernet header
    parseEthernet(packet, packet_len, os);

    // Determine what comes after Ethernet
    if (packet_len >= ETHER_HDR_LEN_C) {
        const auto eth_header = reinterpret_cast<const struct ether_header*>(packet);
        const u_short eth_type = ntohs(eth_header->ether_type);

        const u_char* next_protocol_ptr = packet + ETHER_HDR_LEN_C;
        u_int remaining_len = packet_len - ETHER_HDR_LEN_C;

        switch (eth_type) {
            case ETHER_TYPE_IP_V4:
                parseIPv4(next_protocol_ptr, remaining_len, os);
                break;
            case ETHER_TYPE_IPV6:
                parseIPv6(next_protocol_ptr, remaining_len, os);
                break;
            case ETHER_TYPE_ARP:
                parseARP(next_protocol_ptr, remaining_len, os);
                break;
            // Add other EtherTypes as needed (e.g., ETHER_TYPE_VLAN for VLAN-tagged frames)
            default:
                os << "  (Payload starts after Ethernet header, unknown EtherType)" << std::endl;
                // Optionally print hex dump of remaining payload
                // printHex(next_protocol_ptr, remaining_len, os);
                break;
        }
    } else {
        os << "  (Packet too short to contain network layer data after Ethernet header)" << std::endl;
    }
    os << "--- Packet End ---\n" << std::endl;
}