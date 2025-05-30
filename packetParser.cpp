//
// Created by HomePC on 5/22/2025.
// Packetparser.cpp
//
#include "PacketParser.h" // <--- MUST BE THE FIRST INCLUDE FOR ITS OWN DEFINITIONS
#include "PacketStructs.h" // Assumed to define ether_header, ip_header, tcp_header, udp_header, icmp_header, ipv6_header, arp_header
#include <sstream>
#include <iomanip>
#include <vector>    // Required for std::vector<u_char>
#include <algorithm> // For std::transform if needed
#include <cstdint>   // REQUIRED: For uint32_t
#include <pcap/pcap.h> // REQUIRED: For pcap_pkthdr, u_char, u_int, u_short (if not already pulled by PacketParser.h and PacketStructs.h)

// Include the necessary headers for network functions and types
#ifdef _WIN32
#include <winsock2.h> // For u_char, u_short, u_int, in_addr (Windows)
#include <ws2tcpip.h> // For inet_ntop, INET6_ADDRSTRLEN
#else
#include <arpa/inet.h>  // For ntohs, ntohl, inet_ntop etc.
#include <netinet/in.h> // For INET6_ADDRSTRLEN
#endif

// Constructor for PacketParser
PacketParser::PacketParser() = default; // Corrected: This is the definition, not just a declaration

// Helper to get ICMP type name based on type and code
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
    // The opcode passed to this function is already expected to be in host byte order
    // and correctly cast to u_char from the original u_short.
    switch (opcode) {
        case 1: return "Request";
        case 2: return "Reply";
        case 3: return "Request Reverse"; // RARP Request
        case 4: return "Reply Reverse"; // RARP Reply
        default: return "Unknown";
    }
}

// Helper to get IP protocol name
const char* PacketParser::getIpProtocolName(u_char p) {
    switch (p) {
        case IP_PROTOCOL_TCP:  return "TCP";
        case IP_PROTOCOL_UDP:  return "UDP";
        case IP_PROTOCOL_ICMP: return "ICMP";
        default:              return "Unknown";
    }
}

// Helper to get ICMP type (without code) - currently unused, but declared in header
const char *PacketParser::getIcmpType(u_char type) {
    return getIcmpTypeName(type, 0); // Delegate to the more specific function
}

// Helper to print MAC address in colon-separated hex format
void PacketParser::printMacAddress(const u_char *mac, std::ostream &os) {
    os << std::hex << std::setfill('0');
    for (int i = 0; i < ETHER_ADDR_LEN_C; ++i) { // Use constexpr length
        os << std::setw(2) << static_cast<int>(mac[i]);
        if (i < ETHER_ADDR_LEN_C - 1) {
            os << ":";
        }
    }
    os << std::dec << std::setfill(' '); // Reset stream formatting
}

// Helper to print IPv4 address in dot-separated decimal format
void PacketParser::printIpAddress(const u_char *ip, std::ostream &os) {
    os << static_cast<int>(ip[0]) << "." << static_cast<int>(ip[1]) << "." << static_cast<int>(ip[2]) << "." << static_cast<int>(ip[3]);
}

// Helper to print raw data in hex format
void PacketParser::printHex(const u_char *data, int len, std::ostream &os) {
    os << std::hex << std::setfill('0');
    for (int i = 0; i < len; ++i) {
        os << std::setw(2) << static_cast<int>(data[i]);
    }
    os << std::dec << std::setfill(' '); // Reset stream formatting
}

// Parses the Ethernet header and determines the next protocol, handling VLAN tags
// Returns the resolved EtherType and the offset to the next protocol
void PacketParser::parseEthernet(const u_char *packet, u_int packet_len, std::ostream &os,
                                 u_short &out_eth_type, u_int &out_next_protocol_offset) {
    out_eth_type = 0; // Initialize output parameters
    out_next_protocol_offset = 0;

    if (packet_len < ETHER_HDR_LEN_C) {
        os << "  Packet too short for Ethernet header." << std::endl;
        return;
    }

    const auto eth_header = reinterpret_cast<const struct ether_header*>(packet);

    // Lambda for formatting MAC address
    auto formatMAC = [](const u_char *mac) {
        std::ostringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < ETHER_ADDR_LEN_C; ++i) {
            if (i > 0) ss << ":";
            ss << std::setw(2) << static_cast<int>(mac[i]);
        }
        return ss.str();
    };

    os << "Ethernet Header" << std::endl;
    os << "  Destination MAC: " << formatMAC(eth_header->ether_dhost) << std::endl;
    os << "  Source MAC:      " << formatMAC(eth_header->ether_shost) << std::endl;

    u_short current_eth_type = ntohs(eth_header->ether_type);
    out_next_protocol_offset = ETHER_HDR_LEN_C; // Default offset after standard Ethernet header

    // Check for 802.1Q VLAN Tag (EtherType 0x8100)
    if (current_eth_type == ETHER_TYPE_VLAN) {
        os << "  EtherType:       0x" << std::hex << current_eth_type << std::dec << " (VLAN-tagged)" << std::endl;

        // Check if there's enough space for the VLAN tag (4 bytes)
        if (packet_len < ETHER_HDR_LEN_C + 4) {
            os << "  VLAN Tagged Frame too short for VLAN header." << std::endl;
            return; // Cannot parse further
        }

        // The true EtherType is after the VLAN tag (2 bytes of TCI + 2 bytes for true EtherType)
        const u_short* vlan_eth_type_ptr = reinterpret_cast<const u_short*>(packet + ETHER_HDR_LEN_C + 2);
        out_eth_type = ntohs(*vlan_eth_type_ptr); // This is the actual EtherType of the encapsulated payload
        out_next_protocol_offset += 4; // Advance offset by 4 bytes for VLAN tag

        os << "  VLAN Encapsulation: " << std::endl;
        // Optionally, parse and print VLAN Tag Control Information (TCI)
        // const u_short tci = ntohs(*reinterpret_cast<const u_short*>(packet + ETHER_HDR_LEN_C));
        // os << "    TCI: 0x" << std::hex << tci << std::dec << std::endl;
        // os << "    Priority: " << ((tci >> 13) & 0x7) << std::endl;
        // os << "    CFI: " << ((tci >> 12) & 0x1) << std::endl;
        // os << "    VLAN ID: " << (tci & 0xFFF) << std::endl;

        os << "    Encapsulated EtherType: 0x" << std::hex << out_eth_type << std::dec;
        switch (out_eth_type) {
            case ETHER_TYPE_IP_V4:    os << " (IPv4)"; break;
            case ETHER_TYPE_IPV6:     os << " (IPv6)"; break;
            case ETHER_TYPE_ARP:      os << " (ARP)";  break;
            case ETHER_TYPE_REVARP:   os << " (Reverse ARP)"; break;
            default:                  os << " (Unknown)"; break;
        }
        os << std::endl;

    } else {
        // No VLAN tag, the current_eth_type is the actual EtherType
        out_eth_type = current_eth_type;
        os << "  EtherType:       0x" << std::hex << out_eth_type << std::dec;
        switch (out_eth_type) {
            case ETHER_TYPE_IP_V4:    os << " (IPv4)"; break;
            case ETHER_TYPE_IPV6:     os << " (IPv6)"; break; // Corrected typo here (EHER -> ETHER)
            case ETHER_TYPE_ARP:      os << " (ARP)";  break;
            case ETHER_TYPE_REVARP:   os << " (Reverse ARP)"; break;
            default:                  os << " (Unknown)"; break;
        }
        os << std::endl;
    }
}

// Parses an IPv4 header and delegates to the next protocol parser
void PacketParser::parseIPv4(const u_char *packet, u_int packet_len, std::ostream &os) {
    if (packet_len < sizeof(struct ip_header)) {
        os << "Packet too short to be an IPv4 packet (min header size)." << std::endl;
        return;
    }

    const auto ip_h = reinterpret_cast<const struct ip_header *>(packet);

    // Extract IP version and header length
    const u_int version = ip_h->ip_vhl >> 4;
    const u_int ihl = ip_h->ip_vhl & 0x0F;
    const u_int ip_header_len = ihl * 4;

    if (version != 4) {
        os << "Not an IPv4 packet (version = " << version << ")" << std::endl;
        return;
    }

    if (packet_len < ip_header_len) { // Check against remaining packet length
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
    os << "  Protocol:        " << static_cast<int>(ip_h->ip_p) << " (" << getIpProtocolName(ip_h->ip_p) << ")" << std::endl;
    os << "  Header checksum: 0x" << std::hex << ntohs(ip_h->ip_sum) << std::dec << std::endl;
    os << "  Source address:  ";
    printIpAddress(ip_h->ip_src, os);
    os << std::endl;
    os << "  Destination address: ";
    printIpAddress(ip_h->ip_dst, os);
    os << std::endl;

    // Delegate to appropriate protocol parser for the payload
    const u_char* next_header_ptr = packet + ip_header_len;
    u_int remaining_packet_len = packet_len - ip_header_len;

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

// Parses a TCP header
void PacketParser::parseTCP(const u_char *packet, u_int packet_len, std::ostream &os) {
    if (packet_len < sizeof(struct tcp_header)) {
        os << "TCP packet too short for base TCP header." << std::endl;
        return;
    }
    const tcp_header *tcp_h = reinterpret_cast<const tcp_header *>(packet);

    // TCP header length is (th_offx2 >> 4) * 4 (th_offx2 contains data offset in high 4 bits)
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

// Parses a UDP header
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

// Parses an ICMP header
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
            // Ensure packet_len is sufficient for echo fields
            if (packet_len >= sizeof(struct icmp_header)) {
                os << "  ID:       " << ntohs(icmp_h->echo.icmp_id) << std::endl;
                os << "  Sequence: " << ntohs(icmp_h->echo.icmp_seq) << std::endl;
            } else {
                os << "  (Echo fields truncated)" << std::endl;
            }
            break;
        default:
            // For other ICMP types, print the 32-bit union data if available
            if (packet_len >= sizeof(struct icmp_header)) {
                 os << "  Union Data: 0x" << std::hex << static_cast<u_long>(ntohl(icmp_h->icmp_void)) << std::dec << std::endl;
            } else {
                os << "  (ICMP union data truncated)" << std::endl;
            }
            break;
    }
}

// Parses an IPv6 header
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

    char src_str[INET6_ADDRSTRLEN]; // Buffer for source IPv6 address string
    char dst_str[INET6_ADDRSTRLEN]; // Buffer for destination IPv6 address string

    // Convert source IPv6 address from binary to string
    if (inet_ntop(AF_INET6, ip6_h->src, src_str, INET6_ADDRSTRLEN) == nullptr) {
        os << "  Source address:      (Error converting IPv6 address)" << std::endl;
    } else {
        os << "  Source address:      " << src_str << std::endl;
    }

    // Convert destination IPv6 address from binary to string
    if (inet_ntop(AF_INET6, ip6_h->dst, dst_str, INET6_ADDRSTRLEN) == nullptr) {
        os << "  Destination address: (Error converting IPv6 address)" << std::endl;
    } else {
        os << "  Destination address: " << dst_str << std::endl;
    }

    // You would typically parse the next header here based on ip6_h->next_header
    const u_char* next_header_ptr = packet + sizeof(ipv6_header);
    u_int remaining_packet_len = packet_len - sizeof(ipv6_header);
    // Add parsing for next_header, similar to IPv4 protocol parsing
    // This would involve a switch statement based on ip6_h->next_header
}

// Parses an ARP header
void PacketParser::parseARP(const u_char *packet, u_int packet_len, std::ostream &os) {
    if (packet_len < sizeof(struct arp_header)) {
        os << "ARP packet too short for base ARP header." << std::endl;
        return;
    }
    const arp_header *arp_h = reinterpret_cast<const arp_header *>(packet);

    os << "ARP Header" << std::endl; // Consistent capitalization
    os << "  Hardware type:           " << ntohs(arp_h->arp_hrd) << std::endl; // Network byte order to host
    os << "  Protocol type:           0x" << std::hex << ntohs(arp_h->arp_pro) << std::dec << std::endl; // Network byte order to host
    os << "  Hardware address length: " << static_cast<int>(arp_h->arp_hln) << std::endl;
    os << "  Protocol address length: " << static_cast<int>(arp_h->arp_pln) << std::endl;
    os << "  Operation:               " << ntohs(arp_h->arp_op) << " (" << getArpOpcode(static_cast<u_char>(ntohs(arp_h->arp_op))) << ")" << std::endl; // Convert to host byte order and then to u_char for getArpOpcode
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
}

// Main parsing function: orchestrates parsing of different layers
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

    u_short eth_type_resolved;      // To store the resolved EtherType after VLAN checks
    u_int next_protocol_offset;     // To store the offset to the next protocol header

    // Parse Ethernet header and get the resolved EtherType and offset
    parseEthernet(packet, packet_len, os, eth_type_resolved, next_protocol_offset);

    // Check if Ethernet parsing failed or packet too short for next layer
    if (next_protocol_offset == 0 || packet_len < next_protocol_offset) {
        os << "  (Cannot parse network layer: Ethernet parsing failed or packet too short)" << std::endl;
        os << "--- Packet End ---\n" << std::endl;
        return;
    }

    const u_char* next_protocol_ptr = packet + next_protocol_offset;
    u_int remaining_len = packet_len - next_protocol_offset;

    // Now, use the resolved EtherType to parse the next layer
    switch (eth_type_resolved) {
        case ETHER_TYPE_IP_V4:
            parseIPv4(next_protocol_ptr, remaining_len, os);
            break;
        case ETHER_TYPE_IPV6:
            parseIPv6(next_protocol_ptr, remaining_len, os);
            break;
        case ETHER_TYPE_ARP:
            parseARP(next_protocol_ptr, remaining_len, os);
            break;
        // Add other EtherTypes as needed
        default:
            os << "  (Payload starts after Ethernet/VLAN header, unknown EtherType: 0x"
               << std::hex << eth_type_resolved << std::dec << ")" << std::endl;
            break;
    }
    os << "--- Packet End ---\n" << std::endl;
}
