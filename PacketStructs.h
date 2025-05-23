//
// Created by HomePC on 5/22/2025.
//

#ifndef PACKETSTRUCTS_H
#define PACKETSTRUCTS_H

#include <cstdint> // For uint8_t, uint16_t, uint32_t for better portability
#ifdef _WIN32
#include <winsock2.h> // For u_char, u_short, u_int, in_addr (on Windows)
#else
// On Linux/macOS, these would typically be in <netinet/ether.h>, <netinet/ip.h> etc.
// For example:
// #include <netinet/ether.h>
// #include <netinet/ip.h>
// #include <netinet/tcp.h>
// #include <netinet/udp.h>
// #include <netinet/ip_icmp.h>
// If your system doesn't define u_char, u_short, u_int, you might need:
// using u_char = unsigned char;
// using u_short = unsigned short;
// using u_int = unsigned int;
#endif

// Ethernet header (14 bytes)
struct ether_header {
    u_char ether_dhost[6]; // Destination MAC address
    u_char ether_shost[6]; // Source MAC address
    u_short ether_type;    // Ethernet type (e.g., IPv4, IPv6, ARP)
};

// IPv4 header (variable length, min 20 bytes)
struct ip_header {
    u_char ip_vhl;  // Version (4 bits) + Internet Header Length (IHL, 4 bits)
    u_char ip_tos;  // Type of Service (8 bits)
    u_short ip_len; // Total Length (16 bits)
    u_short ip_id;  // Identification (16 bits)
    u_short ip_off; // Flags (3 bits) + Fragment Offset (13 bits)
    u_char ip_ttl;  // Time To Live (8 bits)
    u_char ip_p;    // Protocol (8 bits)
    u_short ip_sum; // Header Checksum (16 bits)
    u_char ip_src[4]; // Source IP address (32 bits)
    u_char ip_dst[4]; // Destination IP address (32 bits)
    // No ip_flow; this is not a standard IP header field for IPv4
};

// IPv6 header (fixed 40 bytes)
struct ipv6_header {
    uint32_t ver_tc_fl;     // Version (4 bits), Traffic Class (8 bits), Flow Label (20 bits)
    uint16_t payload_len;   // Payload length (16 bits)
    uint8_t next_header;    // Next header protocol (8 bits)
    uint8_t hop_limit;      // Hop limit (8 bits)
    uint8_t src[16];        // Source IPv6 address (128 bits)
    uint8_t dst[16];        // Destination IPv6 address (128 bits)
};

// ARP header (variable length, depending on HW/Prot types)
struct arp_header {
    u_short arp_hrd; // Hardware type (e.g., Ethernet)
    u_short arp_pro; // Protocol type (e.g., IPv4)
    u_char arp_hln;  // Hardware address length
    u_char arp_pln;  // Protocol address length
    u_short arp_op;  // Operation (e.g., request, reply)
    u_char arp_sha[6]; // Sender hardware address
    u_char arp_spa[4]; // Sender protocol address
    u_char arp_tha[6]; // Target hardware address
    u_char arp_tpa[4]; // Target protocol address
};

// TCP header (variable length, min 20 bytes)
struct tcp_header {
    u_short th_sport;   // Source port
    u_short th_dport;   // Destination port
    u_int th_seq;       // Sequence number
    u_int th_ack;       // Acknowledgment number
    u_char th_offx2;    // Data offset (4 bits) + Reserved (4 bits)
    u_char th_flags;    // Flags (e.g., SYN, ACK, FIN)
    u_short th_win;     // Window size
    u_short th_sum;     // Checksum
    u_short th_urp;     // Urgent pointer
};

// UDP header (fixed 8 bytes)
struct udp_header {
    u_short uh_sport;   // Source port
    u_short uh_dport;   // Destination port
    u_short uh_len;     // Length
    u_short uh_sum;     // Checksum
};

// ICMP header (variable length, min 8 bytes)
struct icmp_header {
    u_char icmp_type;    // Type
    u_char icmp_code;    // Code
    u_short icmp_checksum; // Checksum
    union { // ICMP message specific data
        struct {
            u_short icmp_id;  // Identifier
            u_short icmp_seq; // Sequence number
        } echo; // For Echo Request/Reply (Type 0 and 8)
        uint32_t icmp_void; // Generic 32-bit field for other types (e.g., timestamp, address mask)
        // Add other common ICMP union members as needed, e.g.:
        // struct { uint32_t gateway; } redirect;
        // struct { uint16_t unused; uint16_t next_hop_mtu; } frag_needed;
    };
};
    #define ETHER_HDR_LEN_C sizeof(ether_header) // Define Ethernet header length

#endif //PACKETSTRUCTS_H