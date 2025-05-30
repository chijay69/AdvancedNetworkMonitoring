//
// Created by HomePC on 5/22/2025.
//

#ifndef PACKETPARSER_H
#define PACKETPARSER_H

#include "PacketStructs.h" // Assumed to define ether_header, ip_header, etc.
#include <iostream>
#include <vector>
#include <iomanip>
#include <pcap/pcap.h> // For pcap_pkthdr, u_char, u_int, u_short


// Prefer constexpr over #define for type safety and scoping
// Using 'inline constexpr' to ensure external linkage and prevent multiple definition errors
inline constexpr u_short ETHER_TYPE_IP_V4    = 0x0800;
inline constexpr u_short ETHER_TYPE_ARP      = 0x0806;
inline constexpr u_short ETHER_TYPE_IPV6     = 0x86DD;
inline constexpr u_short ETHER_TYPE_VLAN     = 0x8100;
inline constexpr u_short ETHER_TYPE_REVARP   = 0x8035; // Corrected RE_VARP definition

inline constexpr u_char IP_PROTOCOL_TCP   = 0x06;
inline constexpr u_char IP_PROTOCOL_UDP   = 0x11;
inline constexpr u_char IP_PROTOCOL_ICMP  = 0x01;

inline constexpr int ETHER_ADDR_LEN_C = 6;
inline constexpr u_int ETHER_HDR_LEN = 14; // Standard Ethernet II header length


inline constexpr u_int IP_FLAG_RESERVED = 0x4;  // bit 2
inline constexpr u_int IP_FLAG_DF       = 0x2;  // bit 1 (Don't Fragment)
inline constexpr u_int IP_FLAG_MF       = 0x1;  // bit 0 (More Fragments)

// Define TCP flags
inline constexpr u_char TH_FIN_C  = 0x01;
inline constexpr u_char TH_SYN_C  = 0x02;
inline constexpr u_char TH_RST_C  = 0x04;
inline constexpr u_char TH_PSH_C  = 0x08;
inline constexpr u_char TH_ACK_C  = 0x10;
inline constexpr u_char TH_URG_C  = 0x20;
inline constexpr u_char TH_ECE_C  = 0x40;
inline constexpr u_char TH_CWR_C  = 0x80;


class PacketParser {
    public:
        PacketParser();
        ~PacketParser() = default;

        // Main parsing function
        static void parseAndPrint(const pcap_pkthdr *header, const std::vector<u_char> *packet_data,  std::ostream &os = std::cout);
    private:
        // Helper functions for printing formatted data
        static void printHex(const u_char *data, int len, std::ostream &os);
        static void printIpAddress(const u_char *ip, std::ostream &os);
        static void printMacAddress(const u_char *mac, std::ostream &os);

        // Protocol-specific parsing functions
        // Updated signature to return resolved EtherType and next protocol offset
        static void parseEthernet(const u_char *packet, u_int packet_len, std::ostream &os,
                                  u_short &out_eth_type, u_int &out_next_protocol_offset);
        static void parseIPv4(const u_char *packet, u_int packet_len, std::ostream &os);
        static void parseTCP(const u_char *packet, u_int packet_len, std::ostream &os);
        static void parseUDP(const u_char *packet, u_int packet_len, std::ostream &os);
        static void parseICMP(const u_char *packet, u_int packet_len, std::ostream &os);
        static void parseARP(const u_char *packet, u_int packet_len, std::ostream &os);
        static void parseIPv6(const u_char *packet, u_int packet_len, std::ostream &os);

        // Helper functions for getting protocol/opcode names
        static const char *getIpProtocolName(u_char protocol_code); // Not currently implemented in .cpp, but declared
        static const char *getArpOpcode(u_char opcode);
        static const char *getIcmpType(u_char type); // Not currently implemented in .cpp, but declared
        static const char *getIcmpTypeName(u_char type, u_char code); // This one is implemented

        // The ParseResult struct is not currently used in the public interface or any of the
        // current static functions. It has been removed to avoid unused declarations.
};

#endif //PACKETPARSER_H
