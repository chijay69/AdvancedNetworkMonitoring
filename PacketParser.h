//
// Created by HomePC on 5/22/2025.
//

#ifndef PACKETPARSER_H
#define PACKETPARSER_H

#include "PacketStructs.h"
#include <iostream>
#include <vector>
#include <iomanip>
#include <pcap/pcap.h>


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


class PacketParser {
    public:
        PacketParser();
        ~PacketParser() = default;

        static void parseAndPrint(const pcap_pkthdr *header, const std::vector<u_char> *packet_data,  std::ostream &os = std::cout);
    private:
    static void printHex(const u_char *data, int len, std::ostream &os);
    static void printIpAddress(const u_char *ip, std::ostream &os);
    static void printMacAddress(const u_char *mac, std::ostream &os);

    // Protocol-specific parsing function
    static void parseEthernet(const u_char *packet, u_int packet_len, std::ostream &os);
    static void parseIPv4(const u_char *packet, u_int packet_len, std::ostream &os);
    static void parseTCP(const u_char *packet, u_int packet_len, std::ostream &os);
    static void parseUDP(const u_char *packet, u_int packet_len, std::ostream &os);
    static void parseICMP(const u_char *packet, u_int packet_len, std::ostream &os);
    static void parseARP(const u_char *packet, u_int packet_len, std::ostream &os);
    static void parseIPv6(const u_char *packet, u_int packet_len, std::ostream &os);


    // Helper functions
    static const char *getIpProtocolName(u_char protocol_code);
    static const char *getArpOpcode(u_char opcode);
    static const char *getIcmpType(u_char type);
    static const char *getIcmpTypeName(u_char type, u_char code);
    //
    // static const char *getMacProtocolName(u_char protocol_code);
    // static const char *getTcpFlagName(u_char flag);
    // static const char *getTcpControlFlagName(u_char flag);
    // static const char *getTcpOptionName(u_char option);
    // static const char *getIcmpCode(u_char code);
    // static const char *getArpHardwareType(u_char hardware_type);
    // static const char *getArpProtocolType(u_char protocol_type);

    struct ParseResult {
        int next_proto;
        size_t next_offset;
        bool success;
    };
};

#endif //PACKETPARSER_H
