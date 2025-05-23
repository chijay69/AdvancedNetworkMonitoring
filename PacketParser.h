//
// Created by HomePC on 5/22/2025.
//

#ifndef PACKETPARSER_H
#define PACKETPARSER_H

#include "PacketStructs.h"
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <pcap/pcap.h>

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
