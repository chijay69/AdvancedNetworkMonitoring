//
// Created by HomePC on 5/22/2025.
// ConsoleWriter.cpp
//
#include "ConsoleWriter.h"
#include "PacketParser.h"   // REQUIRED: Needed for PacketParser::parseAndPrint and PacketParser member
#include "PacketStructs.h"  // REQUIRED: Needed for ether_header and arp_header sizeof calculations
#include <iostream>
#include <vector>           // REQUIRED: For std::vector
#include <iomanip>          // Keep if PacketParser might use it via std::cout passed to it
#include <cassert>

// Constructor for ConsoleWriter
ConsoleWriter::ConsoleWriter() {
    std::cout << "ConsoleWriter::ConsoleWriter()" << std::endl;
    // The 'parser_' member is default-constructed automatically.
    // If PacketParser needs specific initialization, do it here:
    // parser_ = PacketParser(some_config);
} // No semicolon needed after definition body

bool ConsoleWriter::open(const std::string & /*options*/, pcap_t * /*metadata_or_live_handler*/) {
    // Parameters are unnamed, indicating they are unused by ConsoleWriter,
    // which is fine if required by an interface.
    std::cout << "ConsoleWriter: Ready to print to console." << std::endl;
    return true;
}

void ConsoleWriter::writePacket(const pcap_pkthdr *header, const u_char *packet) {
    // Defensive checks
    if (!header) {
        std::cerr << "ConsoleWriter Error: null header pointer passed to writePacket." << std::endl;
        return;
    }
    if (!packet) {
        std::cerr << "ConsoleWriter Error: null packet pointer passed to writePacket." << std::endl;
        return;
    }
    if (header->caplen == 0) {
        std::cerr << "ConsoleWriter Error: header->caplen is zero!" << std::endl;
        return;
    }
    // These checks require PacketStructs.h to be included
    if (header->caplen < sizeof(ether_header)) {
        std::cerr << "ConsoleWriter Error: caplen (" << header->caplen << ") < Ethernet header size (" << sizeof(ether_header) << ")" << std::endl;
        return;
    }
    // This check is more specific to ARP, consider if you want to filter non-ARP packets here
    if (header->caplen < sizeof(ether_header) + sizeof(arp_header)) {
        std::cerr << "ConsoleWriter Error: caplen (" << header->caplen << ") < Ethernet+ARP header size ("
                  << (sizeof(ether_header) + sizeof(arp_header)) << ")" << std::endl;
        // Let it through if you want to process other protocols, else: return;
        // return; // Uncomment this if you want to drop packets shorter than ARP header
    }

    // Assertions (local, redundant with above but keeps debug strict)
    assert(packet != nullptr);
    assert(header->caplen > 0);

    std::cout << "header=" << header
              << ", packet=" << static_cast<const void*>(packet)
              << ", caplen=" << header->caplen << std::endl;

    // Create a std::vector from the raw packet data
    std::vector<u_char> packet_data(packet, packet + header->caplen);

    // Use the PacketParser member to parse and print the packet
    parser_.parseAndPrint(header, &packet_data, std::cout);
}

void ConsoleWriter::close() {
    std::cout << "ConsoleWriter::close()" << std::endl;
} // No semicolon needed after definition body
