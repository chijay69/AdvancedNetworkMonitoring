//
// Created by HomePC on 5/22/2025.
//

#ifndef CONSOLEWRITER_H
#define CONSOLEWRITER_H

#include "PacketWriter.h"  // Assuming this is your base/interface
#include "PacketParser.h"    // Include the PacketParser header
#include <string>            // For std::string in open method
#include <pcap/pcap.h>       // <--- ADDED: For pcap_pkthdr and u_char types

class ConsoleWriter : public PacketWriter { // Or your specific base class
public:
    ConsoleWriter();
    virtual ~ConsoleWriter() = default; // Use default if base has virtual destructor

    bool open(const std::string &options, pcap_t *metadata_or_live_handler) override;
    void writePacket(const pcap_pkthdr *header, const u_char *packet) override;
    void close() override;

private:
    PacketParser parser_; // PacketParser as a member variable
};

#endif //CONSOLEWRITER_H
