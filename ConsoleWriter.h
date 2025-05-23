#ifndef CONSOLEWRITER_H
#define CONSOLEWRITER_H

#include "PacketWriter.h" // Assuming this is your base/interface
#include "PacketParser.h"   // Include the PacketParser header
#include <string>
// #include "pcap/pcap.h" // if pcap_t is not from PacketWriter.h

class ConsoleWriter : public PacketWriter { // Or your specific base class
public:
    ConsoleWriter();
    // virtual ~ConsoleWriter(); // If base has virtual destructor

    bool open(const std::string &options, pcap_t *metadata_or_live_handler) override;
    void writePacket(const pcap_pkthdr *header, const u_char *packet) override;
    void close() override;

private:
    PacketParser parser_; // <<< Add PacketParser as a member variable
};

#endif //CONSOLEWRITER_H