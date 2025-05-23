//
// Created by HomePC on 5/22/2025.
//

#ifndef PACKETWRITER_H
#define PACKETWRITER_H

#include <string>
#include <pcap/pcap.h>

class PacketWriter {
public:
    PacketWriter() = default;
    virtual ~PacketWriter() = default;
    virtual bool open(const std::string &destination, pcap_t *live_pcap_handler_or_metadata) = 0;
    virtual void writePacket(const pcap_pkthdr *header, const u_char *packet) = 0;
    virtual void close() = 0;
};
#endif //PACKETWRITER_H