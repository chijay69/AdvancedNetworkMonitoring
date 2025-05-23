//
// Created by HomePC on 5/22/2025.
//

#ifndef PCAPFILEREADER_H
#define PCAPFILEREADER_H

#include "PacketWriter.h"
#include <string>
#include <memory>
#include <pcap/pcap.h>

class PcapFileReader {
public:
    PcapFileReader();
    ~PcapFileReader() = default;

    static bool readFromFile(const std::string &filename, PacketWriter &writer_impl);
private:
    static void readPacketHandler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
};

#endif //PCAPFILEREADER_H
