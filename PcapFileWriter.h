//
// Created by HomePC on 5/22/2025.
//
#pragma once

#include <string>
#include <memory>
#include "pcap/pcap.h"
#include "PacketWriter.h" // Assuming PacketWriter is the base class or interface

class PcapFileWriter : public PacketWriter { // Or implements PacketWriter
public:
    PcapFileWriter();
    ~PcapFileWriter() override; // Good practice to make destructors virtual in base classes

    bool open(const std::string &filename, pcap_t *live_pcap_handler_or_metadata) override;
    void writePacket(const pcap_pkthdr *header, const u_char *packet) override;
    void close() override;

private:
    std::unique_ptr<pcap_dumper_t, decltype(&pcap_dump_close)> dumper_handle;
    std::string output_filename_; // <<< Make it a member variable
};