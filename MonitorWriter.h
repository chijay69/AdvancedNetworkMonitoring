//
// Created by HomePC on 5/24/2025.
//

#include <memory>

#include "NetworkMonitor.h"
#include "PacketWriter.h"


#ifndef MONITORWRITER_H
#define MONITORWRITER_H

class MonitorWriter : public PacketWriter {
public:
    MonitorWriter(std::unique_ptr<PacketWriter> base_writer, NetworkMonitor &monitor);

    bool open(const std::string &options, pcap_t *live_pcap_handler_or_metadata) override;

    void writePacket(const pcap_pkthdr *header, const u_char *packet) override;
    void close() override;

private:
    std::unique_ptr<PacketWriter> base_writer_;
    NetworkMonitor &monitor_;
};

#endif //MONITORWRITER_H
