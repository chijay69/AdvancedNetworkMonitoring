//
// Created by HomePC on 5/24/2025.
//
#include "MonitorWriter.h"

#include <iostream>

MonitorWriter::MonitorWriter(std::unique_ptr<PacketWriter> base_writer, NetworkMonitor& monitor)
    : base_writer_(std::move(base_writer)), monitor_(monitor){
    std::cout << "MonitorWriter::MonitorWriter()" << std::endl;
}

bool MonitorWriter::open(const std::string& options, pcap_t* metadata_or_live_handler) {
    return base_writer_->open(options, metadata_or_live_handler);
}

void MonitorWriter::writePacket(const pcap_pkthdr* header, const u_char* packet) {
    monitor_.processPacket(header, packet);
    // Pass packet to base writer
    base_writer_->writePacket(header, packet);
}

void MonitorWriter::close() {
    base_writer_->close();
}