//
// Created by HomePC on 5/22/2025.
//
#include "PcapFileWriter.h"
#include <iostream>
#include <stdexcept>

// std::string output_filename; // <<< REMOVE GLOBAL VARIABLE

PcapFileWriter::PcapFileWriter(): dumper_handle(nullptr, pcap_dump_close) {
    std::cout << "PcapFileWriter::PcapFileWriter()" << std::endl;
};

PcapFileWriter::~PcapFileWriter() = default; // Or implement if needed, ensure dumper_handle is managed.

bool PcapFileWriter::open(const std::string &filename, pcap_t *live_pcap_handler_or_metadata) {
    // Use the correct parameter name in the log message
    std::cout << "PcapFileWriter::open(const std::string &filename, pcap_t *live_pcap_handler_or_metadata)" << std::endl;

    if (!live_pcap_handler_or_metadata) {
        std::cerr << "PcapFileWriter Error: live_pcap_handler_or_metadata is null" << std::endl;
        // Throwing an exception is a valid way to handle this error.
        // The function will not return false after a throw.
        throw std::runtime_error("PcapFileWriter: live_pcap_handler_or_metadata is null");
        // return false; // <<< UNREACHABLE CODE
    }
    this->output_filename_ = filename; // <<< STORE FILENAME IN MEMBER VARIABLE
    dumper_handle.reset(pcap_dump_open(live_pcap_handler_or_metadata, this->output_filename_.c_str()));

    if (!dumper_handle) {
        std::cerr << "PcapFileWriter Error: Error opening pcap dumper for file: " << this->output_filename_ << std::endl;
        std::cerr << "Pcap Error: " << pcap_geterr(live_pcap_handler_or_metadata) << std::endl;
        return false;
    }

    std::cout << "PcapFileWriter::open() successful. " << this->output_filename_ << " is ready for writing." << std::endl;

    return true;
}

void PcapFileWriter::writePacket(const pcap_pkthdr *header, const u_char *packet) {
    // Correct the logging message parameter type
    // std::cout << "PcapFileWriter::writePacket(const pcap_pkthdr *header, const u_char *packet)" << std::endl; 
    // ^ Optional: For brevity or performance, you might remove or conditionalize frequent logs like this.

    if (!dumper_handle) {
        std::cerr << "PcapFileWriter Error: Error writing packet. Dumper handle is null. File: " << this->output_filename_ << std::endl;
        return;
    }
    pcap_dump(reinterpret_cast<u_char*>(dumper_handle.get()), header, packet);
}

void PcapFileWriter::close() {
    if (dumper_handle) {
        // Use the member variable for the filename
        std::cout << "PcapFileWriter::close() closing file: " << this->output_filename_ << std::endl;
        dumper_handle.reset(); // This will call pcap_dump_close
        this->output_filename_.clear(); // Clear the stored filename
    } else {
        std::cout << "PcapFileWriter::close() called but no file was open." << std::endl;
    }
}