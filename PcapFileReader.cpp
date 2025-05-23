//
// Created by HomePC on 5/22/2025.
//

#include "PcapFileReader.h"
#include <iostream>
#include <memory> // For std::unique_ptr

#include "PcapFileReader.h"

PcapFileReader::PcapFileReader() = default;
// Note: The `readPacketHandler` is a static C-style callback function for pcap_loop.
// It receives `user_data` as a `u_char*`, which we expect to be a `PacketWriter*`.
void PcapFileReader::readPacketHandler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Cast the user_data back to a PacketWriter pointer.
    // It's crucial that the PacketWriter object pointed to by user_data remains valid
    // throughout the pcap_loop call.
    PacketWriter *packet_writer = reinterpret_cast<PacketWriter *>(user_data);

    if (packet_writer) {
        packet_writer->writePacket(pkthdr, packet);
    }
    else {
        std::cerr << "PcapFileReader Error: packet_writer is null in readPacketHandler. Cannot write packet." << std::endl;
    }
}

// Function to read from a pcap file and write to a PacketWriter implementation.
// We take std::unique_ptr by reference to avoid transferring ownership to this function,
// allowing the caller to retain and manage the lifetime of the PacketWriter.
// If PcapFileReader *should* own it, then writer_impl should be a member.
bool PcapFileReader::readFromFile(const std::string &filename, PacketWriter &writer_impl) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap_file_handle = pcap_open_offline(filename.c_str(), errbuf);

    if (!pcap_file_handle) {
        std::cerr << "PcapFileReader Error: Could not open pcap file '" << filename << "': " << errbuf << std::endl;
        return false;
    }

    if (!writer_impl.open("", pcap_file_handle)) {
        std::cerr << "PcapFileReader Error: Failed to open packet writer for file: " << filename << std::endl;
        pcap_close(pcap_file_handle);
        return false;
    }

    std::cout << "PcapFileReader::readFromFile() successful. " << filename << " is ready for reading." << std::endl;

    int packet_count = 0;

    // Helper lambda to wrap readPacketHandler and count packets
    auto packetHandlerWithCount = [](u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
        auto count_ptr = reinterpret_cast<int*>(user_data);
        (*count_ptr)++;
        // We must also call the original readPacketHandler with writer pointer
        // But currently user_data points to packet_count. Need different approach.
    };

    // Because pcap_loop callback accepts only one user_data pointer,
    // define a small structure holding both writer pointer and count:
    struct CallbackData {
        PacketWriter* writer;
        int count;
    } cb_data { &writer_impl, 0 };

    // Define a new static callback inside this function:
    auto callback = [](u_char* user_data, const pcap_pkthdr* pkthdr, const u_char* packet) {
        CallbackData* data = reinterpret_cast<CallbackData*>(user_data);
        data->count++;
        if (data->writer) {
            data->writer->writePacket(pkthdr, packet);
        } else {
            std::cerr << "PcapFileReader Error: PacketWriter null in callback." << std::endl;
        }
    };

    int result = pcap_loop(pcap_file_handle, 0, callback, reinterpret_cast<u_char*>(&cb_data));

    if (result == -1) {
        std::cerr << "PcapFileReader Error: Error reading packets from file '" << filename << "': " << pcap_geterr(pcap_file_handle) << std::endl;
    } else if (result == -2) {
        std::cout << "PcapFileReader Info: Reading packets stopped by callback (pcap_breakloop called)." << std::endl;
    } else {
        std::cout << "PcapFileReader Info: Finished reading " << cb_data.count << " packets from file '" << filename << "'." << std::endl;
    }

    writer_impl.close();
    pcap_close(pcap_file_handle);

    return result != -1;
}