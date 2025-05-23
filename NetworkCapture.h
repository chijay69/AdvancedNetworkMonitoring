//
// Created by HomePC on 5/22/2025.
//

#ifndef NETWORKCAPTURE_H
#define NETWORKCAPTURE_H

#include "PacketWriter.h"
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <pcap/pcap.h>

class NetworkCapture {
public:
    NetworkCapture(std::unique_ptr<PacketWriter> writer_impl);
    ~NetworkCapture();

    bool listDevices();
    bool selectDevice();
    bool startCapture(int duration_s, const std::string &output_destination);
    void stop_capture();

    // New helper methods for the scanner
    std::vector<u_char> getSourceMacAddress() const { return source_mac_; }
    std::string getSourceIpAddress() const { return source_ip_str_; }
    std::string getNetworkPrefix() const { return network_prefix_str_; } // e.g., "192.168.1"
    pcap_t* getPcapHandle() const { return live_pcap_handler; } // For scanner to use

private:
    std::unique_ptr<PacketWriter> packet_writer_;
    std::string selected_device_name_;
    pcap_t *live_pcap_handler = nullptr;
    pcap_if_t *all_devices = nullptr;
    //
    std::atomic<bool> stop_capture_flag_;
    std::thread capture_thread_;
    // New members for scanner
    std::vector<u_char> source_mac_;
    std::string source_ip_str_;
    std::string network_prefix_str_;
    //
    static void packetHandler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
    void captureLoop();

    // Helper to get device MAC and IP
    bool getDeviceMacAndIp(pcap_if_t* d);
};

#endif //NETWORKCAPTURE_H
