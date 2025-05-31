// //
// // Created by HomePC on 5/24/2025.
// //
//
// #ifndef NETWORKMONITOR_H
// #define NETWORKMONITOR_H
//
// #include <chrono>
// #include <string>
// #include <map>
// #include <vector>
// #include  <mutex>
// #include <thread>
// #include <atomic>
// #include  <deque>
// #include <pcap/pcap.h>
//
// #include "PacketStructs.h"
//
//
// // Represents a sliding window of traffic statistics
// struct TrafficTimePoint {
//     std::chrono::system_clock::time_point timestamp;
//     size_t bytes_per_second;
//     size_t packets_per_second;
//     std::map<uint16_t, size_t> protocol_distribution; // EtherType -> count
// };
//
// // Per-host traffic statistics
// struct HostTrafficStatistics {
//     std::string ip_address;
//     std::string mac_address;
//     size_t bytes_sent;
//     size_t bytes_received;
//     size_t packets_sent;
//     size_t packets_received;
//     std::chrono::system_clock::time_point first_seen;
//     std::chrono::system_clock::time_point last_seen;
// };
//
//
// class NetworkMonitor {
// public:
//     NetworkMonitor(size_t history_s = 60);
//     ~NetworkMonitor();
//
//     void processPacket(const pcap_pkthdr *header, const u_char *packet);
//
//     void startMonitoring();
//     void stopMonitoring();
//
//     double getCurrentBandwidthMbps() const;
//     size_t getPacketCountPerSecond() const;
//
//     std::vector<TrafficTimePoint> getTrafficHistory();
//     std::vector<HostTrafficStatistics> getHostTrafficStatistics() const;
//     std::vector<HostTrafficStatistics> getTopTalkers(size_t count = 10);
//     std::vector<HostTrafficStatistics> getTopListeners(size_t count = 10);
//
//     void printCurrentStats();
//
//     std::map<std::string, double> getProtocolDistribution();
//
//     void setBandwidthThresholdMbps(double threshold_mbps);
//
//     void setPacketRateThreshold(size_t threshold_pps);
//
//     bool isBandwidthThresholdExceeded() const;
//     bool isPacketRateThresholdExceeded() const;
//
// private:
//     std::map<uint16_t, size_t> current_protocol_counts_;
//     std::deque<TrafficTimePoint> traffic_history_;
//     std::map<std::string, HostTrafficStatistics> host_stats_; //IP -> HostStats
//
//     std::atomic<size_t> current_bytes_per_second_;
//     std::atomic<size_t> current_packets_per_second_;
//     std::map<uint16_t, size_t> interval_protocols_counts;
//
//     size_t interval_bytes_;
//     size_t interval_packets_;
//     std::map<uint16_t, size_t> interval_protocols_;
//
//     double bandwidth_threshold_mbps_;
//     size_t packet_rate_threshold_;
//
//     std::atomic<bool> stop_monitoring_;
//     std::thread monitor_thread_;
//     mutable std::mutex stats_mutex_;
//
//     size_t history_duration__s;
//     std::chrono::system_clock::time_point last_updated_time_;
//
//     void monitorLoop();
//     void updateStatistics();
//
//     std::string getProtocolName(uint16_t ethertype) const;
//
//     std::string getMacAddressString(const u_char *mac) const;
//
//     std::pair<std::string, std::string> extractAddresses(const u_char* packet, uint16_t ethertype) const;
// };
// #endif //NETWORKMONITOR_H


//
// Created by HomePC on 5/22/2025.
//

#ifndef NETWORKMONITOR_H
#define NETWORKMONITOR_H

#include <deque>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <map>    // For discovered hosts
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#include <pcap/pcap.h> // For pcap_t, pcap_pkthdr
#include "PacketWriter.h"
#include "PacketStructs.h"
#include "DiscoveryManager.h" // <--- NEW: Include DiscoveryManager

// Represents a sliding window of traffic statistics
struct TrafficTimePoint {
    std::chrono::system_clock::time_point timestamp;
    size_t bytes_per_second;
    size_t packets_per_second;
    std::map<uint16_t, size_t> protocol_distribution; // EtherType -> count
};

// Per-host traffic statistics
struct HostTrafficStatistics {
    std::string ip_address;
    std::string mac_address;
    size_t bytes_sent;
    size_t bytes_received;
    size_t packets_sent;
    size_t packets_received;
    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_seen;
};

class NetworkMonitor {
public:
    NetworkMonitor(size_t history_s = 60);
    ~NetworkMonitor();

    // Initializes the network monitor, including pcap setup
    bool initialize(const std::string& interface_name, int snaplen, int promisc, int to_ms, char* errbuf);

    // Starts live packet capture
    void startLiveCapture(int duration_seconds, PacketWriter* writer);

    // Stops live packet capture
    void stopLiveCapture();

    // Getter for the pcap_t handle, needed by PcapFileWriter
    pcap_t* getPcapHandle() const { return pcap_handle_; } // <--- NEW: Getter for pcap_handle_

    void processPacket(const pcap_pkthdr *header, const u_char *packet);

    void startMonitoring();
    void stopMonitoring();

    // Performs an ARP scan and prints discovered hosts
    void performArpScan(const std::string& network_prefix, int start_host_ip, int end_host_ip);
    // <--- NEW: Methods for advanced discovery ---
    void performIpRangeDiscovery(const std::string& network_prefix, int start_host_ip, int end_host_ip, bool perform_ping, const std::vector<u_short>& common_ports);
    void performDNSDiscovery(const std::string& domain_name, const std::string& dns_server_ip);
    void performADDiscovery(const std::string& ad_domain, const std::string& username, const std::string& password);
    void performManualDeviceAddition(const std::string& ip_address, const std::string& mac_address);
    void performSNMPDiscoveryOnDiscoveredDevices(const std::string& snmp_version, const std::string& community_or_username);
    // -------------------------------------------

    // Prints network statistics (placeholder for now, actual implementation in NetworkMonitor.cpp)
    void printNetworkStatistics() const;



    double getCurrentBandwidthMbps() const;
    size_t getPacketCountPerSecond() const;
    std::vector<TrafficTimePoint> getTrafficHistory();
    std::vector<HostTrafficStatistics> getHostTrafficStatistics() const;
    std::vector<HostTrafficStatistics> getTopTalkers(size_t count = 10);
    std::vector<HostTrafficStatistics> getTopListeners(size_t count = 10);

    void printCurrentStats();
    std::map<std::string, double> getProtocolDistribution();
    void setBandwidthThresholdMbps(double threshold_mbps);
    void setPacketRateThreshold(size_t threshold_pps);

    bool isBandwidthThresholdExceeded() const;
    bool isPacketRateThresholdExceeded() const;

private:
    std::map<uint16_t, size_t> current_protocol_counts_;
    std::deque<TrafficTimePoint> traffic_history_;
    std::map<std::string, HostTrafficStatistics> host_stats_; //IP -> HostStats

    std::atomic<size_t> current_bytes_per_second_;
    std::atomic<size_t> current_packets_per_second_;
    std::map<uint16_t, size_t> interval_protocols_counts;

    size_t interval_bytes_;
    size_t interval_packets_;
    std::map<uint16_t, size_t> interval_protocols_;

    double bandwidth_threshold_mbps_;
    size_t packet_rate_threshold_;

    std::atomic<bool> stop_monitoring_;
    std::thread monitor_thread_;
    mutable std::mutex stats_mutex_;

    size_t history_duration__s;
    std::chrono::system_clock::time_point last_updated_time_;

    void monitorLoop();
    void updateStatistics();
    std::string getProtocolName(uint16_t ethertype) const;
    std::string getMacAddressString(const u_char *mac) const;
    std::pair<std::string, std::string> extractAddresses(const u_char* packet, uint16_t ethertype) const;

    pcap_t* pcap_handle_; // PCAP capture handle
    bool capture_running_; // Flag to control capture loop
    std::vector<u_char> source_mac_address_; // MAC address of the selected interface
    std::string source_ip_address_; // IP address of the selected interface
    PacketWriter* active_packet_writer_{}; // <--- NEW: Stores the writer passed to startLiveCapture
    std::unique_ptr<DiscoveryManager> discovery_manager_; // <--- NEW: DiscoveryManager instance
    std::map<std::string, DiscoveredDevice> all_discovered_devices_; // Stores all discovered devices

    // Callback function for pcap_loop/pcap_dispatch
    static void packetHandler(u_char *user_data, const pcap_pkthdr *pkthdr, const u_char *packet);
};

#endif // NETWORKMONITOR_H
