//
// Created by HomePC on 5/24/2025.
//

#ifndef NETWORKMONITOR_H
#define NETWORKMONITOR_H

#include <chrono>
#include <string>
#include <map>
#include <vector>
#include  <mutex>
#include <thread>
#include <atomic>
#include  <deque>
#include <pcap/pcap.h>

#include "PacketStructs.h"


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

    void processPacket(const pcap_pkthdr *header, const u_char *packet);

    void startMonitoring();
    void stopMonitoring();

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
};
#endif //NETWORKMONITOR_H
