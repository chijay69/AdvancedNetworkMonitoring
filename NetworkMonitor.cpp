//
// Created by HomePC on 5/24/2025.
//
#include "NetworkMonitor.h"
#include "PacketParser.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <chrono>
#include <pcap/pcap.h>



static const std::map<uint16_t, std::string> ETHER_TYPES = {
    {0x0800, "IPv4"},
    {0x0806, "ARP"},
    {0x86DD, "IPv6"},
    {0x8100, "VLAN"},
    {0x8847, "MPLS"},
    {0x8863, "PPPoE Discovery"},
    {0x8864, "PPPoE Session"}
};



NetworkMonitor::NetworkMonitor(size_t history_s) :
current_bytes_per_second_(0),
current_packets_per_second_(0),
interval_bytes_(0),
interval_packets_(0),
bandwidth_threshold_mbps_(100.0),
packet_rate_threshold_(10000),
stop_monitoring_(true),
history_duration__s(history_s),
last_updated_time_(std::chrono::system_clock::now()){
    std::cout << "NetworkMonitor::NetworkMonitor()" << std::endl;
}

NetworkMonitor::~NetworkMonitor() {
    std::cout << "NetworkMonitor::~NetworkMonitor()" << std::endl;
    stopMonitoring();
}

void NetworkMonitor::processPacket(const pcap_pkthdr *header, const u_char *packet) {
    if ( !header || !packet) return;

    size_t packet_size = header->len;

    if (header->caplen <sizeof(ether_header)) return;

    const ether_header *eth = reinterpret_cast<const ether_header*>(packet);
    uint16_t ethertype = ntohs(eth->ether_type);

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        interval_bytes_ += packet_size;
        interval_packets_++;
        interval_protocols_[ethertype]++;

        auto[src_addr, dst_addr] = extractAddresses(packet, ethertype);

        if (!src_addr.empty()) {
            auto now = std::chrono::system_clock::now();

            if (host_stats_.find(src_addr) == host_stats_.end()) {
                // This is a new host
                host_stats_[src_addr] = {
                    src_addr,
                    getMacAddressString(eth->ether_shost),
                    packet_size, 0, 1, 0, now, now
                };
            } else {
                // existing host
                host_stats_[src_addr].bytes_sent += packet_size;
                host_stats_[src_addr].packets_sent++;
                host_stats_[src_addr].last_seen = now;
            }
            // destination host
            if (!dst_addr.empty() && dst_addr != "ff:ff:ff:ff:ff:ff" &&
                !dst_addr.starts_with("01:00:5e") && !dst_addr.starts_with("33:33")) {
                if (host_stats_.find(dst_addr) == host_stats_.end()) {
                    // This is a new host
                    host_stats_[dst_addr] = {
                        dst_addr,
                        getMacAddressString(eth->ether_dhost),
                        0, packet_size, 1, 0, now, now
                    };
                } else {
                    // existing
                    host_stats_[dst_addr].bytes_received += packet_size;
                    host_stats_[dst_addr].packets_received++;
                    host_stats_[dst_addr].last_seen = now;
                }
            }
        }
    }
}

void NetworkMonitor::startMonitoring() {

    if (!stop_monitoring_) return;

    stop_monitoring_ = false;

    last_updated_time_ = std::chrono::system_clock::now();

    //start monitoring thread
    monitor_thread_ = std::thread(&NetworkMonitor::monitorLoop, this);
    std::cout << "Network monitoring started" << std::endl;
}

void NetworkMonitor::stopMonitoring() {

    if (stop_monitoring_) return;

    stop_monitoring_ = true;

    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
        std::cout << "Network monitoring stopped" << std::endl;
}

void NetworkMonitor::monitorLoop() {
    while (!stop_monitoring_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        updateStatistics();
    }
}

void NetworkMonitor::updateStatistics() {
    auto current_time = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(current_time - last_updated_time_).count();

    if (elapsed < 1) return;

    size_t bytes_per_second = 0 ;
    size_t packets_per_second = 0 ;
    std::map<uint16_t, size_t> protocol_counts;

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        bytes_per_second = interval_bytes_/ elapsed;
        packets_per_second = interval_packets_/ elapsed;
        protocol_counts = interval_protocols_;

        //reset

        interval_bytes_ = 0;
        interval_packets_ = 0;
        interval_protocols_.clear();
    }
    // update atomic values
    current_bytes_per_second_ = bytes_per_second;
    current_packets_per_second_ = packets_per_second;

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        current_protocol_counts_ = protocol_counts;

        // add current statistics to history
        TrafficTimePoint point = {
            current_time,
            bytes_per_second,
            packets_per_second,
            protocol_counts
        };
        traffic_history_.push_back(point);
        if (traffic_history_.size() > history_duration__s) {
            traffic_history_.pop_front();
        }
    }

    last_updated_time_ = current_time;
}

double NetworkMonitor::getCurrentBandwidthMbps() const {

    return(current_bytes_per_second_ * 0.8)/1000000.0;
}

size_t NetworkMonitor::getPacketCountPerSecond() const {
    return current_packets_per_second_;
}

std::vector<TrafficTimePoint> NetworkMonitor::getTrafficHistory() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return std::vector<TrafficTimePoint>(traffic_history_.begin(), traffic_history_.end());
}

std::vector<HostTrafficStatistics> NetworkMonitor::getHostTrafficStatistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    std::vector<HostTrafficStatistics> stats;
    for (const auto &host : host_stats_) {
        stats.push_back(host.second);
    }
    return stats;
}

void NetworkMonitor::printCurrentStats() {
    double mbps = getCurrentBandwidthMbps();
    size_t pps = getPacketCountPerSecond();
    auto protocol_dist = getProtocolDistribution();


    std::cout << "\n ---- Network Statistics ---- " << std::endl;
    std::cout << "Current bandwidth: " << std::fixed << std::setprecision(2) << mbps << " Mbps" << std::endl;
    std::cout << "Current packet rate: " << pps << " packets/sec" << std::endl;

    std::cout << "\nProtocol distribution:"<< std::endl;
    std::cout << "Current protocol distribution: " << std::endl;
    for (const auto & [proto, percentage] : protocol_dist) {
        std::cout << std::setw(10) << proto << " : " << std::fixed << std::setprecision(1) << percentage << "%" << std::endl;
    }
    std::cout << std::endl;

    // Top talkers

    auto top_talkers = getTopTalkers(5);

    std::cout << "\nTop talkers:" << std::endl;
    std::cout << std::left << std::setw(18) << "IP" << std::setw(12)<< std::setw(18) << "MAC" << std::setw(12) << "Sent (KB)" << std::setw(12) << std::setw(12) << "Recv (KB)" <<std::setw(10)<< "Packets"<< std::endl;
    std::cout << std::string(70, '-') << std::endl;

    for (const auto &host : top_talkers) {
        std::cout <<std::left<<std::setw(18) << host.ip_address << " (" << host.mac_address << ")" << std::setw(12) << std::fixed << std::setprecision(1) << host.bytes_sent/1024 << std::setw(12) << host.bytes_received/1024 << std::setw(10) << host.packets_sent + host.packets_received << std::endl;
    }
 // Top listeners

    auto top_listeners = getTopListeners(5);

    std::cout << "\nTop listeners:" << std::endl;
    std::cout << std::left << std::setw(18) << "IP" << std::setw(12)<< std::setw(18) << "MAC" << std::setw(12) << "Sent (KB)" << std::setw(12) << std::setw(12) << "Recv (KB)" <<std::setw(10)<< "Packets"<< std::endl;
    std::cout << std::string(70, '-') << std::endl;

    for (const auto &host : top_listeners) {
        std::cout <<std::left<<std::setw(18) << host.ip_address << " (" << host.mac_address << ")" << std::setw(12) << std::fixed << std::setprecision(1) << host.bytes_sent/1024 << std::setw(12) << host.bytes_received/1024 << std::setw(10) << host.packets_sent + host.packets_received << std::endl;
    }

    // Alert status
    if (isBandwidthThresholdExceeded() || isPacketRateThresholdExceeded()) {
        std::cout << "\nAlert: Bandwidth threshold exceeded or packet rate threshold exceeded" << std::endl;
        if (isBandwidthThresholdExceeded()) {
            std::cout << "\nBandwidth threshold exceeded! (" << mbps <<" Mbps > "<< bandwidth_threshold_mbps_ << " Mbps)" << std::endl;
        }
        if (isPacketRateThresholdExceeded()) {
            std::cout << "\nPacket rate threshold exceeded! (" << pps <<" pps > "<< packet_rate_threshold_ << " pps)" << std::endl;
        }
    }
    std::cout << std::endl;
}

std::map<std::string, double> NetworkMonitor::getProtocolDistribution() {
    std::map<uint16_t, size_t> protocol_counts;
    std::map<std::string, double> result;

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        protocol_counts = current_protocol_counts_;
    }

    // Calculate total packets
    size_t total_packets = 0;
    for (const auto& [proto, count] : protocol_counts) {
        total_packets += count;
    }

    if (total_packets == 0) return result;

    // Calculate percentages
    for (const auto& [proto, count] : protocol_counts) {
        double percentage = (count * 100.0) / total_packets;
        result[getProtocolName(proto)] = percentage;
    }

    return result;
}


void NetworkMonitor::setBandwidthThresholdMbps(double threshold_mbps) {
    bandwidth_threshold_mbps_ = threshold_mbps;
}

void NetworkMonitor::setPacketRateThreshold(size_t threshold_pps) {
    packet_rate_threshold_ = threshold_pps;
}

bool NetworkMonitor::isBandwidthThresholdExceeded() const {
    return getCurrentBandwidthMbps() > bandwidth_threshold_mbps_;
}

bool NetworkMonitor::isPacketRateThresholdExceeded() const {
    return getPacketCountPerSecond() > packet_rate_threshold_;
}

std::string NetworkMonitor::getProtocolName(uint16_t ethertype) const {
    auto it = ETHER_TYPES.find(ethertype);
    if (it != ETHER_TYPES.end()) {
        return it->second;
    }
    // format unkown protocol

    std::stringstream ss;

    ss << "0x" << std::hex << std::setw(4) << std::setfill('0') << ethertype;
    return ss.str();

}

std::string NetworkMonitor::getMacAddressString(const u_char *mac) const {
    std::stringstream ss;
    for (int i =0;  i < 6; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
        if (i < 5) {
            ss << ":";
        }
    }
    return ss.str();
}

std::pair<std::string, std::string> NetworkMonitor::extractAddresses(const u_char *packet, uint16_t ethertype) const {
    const ether_header *eth = reinterpret_cast<const ether_header*>(packet);

    // Default to MAC Address
    std::string src_addr = getMacAddressString(eth->ether_shost);
    std::string dst_addr = getMacAddressString(eth->ether_dhost);

    // For IPv4, try to extract IP Address
    if (ethertype == ETHER_TYPE_IP_V4) {
        const u_char *ip_packet = packet + sizeof(ether_header);
        const ip_header* ip = reinterpret_cast<const ip_header*>(ip_packet);

        // check for valid IPv4 packet
        if (ip->ip_vhl >> 4) {
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];

            // convert IP to string
            if (inet_ntop(AF_INET, ip->ip_src, src_ip, INET_ADDRSTRLEN)) {
                src_addr = src_ip;
            }

            if (inet_ntop(AF_INET, ip->ip_dst, dst_ip, INET_ADDRSTRLEN)) {
                dst_addr = dst_ip;
            }
        }
    }
    return {src_addr, dst_addr};
}

/**
 * @brief Retrieves a vector of HostTrafficStatistics, sorted by hosts that have sent the most data.
 * "Top Talkers" are defined by the total bytes sent, then by packets sent if bytes are equal.
 * @param count The maximum number of top talkers to return. Defaults to 10.
 * @return A vector of HostTrafficStatistics for the top talkers.
 */
std::vector<HostTrafficStatistics> NetworkMonitor::getTopTalkers(size_t count) {
    std::vector<HostTrafficStatistics> result;

    // Acquire a lock to protect host_stats_ during iteration
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        // Populate the result vector with all host statistics
        for (const auto & [addr, stats] : host_stats_) {
            result.push_back(stats);
        }
    }

    // Sort the hosts based on bytes sent (descending), then packets sent (descending)
    // A host is a "top talker" if it has sent more bytes. If bytes are equal,
    // then the one that sent more packets is considered "more of a talker".
    std::sort(result.begin(), result.end(), [](const HostTrafficStatistics &a, const HostTrafficStatistics &b) {
        // Primary sort: by bytes_sent in descending order
        if (a.bytes_sent != b.bytes_sent) {
            return a.bytes_sent > b.bytes_sent;
        }
        // Secondary sort: if bytes_sent are equal, sort by packets_sent in descending order
        return a.packets_sent > b.packets_sent;
    });

    // Resize the result vector to return only the 'count' top talkers
    if (result.size() > count) {
        result.resize(count);
    }
    return result;
}

/**
 * @brief Retrieves a vector of HostTrafficStatistics, sorted by hosts that have received the most data.
 * "Top Listeners" are defined by the total bytes received, then by packets received if bytes are equal.
 * @param count The maximum number of top listeners to return. Defaults to 10.
 * @return A vector of HostTrafficStatistics for the top listeners.
 */
std::vector<HostTrafficStatistics> NetworkMonitor::getTopListeners(size_t count) {
    std::vector<HostTrafficStatistics> result;
    // Acquire a lock to protect host_stats_ during iteration
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        // Populate the result vector with all host statistics
        for (const auto & [addr, stats] : host_stats_) {
            result.push_back(stats);
        }
    }

    // Sort the hosts based on bytes received (descending), then packets received (descending)
    // A host is a "top listener" if it has received more bytes. If bytes are equal,
    // then the one that received more packets is considered "more of a listener".
    std::sort(result.begin(), result.end(), [](const HostTrafficStatistics &a, const HostTrafficStatistics &b) {
        // Primary sort: by bytes_received in descending order
        if (a.bytes_received != b.bytes_received) {
            return a.bytes_received > b.bytes_received;
        }
        // Secondary sort: if bytes_received are equal, sort by packets_received in descending order
        return a.packets_received > b.packets_received;
    });

    // Resize the result vector to return only the 'count' top listeners
    if (result.size() > count) {
        result.resize(count);
    }
    return result;
}








