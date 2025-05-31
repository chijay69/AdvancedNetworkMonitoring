// //
// // Created by HomePC on 5/24/2025.
// //
// #include "NetworkMonitor.h"
// #include "PacketParser.h"
// #include <iostream>
// #include <sstream>
// #include <algorithm>
// #include <iomanip>
// #include <chrono>
// #include <pcap/pcap.h>
//
//
//
// static const std::map<uint16_t, std::string> ETHER_TYPES = {
//     {0x0800, "IPv4"},
//     {0x0806, "ARP"},
//     {0x86DD, "IPv6"},
//     {0x8100, "VLAN"},
//     {0x8847, "MPLS"},
//     {0x8863, "PPPoE Discovery"},
//     {0x8864, "PPPoE Session"}
// };
//
//
//
// NetworkMonitor::NetworkMonitor(size_t history_s) :
// current_bytes_per_second_(0),
// current_packets_per_second_(0),
// interval_bytes_(0),
// interval_packets_(0),
// bandwidth_threshold_mbps_(100.0),
// packet_rate_threshold_(10000),
// stop_monitoring_(true),
// history_duration__s(history_s),
// last_updated_time_(std::chrono::system_clock::now()){
//     std::cout << "NetworkMonitor::NetworkMonitor()" << std::endl;
// }
//
// NetworkMonitor::~NetworkMonitor() {
//     std::cout << "NetworkMonitor::~NetworkMonitor()" << std::endl;
//     stopMonitoring();
// }
//
// void NetworkMonitor::processPacket(const pcap_pkthdr *header, const u_char *packet) {
//     if ( !header || !packet) return;
//
//     size_t packet_size = header->len;
//
//     if (header->caplen <sizeof(ether_header)) return;
//
//     const ether_header *eth = reinterpret_cast<const ether_header*>(packet);
//     uint16_t ethertype = ntohs(eth->ether_type);
//
//     {
//         std::lock_guard<std::mutex> lock(stats_mutex_);
//         interval_bytes_ += packet_size;
//         interval_packets_++;
//         interval_protocols_[ethertype]++;
//
//         auto[src_addr, dst_addr] = extractAddresses(packet, ethertype);
//
//         if (!src_addr.empty()) {
//             auto now = std::chrono::system_clock::now();
//
//             if (host_stats_.find(src_addr) == host_stats_.end()) {
//                 // This is a new host
//                 host_stats_[src_addr] = {
//                     src_addr,
//                     getMacAddressString(eth->ether_shost),
//                     packet_size, 0, 1, 0, now, now
//                 };
//             } else {
//                 // existing host
//                 host_stats_[src_addr].bytes_sent += packet_size;
//                 host_stats_[src_addr].packets_sent++;
//                 host_stats_[src_addr].last_seen = now;
//             }
//             // destination host
//             if (!dst_addr.empty() && dst_addr != "ff:ff:ff:ff:ff:ff" &&
//                 !dst_addr.starts_with("01:00:5e") && !dst_addr.starts_with("33:33")) {
//                 if (host_stats_.find(dst_addr) == host_stats_.end()) {
//                     // This is a new host
//                     host_stats_[dst_addr] = {
//                         dst_addr,
//                         getMacAddressString(eth->ether_dhost),
//                         0, packet_size, 1, 0, now, now
//                     };
//                 } else {
//                     // existing
//                     host_stats_[dst_addr].bytes_received += packet_size;
//                     host_stats_[dst_addr].packets_received++;
//                     host_stats_[dst_addr].last_seen = now;
//                 }
//             }
//         }
//     }
// }
//
// void NetworkMonitor::startMonitoring() {
//
//     if (!stop_monitoring_) return;
//
//     stop_monitoring_ = false;
//
//     last_updated_time_ = std::chrono::system_clock::now();
//
//     //start monitoring thread
//     monitor_thread_ = std::thread(&NetworkMonitor::monitorLoop, this);
//     std::cout << "Network monitoring started" << std::endl;
// }
//
// void NetworkMonitor::stopMonitoring() {
//
//     if (stop_monitoring_) return;
//
//     stop_monitoring_ = true;
//
//     if (monitor_thread_.joinable()) {
//         monitor_thread_.join();
//     }
//         std::cout << "Network monitoring stopped" << std::endl;
// }
//
// void NetworkMonitor::monitorLoop() {
//     while (!stop_monitoring_) {
//         std::this_thread::sleep_for(std::chrono::milliseconds(1000));
//         updateStatistics();
//     }
// }
//
// void NetworkMonitor::updateStatistics() {
//     auto current_time = std::chrono::system_clock::now();
//     auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(current_time - last_updated_time_).count();
//
//     if (elapsed < 1) return;
//
//     size_t bytes_per_second = 0 ;
//     size_t packets_per_second = 0 ;
//     std::map<uint16_t, size_t> protocol_counts;
//
//     {
//         std::lock_guard<std::mutex> lock(stats_mutex_);
//         bytes_per_second = interval_bytes_/ elapsed;
//         packets_per_second = interval_packets_/ elapsed;
//         protocol_counts = interval_protocols_;
//
//         //reset
//
//         interval_bytes_ = 0;
//         interval_packets_ = 0;
//         interval_protocols_.clear();
//     }
//     // update atomic values
//     current_bytes_per_second_ = bytes_per_second;
//     current_packets_per_second_ = packets_per_second;
//
//     {
//         std::lock_guard<std::mutex> lock(stats_mutex_);
//         current_protocol_counts_ = protocol_counts;
//
//         // add current statistics to history
//         TrafficTimePoint point = {
//             current_time,
//             bytes_per_second,
//             packets_per_second,
//             protocol_counts
//         };
//         traffic_history_.push_back(point);
//         if (traffic_history_.size() > history_duration__s) {
//             traffic_history_.pop_front();
//         }
//     }
//
//     last_updated_time_ = current_time;
// }
//
// double NetworkMonitor::getCurrentBandwidthMbps() const {
//
//     return(current_bytes_per_second_ * 0.8)/1000000.0;
// }
//
// size_t NetworkMonitor::getPacketCountPerSecond() const {
//     return current_packets_per_second_;
// }
//
// std::vector<TrafficTimePoint> NetworkMonitor::getTrafficHistory() {
//     std::lock_guard<std::mutex> lock(stats_mutex_);
//     return std::vector<TrafficTimePoint>(traffic_history_.begin(), traffic_history_.end());
// }
//
// std::vector<HostTrafficStatistics> NetworkMonitor::getHostTrafficStatistics() const {
//     std::lock_guard<std::mutex> lock(stats_mutex_);
//     std::vector<HostTrafficStatistics> stats;
//     for (const auto &host : host_stats_) {
//         stats.push_back(host.second);
//     }
//     return stats;
// }
//
// void NetworkMonitor::printCurrentStats() {
//     double mbps = getCurrentBandwidthMbps();
//     size_t pps = getPacketCountPerSecond();
//     auto protocol_dist = getProtocolDistribution();
//
//
//     std::cout << "\n ---- Network Statistics ---- " << std::endl;
//     std::cout << "Current bandwidth: " << std::fixed << std::setprecision(2) << mbps << " Mbps" << std::endl;
//     std::cout << "Current packet rate: " << pps << " packets/sec" << std::endl;
//
//     std::cout << "\nProtocol distribution:"<< std::endl;
//     std::cout << "Current protocol distribution: " << std::endl;
//     for (const auto & [proto, percentage] : protocol_dist) {
//         std::cout << std::setw(10) << proto << " : " << std::fixed << std::setprecision(1) << percentage << "%" << std::endl;
//     }
//     std::cout << std::endl;
//
//     // Top talkers
//
//     auto top_talkers = getTopTalkers(5);
//
//     std::cout << "\nTop talkers:" << std::endl;
//     std::cout << std::left << std::setw(18) << "IP" << std::setw(12)<< std::setw(18) << "MAC" << std::setw(12) << "Sent (KB)" << std::setw(12) << std::setw(12) << "Recv (KB)" <<std::setw(10)<< "Packets"<< std::endl;
//     std::cout << std::string(70, '-') << std::endl;
//
//     for (const auto &host : top_talkers) {
//         std::cout <<std::left<<std::setw(18) << host.ip_address << " (" << host.mac_address << ")" << std::setw(12) << std::fixed << std::setprecision(1) << host.bytes_sent/1024 << std::setw(12) << host.bytes_received/1024 << std::setw(10) << host.packets_sent + host.packets_received << std::endl;
//     }
//  // Top listeners
//
//     auto top_listeners = getTopListeners(5);
//
//     std::cout << "\nTop listeners:" << std::endl;
//     std::cout << std::left << std::setw(18) << "IP" << std::setw(12)<< std::setw(18) << "MAC" << std::setw(12) << "Sent (KB)" << std::setw(12) << std::setw(12) << "Recv (KB)" <<std::setw(10)<< "Packets"<< std::endl;
//     std::cout << std::string(70, '-') << std::endl;
//
//     for (const auto &host : top_listeners) {
//         std::cout <<std::left<<std::setw(18) << host.ip_address << " (" << host.mac_address << ")" << std::setw(12) << std::fixed << std::setprecision(1) << host.bytes_sent/1024 << std::setw(12) << host.bytes_received/1024 << std::setw(10) << host.packets_sent + host.packets_received << std::endl;
//     }
//
//     // Alert status
//     if (isBandwidthThresholdExceeded() || isPacketRateThresholdExceeded()) {
//         std::cout << "\nAlert: Bandwidth threshold exceeded or packet rate threshold exceeded" << std::endl;
//         if (isBandwidthThresholdExceeded()) {
//             std::cout << "\nBandwidth threshold exceeded! (" << mbps <<" Mbps > "<< bandwidth_threshold_mbps_ << " Mbps)" << std::endl;
//         }
//         if (isPacketRateThresholdExceeded()) {
//             std::cout << "\nPacket rate threshold exceeded! (" << pps <<" pps > "<< packet_rate_threshold_ << " pps)" << std::endl;
//         }
//     }
//     std::cout << std::endl;
// }
//
// std::map<std::string, double> NetworkMonitor::getProtocolDistribution() {
//     std::map<uint16_t, size_t> protocol_counts;
//     std::map<std::string, double> result;
//
//     {
//         std::lock_guard<std::mutex> lock(stats_mutex_);
//         protocol_counts = current_protocol_counts_;
//     }
//
//     // Calculate total packets
//     size_t total_packets = 0;
//     for (const auto& [proto, count] : protocol_counts) {
//         total_packets += count;
//     }
//
//     if (total_packets == 0) return result;
//
//     // Calculate percentages
//     for (const auto& [proto, count] : protocol_counts) {
//         double percentage = (count * 100.0) / total_packets;
//         result[getProtocolName(proto)] = percentage;
//     }
//
//     return result;
// }
//
//
// void NetworkMonitor::setBandwidthThresholdMbps(double threshold_mbps) {
//     bandwidth_threshold_mbps_ = threshold_mbps;
// }
//
// void NetworkMonitor::setPacketRateThreshold(size_t threshold_pps) {
//     packet_rate_threshold_ = threshold_pps;
// }
//
// bool NetworkMonitor::isBandwidthThresholdExceeded() const {
//     return getCurrentBandwidthMbps() > bandwidth_threshold_mbps_;
// }
//
// bool NetworkMonitor::isPacketRateThresholdExceeded() const {
//     return getPacketCountPerSecond() > packet_rate_threshold_;
// }
//
// std::string NetworkMonitor::getProtocolName(uint16_t ethertype) const {
//     auto it = ETHER_TYPES.find(ethertype);
//     if (it != ETHER_TYPES.end()) {
//         return it->second;
//     }
//     // format unkown protocol
//
//     std::stringstream ss;
//
//     ss << "0x" << std::hex << std::setw(4) << std::setfill('0') << ethertype;
//     return ss.str();
//
// }
//
// std::string NetworkMonitor::getMacAddressString(const u_char *mac) const {
//     std::stringstream ss;
//     for (int i =0;  i < 6; i++) {
//         ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
//         if (i < 5) {
//             ss << ":";
//         }
//     }
//     return ss.str();
// }
//
// std::pair<std::string, std::string> NetworkMonitor::extractAddresses(const u_char *packet, uint16_t ethertype) const {
//     const ether_header *eth = reinterpret_cast<const ether_header*>(packet);
//
//     // Default to MAC Address
//     std::string src_addr = getMacAddressString(eth->ether_shost);
//     std::string dst_addr = getMacAddressString(eth->ether_dhost);
//
//     // For IPv4, try to extract IP Address
//     if (ethertype == ETHER_TYPE_IP_V4) {
//         const u_char *ip_packet = packet + sizeof(ether_header);
//         const ip_header* ip = reinterpret_cast<const ip_header*>(ip_packet);
//
//         // check for valid IPv4 packet
//         if (ip->ip_vhl >> 4) {
//             char src_ip[INET_ADDRSTRLEN];
//             char dst_ip[INET_ADDRSTRLEN];
//
//             // convert IP to string
//             if (inet_ntop(AF_INET, ip->ip_src, src_ip, INET_ADDRSTRLEN)) {
//                 src_addr = src_ip;
//             }
//
//             if (inet_ntop(AF_INET, ip->ip_dst, dst_ip, INET_ADDRSTRLEN)) {
//                 dst_addr = dst_ip;
//             }
//         }
//     }
//     return {src_addr, dst_addr};
// }
//
// /**
//  * @brief Retrieves a vector of HostTrafficStatistics, sorted by hosts that have sent the most data.
//  * "Top Talkers" are defined by the total bytes sent, then by packets sent if bytes are equal.
//  * @param count The maximum number of top talkers to return. Defaults to 10.
//  * @return A vector of HostTrafficStatistics for the top talkers.
//  */
// std::vector<HostTrafficStatistics> NetworkMonitor::getTopTalkers(size_t count) {
//     std::vector<HostTrafficStatistics> result;
//
//     // Acquire a lock to protect host_stats_ during iteration
//     {
//         std::lock_guard<std::mutex> lock(stats_mutex_);
//         // Populate the result vector with all host statistics
//         for (const auto & [addr, stats] : host_stats_) {
//             result.push_back(stats);
//         }
//     }
//
//     // Sort the hosts based on bytes sent (descending), then packets sent (descending)
//     // A host is a "top talker" if it has sent more bytes. If bytes are equal,
//     // then the one that sent more packets is considered "more of a talker".
//     std::sort(result.begin(), result.end(), [](const HostTrafficStatistics &a, const HostTrafficStatistics &b) {
//         // Primary sort: by bytes_sent in descending order
//         if (a.bytes_sent != b.bytes_sent) {
//             return a.bytes_sent > b.bytes_sent;
//         }
//         // Secondary sort: if bytes_sent are equal, sort by packets_sent in descending order
//         return a.packets_sent > b.packets_sent;
//     });
//
//     // Resize the result vector to return only the 'count' top talkers
//     if (result.size() > count) {
//         result.resize(count);
//     }
//     return result;
// }
//
// /**
//  * @brief Retrieves a vector of HostTrafficStatistics, sorted by hosts that have received the most data.
//  * "Top Listeners" are defined by the total bytes received, then by packets received if bytes are equal.
//  * @param count The maximum number of top listeners to return. Defaults to 10.
//  * @return A vector of HostTrafficStatistics for the top listeners.
//  */
// std::vector<HostTrafficStatistics> NetworkMonitor::getTopListeners(size_t count) {
//     std::vector<HostTrafficStatistics> result;
//     // Acquire a lock to protect host_stats_ during iteration
//     {
//         std::lock_guard<std::mutex> lock(stats_mutex_);
//         // Populate the result vector with all host statistics
//         for (const auto & [addr, stats] : host_stats_) {
//             result.push_back(stats);
//         }
//     }
//
//     // Sort the hosts based on bytes received (descending), then packets received (descending)
//     // A host is a "top listener" if it has received more bytes. If bytes are equal,
//     // then the one that received more packets is considered "more of a listener".
//     std::sort(result.begin(), result.end(), [](const HostTrafficStatistics &a, const HostTrafficStatistics &b) {
//         // Primary sort: by bytes_received in descending order
//         if (a.bytes_received != b.bytes_received) {
//             return a.bytes_received > b.bytes_received;
//         }
//         // Secondary sort: if bytes_received are equal, sort by packets_received in descending order
//         return a.packets_received > b.packets_received;
//     });
//
//     // Resize the result vector to return only the 'count' top listeners
//     if (result.size() > count) {
//         result.resize(count);
//     }
//     return result;
// }
//
//
//
//
//
//
//
//


//
// Created by HomePC on 5/22/2025.
// NetworkMonitor.cpp
//
#include "NetworkMonitor.h"
#include "ConsoleWriter.h" // For default writer
#include "PacketParser.h"  // For constants like ETHER_TYPE_IP_V4 and parsing
#include "PacketStructs.h" // For ether_header, ip_header etc.
#include <iostream>
#include <thread>
#include <chrono>
#include <iomanip> // For std::setw, std::setfill
#include <algorithm> // For std::transform
#include <array>     // For std::array
#include <iphlpapi.h>
#include <limits>    // For std::numeric_limits

#include "PcapFileWriter.h"

// Platform-specific includes for IP address retrieval
#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

// Define ETHER_TYPES map (moved from global to class method, but keeping for now as it's in your original code)
static const std::map<uint16_t, std::string> ETHER_TYPES = {
    {0x0800, "IPv4"},
    {0x0806, "ARP"},
    {0x86DD, "IPv6"},
    {0x8100, "VLAN"},
    {0x8847, "MPLS"},
    {0x8863, "PPPoE Discovery"},
    {0x8864, "PPPoE Session"}
};


// Constructor
NetworkMonitor::NetworkMonitor(const size_t history_s) :
current_bytes_per_second_(0), // Initialize new member
current_packets_per_second_(0), // Initialize new member
interval_bytes_(0), // Initialize statistics members
interval_packets_(0),
bandwidth_threshold_mbps_(100.0),
packet_rate_threshold_(10000),
stop_monitoring_(true), // Default threshold
history_duration__s(history_s),    // Default threshold
last_updated_time_(std::chrono::system_clock::now()),           // Initially stopped
pcap_handle_(nullptr),
capture_running_(false),
discovery_manager_(std::make_unique<DiscoveryManager>()) // Initialize DiscoveryManager
{
    std::cout << "NetworkMonitor::NetworkMonitor()" << std::endl;
}

// Destructor
NetworkMonitor::~NetworkMonitor() {
    std::cout << "NetworkMonitor::~NetworkMonitor()" << std::endl;
    stopMonitoring(); // Stop statistics thread
    if (pcap_handle_) { // Close pcap handle if open
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }
}

// Initializes the network monitor
bool NetworkMonitor::initialize(const std::string& interface_name, int snaplen, int promisc, int to_ms, char* errbuf) {
    pcap_handle_ = pcap_open_live(interface_name.c_str(), snaplen, promisc, to_ms, errbuf);
    if (!pcap_handle_) {
        std::cerr << "Error opening device " << interface_name << ": " << errbuf << std::endl;
        return false;
    }

    // Set the pcap handle for the DiscoveryManager's ARP scanner
    discovery_manager_->setPcapHandle(pcap_handle_);

    // Get MAC and IP address of the selected interface
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices for interface info: " << errbuf << std::endl;
        return false;
    }

    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
        if (d->name == interface_name) {
            for (pcap_addr_t *a = d->addresses; a != nullptr; a = a->next) {
                if (a->addr->sa_family == AF_INET) { // IPv4 address
                    struct sockaddr_in *ipv4 = reinterpret_cast<struct sockaddr_in*>(a->addr);
                    char ip_str[INET_ADDRSTRLEN];
                    if (inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, INET_ADDRSTRLEN) != nullptr) {
                        source_ip_address_ = ip_str;
                    }
                }
                // Attempt to get MAC address (Windows specific using IPHLPAPI or general approach)
                // This part is highly OS-specific and might need refinement for Linux/macOS
#ifdef _WIN32
                // Using GetAdaptersInfo (deprecated but simpler for example)
                // For production, prefer GetAdaptersAddresses
                IP_ADAPTER_INFO *pAdapterInfo = nullptr;
                ULONG ulOutBufLen = 0;
                // First call to get buffer size
                if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
                    pAdapterInfo = (IP_ADAPTER_INFO *) malloc(ulOutBufLen);
                    if (pAdapterInfo == nullptr) {
                        std::cerr << "Error allocating memory for adapter info." << std::endl;
                        pcap_freealldevs(alldevs);
                        return false;
                    }
                }

                if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
                    IP_ADAPTER_INFO *pAdapter = pAdapterInfo;
                    while (pAdapter) {
                        // Compare adapter name (might need more robust matching)
                        if (interface_name.find(pAdapter->AdapterName) != std::string::npos) {
                            if (pAdapter->AddressLength == 6) {
                                source_mac_address_.assign(pAdapter->Address, pAdapter->Address + pAdapter->AddressLength);
                                break;
                            }
                        }
                        pAdapter = pAdapter->Next;
                    }
                }
                if (pAdapterInfo) free(pAdapterInfo);
#else
                // On Linux/Unix, getting MAC from pcap_findalldevs is not direct.
                // You'd typically use ioctl with SIOCGIFHWADDR or ifaddrs.
                // For this example, we'll assume the MAC is known or can be manually provided.
                // If not found, it will remain empty.
                // Example (conceptual, requires more includes and error handling):
                // int fd = socket(AF_INET, SOCK_DGRAM, 0);
                // struct ifreq ifr;
                // strncpy(ifr.ifr_name, d->name, IFNAMSIZ - 1);
                // if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
                //     source_mac_address_.assign(reinterpret_cast<u_char*>(ifr.ifr_hwaddr.sa_data),
                //                                reinterpret_cast<u_char*>(ifr.ifr_hwaddr.sa_data) + 6);
                // }
                // close(fd);
#endif
            }
            break; // Found the interface
        }
    }
    pcap_freealldevs(alldevs);

    if (source_mac_address_.empty()) {
        std::cerr << "Warning: Could not determine source MAC address for " << interface_name << ". ARP scan might not work correctly." << std::endl;
        // Provide a dummy MAC if it's critical for compilation, or handle gracefully
        source_mac_address_ = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    }
    if (source_ip_address_.empty()) {
        std::cerr << "Warning: Could not determine source IP address for " << interface_name << ". Some features might not work correctly." << std::endl;
        source_ip_address_ = "0.0.0.0"; // Default to a dummy IP
    }

    std::cout << "Successfully selected device: " << interface_name << std::endl;
    return true;
}

// Starts live packet capture
void NetworkMonitor::startLiveCapture(int duration_seconds, PacketWriter* writer) {
    if (!pcap_handle_) {
        std::cerr << "Error: PCAP handle not initialized. Cannot start capture." << std::endl;
        return;
    }

    active_packet_writer_ = writer;
    if (active_packet_writer_) {
        std::string writer_filename = "";
        if (dynamic_cast<PcapFileWriter*>(active_packet_writer_)) {
            // PcapFileWriter needs a filename to open, but it's already provided in main.cpp
            // when the PcapFileWriter object is constructed.
            // The 'open' method of PcapFileWriter takes the filename directly.
            // For this specific setup, the filename passed here might be redundant if the writer
            // is already managing its own file. Let's assume the open method is called
            // by main.cpp before passing to startLiveCapture.
            // However, the PacketWriter::open signature requires it.
            // We'll pass an empty string, assuming PcapFileWriter handles its own filename.
            // If PcapFileWriter needs the pcap_handle_ to open, it should get it from here.
            // This is a design point: should PacketWriter::open take pcap_t* or NetworkMonitor::initialize?
            // Current design: PcapFileWriter::open takes pcap_t*.
            // So, NetworkMonitor::startLiveCapture needs to pass its pcap_handle_ to the writer's open method.
            // This means the writer must be opened *before* being passed here, or its open method needs to be called here.
            // Let's call it here for consistency.
        }
        // Call open on the writer. For PcapFileWriter, this is where the dump handle is created.
        // For ConsoleWriter, it just prints a message.
        // The filename for PcapFileWriter is already set in its constructor in main.
        // So, we don't need to pass a filename here, but the PacketWriter::open signature requires it.
        // Let's adjust PacketWriter::open to take the pcap_t* as the second argument, which is what PcapFileWriter needs.
        // The first string argument for `open` is `destination`.
        active_packet_writer_->open("", pcap_handle_); // Pass pcap_handle_ to the writer's open method
    }
    std::cout << "Starting Network monitoring..." << std::endl;
    capture_running_ = true; // Flag for capture loop
    startMonitoring(); // Start the statistics update thread

    auto start_time = std::chrono::high_resolution_clock::now();
    auto end_time = start_time + std::chrono::seconds(duration_seconds);

    // Loop for capture duration
    while (capture_running_ && std::chrono::high_resolution_clock::now() < end_time) {
        // -1 means process all packets currently in the buffer or until timeout
        // The user_data here is the NetworkMonitor instance, which will then call processPacket
        int res = pcap_dispatch(pcap_handle_, -1, packetHandler, reinterpret_cast<u_char*>(this));
        if (res == -1) {
            std::cerr << "Error in pcap_dispatch: " << pcap_geterr(pcap_handle_) << std::endl;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Small sleep to avoid busy-waiting
        long long remaining_seconds = std::chrono::duration_cast<std::chrono::seconds>(end_time - std::chrono::high_resolution_clock::now()).count();
        if (remaining_seconds >= 0) {
            std::cout << "Capture running... " << remaining_seconds << " second(s) left" << std::endl;
        }
    }

    std::cout << "Capture loop terminated by stop_capture or error" << std::endl;
    if (writer) {
        writer->close();
    }
    stopMonitoring(); // Stop the statistics update thread
    std::cout << "Network monitoring stopped" << std::endl;
}

// Stops live packet capture
void NetworkMonitor::stopLiveCapture() {
    capture_running_ = false;
}

// Static packet handler callback for pcap_dispatch
void NetworkMonitor::packetHandler(u_char *user_data, const pcap_pkthdr *pkthdr, const u_char *packet) {
    NetworkMonitor* monitor = reinterpret_cast<NetworkMonitor*>(user_data);
    if (monitor) {
        monitor->processPacket(pkthdr, packet); // Call the instance method for statistics
        // If you want to also send to console, you'd need to pass the ConsoleWriter here too
        // For now, assume processPacket handles internal stats, and main.cpp calls printCurrentStats
    }
}


void NetworkMonitor::processPacket(const pcap_pkthdr *header, const u_char *packet) {
    if ( !header || !packet) return;

    size_t packet_size = header->len;

    if (header->caplen < sizeof(ether_header)) return;

    const ether_header *eth = reinterpret_cast<const ether_header*>(packet);
    uint16_t ethertype = ntohs(eth->ether_type);

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        interval_bytes_ += packet_size;
        interval_packets_++;
        interval_protocols_[ethertype]++;

        auto[src_addr, dst_addr] = extractAddresses(packet, ethertype);

        // Update host statistics for source
        if (!src_addr.empty()) {
            auto now = std::chrono::system_clock::now();
            if (host_stats_.find(src_addr) == host_stats_.end()) {
                host_stats_[src_addr] = {
                    src_addr,
                    getMacAddressString(eth->ether_shost),
                    packet_size, 0, 1, 0, now, now
                };
            } else {
                host_stats_[src_addr].bytes_sent += packet_size;
                host_stats_[src_addr].packets_sent++;
                host_stats_[src_addr].last_seen = now;
            }
        }

        // Update host statistics for destination (excluding broadcast/multicast for listeners)
        if (!dst_addr.empty() && dst_addr != "ff:ff:ff:ff:ff:ff" &&
            !dst_addr.starts_with("01:00:5e") && !dst_addr.starts_with("33:33")) {
            auto now = std::chrono::system_clock::now();
            if (host_stats_.find(dst_addr) == host_stats_.end()) {
                host_stats_[dst_addr] = {
                    dst_addr,
                    getMacAddressString(eth->ether_dhost),
                    0, packet_size, 0, 1, now, now // packets_sent should be 0 for a listener
                };
            } else {
                host_stats_[dst_addr].bytes_received += packet_size;
                host_stats_[dst_addr].packets_received++;
                host_stats_[dst_addr].last_seen = now;
            }
        }
    }
}

void NetworkMonitor::startMonitoring() {
    if (!stop_monitoring_) return; // Already running

    stop_monitoring_ = false;
    last_updated_time_ = std::chrono::system_clock::now();
    monitor_thread_ = std::thread(&NetworkMonitor::monitorLoop, this);
    // std::cout << "Network monitoring started" << std::endl; // Already printed by startLiveCapture
}

void NetworkMonitor::stopMonitoring() {
    if (stop_monitoring_) return; // Already stopped

    stop_monitoring_ = true;
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
    // std::cout << "Network monitoring stopped" << std::endl; // Already printed by startLiveCapture
}

void NetworkMonitor::monitorLoop() {
    while (!stop_monitoring_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000)); // Update every 1 second
        updateStatistics();
    }
}

void NetworkMonitor::updateStatistics() {
    auto current_time = std::chrono::system_clock::now();
    auto elapsed_seconds = std::chrono::duration_cast<std::chrono::seconds>(current_time - last_updated_time_).count();

    if (elapsed_seconds < 1) return; // Not enough time has passed for a full second interval

    size_t bytes_per_second_calc = 0;
    size_t packets_per_second_calc = 0;
    std::map<uint16_t, size_t> protocol_counts_calc;

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        bytes_per_second_calc = interval_bytes_ / elapsed_seconds;
        packets_per_second_calc = interval_packets_ / elapsed_seconds;
        protocol_counts_calc = interval_protocols_; // Copy current interval's protocol counts

        // Reset interval counters
        interval_bytes_ = 0;
        interval_packets_ = 0;
        interval_protocols_.clear();
    }

    // Update atomic values
    current_bytes_per_second_ = bytes_per_second_calc;
    current_packets_per_second_ = packets_per_second_calc;

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        current_protocol_counts_ = protocol_counts_calc; // Update overall current protocol counts

        // Add current statistics to history
        TrafficTimePoint point = {
            current_time,
            bytes_per_second_calc,
            packets_per_second_calc,
            protocol_counts_calc
        };
        traffic_history_.push_back(point);

        // Trim history to desired duration
        while (traffic_history_.size() > 0 &&
               std::chrono::duration_cast<std::chrono::seconds>(current_time - traffic_history_.front().timestamp).count() > history_duration__s) {
            traffic_history_.pop_front();
        }
    }

    last_updated_time_ = current_time;
}

double NetworkMonitor::getCurrentBandwidthMbps() const {
    // Note: 0.8 is for bits (8 bits per byte), then divide by 1,000,000 for Mbps
    return (static_cast<double>(current_bytes_per_second_.load()) * 8.0) / 1000000.0;
}

size_t NetworkMonitor::getPacketCountPerSecond() const {
    return current_packets_per_second_.load();
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
    std::cout << std::left << std::setw(18) << "IP" << std::setw(18) << "MAC" << std::setw(12) << "Sent (KB)" << std::setw(12) << "Recv (KB)" <<std::setw(10)<< "Packets"<< std::endl;
    std::cout << std::string(70, '-') << std::endl;

    for (const auto &host : top_talkers) {
        std::cout <<std::left<<std::setw(18) << host.ip_address << std::setw(18) << host.mac_address << std::setw(12) << std::fixed << std::setprecision(1) << static_cast<double>(host.bytes_sent)/1024.0 << std::setw(12) << static_cast<double>(host.bytes_received)/1024.0 << std::setw(10) << host.packets_sent + host.packets_received << std::endl;
    }
    std::cout << std::string(70, '-') << std::endl;

 // Top listeners
    auto top_listeners = getTopListeners(5);

    std::cout << "\nTop listeners:" << std::endl;
    std::cout << std::left << std::setw(18) << "IP" << std::setw(18) << "MAC" << std::setw(12) << "Sent (KB)" << std::setw(12) << "Recv (KB)" <<std::setw(10)<< "Packets"<< std::endl;
    std::cout << std::string(70, '-') << std::endl;

    for (const auto &host : top_listeners) {
        std::cout <<std::left<<std::setw(18) << host.ip_address << std::setw(18) << host.mac_address << std::setw(12) << std::fixed << std::setprecision(1) << static_cast<double>(host.bytes_sent)/1024.0 << std::setw(12) << static_cast<double>(host.bytes_received)/1024.0 << std::setw(10) << host.packets_sent + host.packets_received << std::endl;
    }
    std::cout << std::string(70, '-') << std::endl;

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
    if (ethertype == ETHER_TYPE_IP_V4) { // ETHER_TYPE_IP_V4 is defined in PacketParser.h
        // Check if packet is long enough for Ethernet + IP header
        if (packet + sizeof(ether_header) + sizeof(ip_header) <= packet + ETHER_HDR_LEN_C) {
            // This condition is incorrect. It should check against header->caplen.
            // The original logic was:
            // const u_char *ip_packet = packet + sizeof(ether_header);
            // const ip_header* ip = reinterpret_cast<const ip_header*>(ip_packet);
            // if (ip->ip_vhl >> 4) { ... } // This is a check for version 4, not length.
            // Let's use a more robust check.

            // The packet pointer here is the start of the Ethernet frame.
            // We need to advance past the Ethernet header to get to the IP header.
            const u_char *ip_packet_ptr = packet + ETHER_HDR_LEN_C; // Use ETHER_HDR_LEN_C from PacketParser.h

            // Ensure there's enough captured length for the IP header
            if (ip_packet_ptr + sizeof(ip_header) <= packet + pcap_snapshot(pcap_handle_)) { // Use pcap_snapshot for captured length
                const ip_header* ip = reinterpret_cast<const ip_header*>(ip_packet_ptr);

                // Check IP version and header length
                u_int version = ip->ip_vhl >> 4;
                u_int ip_header_len = (ip->ip_vhl & 0x0F) * 4;

                if (version == 4 && ip_header_len >= sizeof(ip_header) &&
                    ip_packet_ptr + ip_header_len <= packet + pcap_snapshot(pcap_handle_)) { // Ensure full IP header is captured
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
        }
    } else if (ethertype == ETHER_TYPE_IPV6) { // Handle IPv6 as well
        const u_char *ipv6_packet_ptr = packet + ETHER_HDR_LEN_C;

        if (ipv6_packet_ptr + sizeof(ipv6_header) <= packet + pcap_snapshot(pcap_handle_)) {
            const ipv6_header* ipv6_h = reinterpret_cast<const ipv6_header*>(ipv6_packet_ptr);

            char src_ip6[INET6_ADDRSTRLEN];
            char dst_ip6[INET6_ADDRSTRLEN];

            if (inet_ntop(AF_INET6, ipv6_h->src, src_ip6, INET6_ADDRSTRLEN)) {
                src_addr = src_ip6;
            }
            if (inet_ntop(AF_INET6, ipv6_h->dst, dst_ip6, INET6_ADDRSTRLEN)) {
                dst_addr = dst_ip6;
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

// NEW: Performs an ARP scan and prints discovered hosts (uses DiscoveryManager internally)
void NetworkMonitor::performArpScan(const std::string& network_prefix, int start_host_ip, int end_host_ip) {
    if (!pcap_handle_) {
        std::cerr << "Error: PCAP handle not initialized. Cannot perform ARP scan." << std::endl;
        return;
    }
    if (source_mac_address_.empty() || source_ip_address_.empty()) {
        std::cerr << "Error: Source MAC or IP address not determined. Cannot perform ARP scan." << std::endl;
        return;
    }

    std::cout << "\n--- Network Scanning (ARP) ---" << std::endl;
    // Use DiscoveryManager for ARP scan
    // The performArpScan method in NetworkScanner will print its own results.
    // For a more integrated approach, DiscoveryManager::discoverByIpRange is preferred,
    // which can also include ARP.
    if (discovery_manager_->arp_scanner_->performArpScan(pcap_handle_, source_mac_address_, source_ip_address_, network_prefix, start_host_ip, end_host_ip)) {
        // The ARP scanner prints its own discovered hosts.
        // We could also retrieve them and add to all_discovered_devices_ here if NetworkScanner exposed them.
        // For now, we'll rely on IP range discovery to populate all_discovered_devices_ more comprehensively.
    }
}

// NEW: Performs IP Range Discovery (ICMP ping + optional port scanning)
void NetworkMonitor::performIpRangeDiscovery(const std::string& network_prefix, int start_host_ip, int end_host_ip, bool perform_ping, const std::vector<u_short>& common_ports) {
    if (source_mac_address_.empty() || source_ip_address_.empty()) {
        std::cerr << "Error: Source MAC or IP address not determined. Cannot perform IP Range Discovery." << std::endl;
        return;
    }
    std::map<std::string, DiscoveredDevice> current_discovery_results =
        discovery_manager_->discoverByIpRange(source_mac_address_, source_ip_address_, network_prefix,
                                              start_host_ip, end_host_ip, perform_ping, common_ports);

    // Merge new results into all_discovered_devices_
    for (const auto& pair : current_discovery_results) {
        all_discovered_devices_[pair.first] = pair.second;
    }

    std::cout << "\n--- IP Range Discovery Summary ---" << std::endl;
    if (all_discovered_devices_.empty()) {
        std::cout << "No devices discovered in the specified range." << std::endl;
    } else {
        std::cout << std::left << std::setw(18) << "IP Address"
                  << std::setw(18) << "MAC Address"
                  << std::setw(10) << "Pingable"
                  << "Open Ports" << std::endl;
        std::cout << std::string(70, '-') << std::endl;
        for (const auto& pair : all_discovered_devices_) {
            const DiscoveredDevice& dev = pair.second;
            std::cout << std::left << std::setw(18) << dev.ip_address
                      << std::setw(18) << (dev.mac_address.empty() ? "N/A" : dev.mac_address)
                      << std::setw(10) << (dev.connected ? "Yes" : "No");
            std::ostringstream ports_ss;
            if (!dev.open_ports.empty()) {
                for (u_short port : dev.open_ports) {
                    ports_ss << port << " ";
                }
            } else {
                ports_ss << "None";
            }
            std::cout << ports_ss.str() << std::endl;
        }
        std::cout << std::string(70, '-') << std::endl;
    }
}

// NEW: Performs DNS Zone Transfer Discovery (Conceptual)
void NetworkMonitor::performDNSDiscovery(const std::string& domain_name, const std::string& dns_server_ip) {
    std::vector<DiscoveredDevice> dns_devices =
        discovery_manager_->discoverByDNSZoneTransfer(domain_name, dns_server_ip);

    // Merge new results into all_discovered_devices_
    for (const auto& dev : dns_devices) {
        all_discovered_devices_[dev.ip_address] = dev;
    }

    std::cout << "\n--- DNS Zone Transfer Discovery Summary ---" << std::endl;
    if (dns_devices.empty()) {
        std::cout << "No devices discovered via DNS Zone Transfer." << std::endl;
    } else {
        std::cout << "Discovered " << dns_devices.size() << " devices via DNS." << std::endl;
        // You can print details here if desired
    }
}

// NEW: Performs Active Directory Integration Discovery (Conceptual)
void NetworkMonitor::performADDiscovery(const std::string& ad_domain, const std::string& username, const std::string& password) {
    std::vector<DiscoveredDevice> ad_devices =
        discovery_manager_->discoverByActiveDirectory(ad_domain, username, password);

    // Merge new results into all_discovered_devices_
    for (const auto& dev : ad_devices) {
        all_discovered_devices_[dev.ip_address] = dev;
    }

    std::cout << "\n--- Active Directory Discovery Summary ---" << std::endl;
    if (ad_devices.empty()) {
        std::cout << "No devices discovered via Active Directory." << std::endl;
    } else {
        std::cout << "Discovered " << ad_devices.size() << " devices via Active Directory." << std::endl;
        // You can print details here if desired
    }
}

// NEW: Performs Manual Device Addition
void NetworkMonitor::performManualDeviceAddition(const std::string& ip_address, const std::string& mac_address) {
    DiscoveredDevice new_device = discovery_manager_->addManualDevice(ip_address, mac_address);
    all_discovered_devices_[new_device.ip_address] = new_device;
    std::cout << "Device " << new_device.ip_address << " added to discovered list." << std::endl;
}

// NEW: Performs SNMP Discovery on already discovered devices
void NetworkMonitor::performSNMPDiscoveryOnDiscoveredDevices(const std::string& snmp_version, const std::string& community_or_username) {
    if (all_discovered_devices_.empty()) {
        std::cout << "No devices discovered yet to perform SNMP scan on." << std::endl;
        return;
    }
    std::cout << "\n--- Starting SNMP Discovery on Discovered Devices ---" << std::endl;
    discovery_manager_->performSNMPDiscovery(all_discovered_devices_, snmp_version, community_or_username);
    std::cout << "--- SNMP Discovery Finished ---" << std::endl;

    // Optionally, print updated discovered devices with SNMP info
    std::cout << "\n--- Updated Discovered Devices (with SNMP info) ---" << std::endl;
    if (all_discovered_devices_.empty()) {
        std::cout << "No devices in the list." << std::endl;
    } else {
        std::cout << std::left << std::setw(18) << "IP Address"
                  << std::setw(18) << "MAC Address"
                  << std::setw(10) << "Pingable"
                  << std::setw(15) << "Open Ports"
                  << "SNMP Info" << std::endl;
        std::cout << std::string(100, '-') << std::endl;
        for (const auto& pair : all_discovered_devices_) {
            const DiscoveredDevice& dev = pair.second;
            std::cout << std::left << std::setw(18) << dev.ip_address
                      << std::setw(18) << (dev.mac_address.empty() ? "N/A" : dev.mac_address)
                      << std::setw(10) << (dev.connected ? "Yes" : "No");
            std::ostringstream ports_ss;
            if (!dev.open_ports.empty()) {
                for (u_short port : dev.open_ports) {
                    ports_ss << port << " ";
                }
            } else {
                ports_ss << "None";
            }
            std::cout << std::setw(15) << ports_ss.str();

            if (dev.snmp_info.empty()) {
                std::cout << "None";
            } else {
                std::cout << "[";
                for (auto it = dev.snmp_info.begin(); it != dev.snmp_info.end(); ++it) {
                    if (it != dev.snmp_info.begin()) {
                        std::cout << "; ";
                    }
                    std::cout << it->first << "={";
                    for (auto set_it = it->second.begin(); set_it != it->second.end(); ++set_it) {
                        if (set_it != it->second.begin()) {
                            std::cout << ",";
                        }
                        std::cout << *set_it;
                    }
                    std::cout << "}";
                }
                std::cout << "]";
            }
            std::cout << std::endl;
        }
        std::cout << std::string(100, '-') << std::endl;
    }
}


// Prints network statistics (placeholder for now)
void NetworkMonitor::printNetworkStatistics() const {
    std::cout << "\n---- Network Statistics ----" << std::endl;
    std::cout << "Current bandwidth: 0.00 Mbps" << std::endl;
    std::cout << "Current packet rate: 0 packets/sec" << std::endl;

    std::cout << "\nProtocol distribution:" << std::endl;
    std::cout << "Current protocol distribution:\n" << std::endl;

    std::cout << "\nTop talkers:" << std::endl;
    std::cout << std::left << std::setw(18) << "IP"
              << std::setw(20) << "MAC"
              << std::setw(12) << "Sent (KB)"
              << std::setw(12) << "Recv (KB)"
              << "Packets" << std::endl;
    std::cout << std::string(70, '-') << std::endl;
    // Placeholder for actual data
    std::cout << "No data available." << std::endl;
    std::cout << std::string(70, '-') << std::endl;


    std::cout << "\nTop listeners:" << std::endl;
    std::cout << std::left << std::setw(18) << "IP"
              << std::setw(20) << "MAC"
              << std::setw(12) << "Sent (KB)"
              << std::setw(12) << "Recv (KB)"
              << "Packets" << std::endl;
    std::cout << std::string(70, '-') << std::endl;
    // Placeholder for actual data
    std::cout << "No data available." << std::endl;
    std::cout << std::string(70, '-') << std::endl;
}

