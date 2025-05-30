//
// Created by HomePC on 5/22/2025.
//

#ifndef NETWORKSCANNER_H
#define NETWORKSCANNER_H

#include <string>
#include <vector>
#include <map>
#include <pcap/pcap.h> // For pcap_t, pcap_pkthdr, u_char

class NetworkScanner {
public:
    NetworkScanner();
    ~NetworkScanner();

    bool performArpScan(pcap_t* pcap_handle, const std::vector<u_char> &source_mac, const std::string source_ip_str,
        const std::string network_prefix, int start_host_ip, int end_host_ip);

    void printDiscoveredHosts();
private:
    std::map<std::string, std::string> discovered_hosts_; // Stores IP -> MAC mappings of discovered hosts

    // Helper to build an ARP request packet
    static bool buildArpRequestPacket(const std::vector<u_char> &source_mac, const std::string &source_ip_str,
                                      const std::string &target_ip_str, std::vector<u_char> &packet_buffer);
    // Callback function for pcap_dispatch to handle captured ARP packets
    static void arpHandler(u_char *user_data, const pcap_pkthdr *pkthdr, const u_char *packet);
};

#endif //NETWORKSCANNER_H
