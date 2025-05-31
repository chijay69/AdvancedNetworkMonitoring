//
// Created by HomePC on 5/31/2025.
//

#ifndef DISCOVERYMANAGER_H
#define DISCOVERYMANAGER_H
#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include "NetworkScanner.h"
#include "PingScanner.h"
#include "PortScanner.h"
#include "SNMPClient.h"

struct DiscoveredDevice {
    std::string ip_address;
    std::string mac_address;
    std::set<u_short> open_ports;
    bool connected = false;
    std::map<std::string, std::string> snmp_info;  // Changed from std::set<u_short> to std::string
};

class DiscoveryManager {
    public:
    DiscoveryManager();
    ~DiscoveryManager();

    void setPcapHandle(pcap_t* handle);

    std::map<std::string, DiscoveredDevice> discoverByIpRange(
        const std::vector<u_char>& source_mac_address,
        const std::string& source_ip_address,
        const std::string& network_prefix,
        int start_host_ip,
        int end_host_ip,
        bool perform_ping = true,
        const std::vector<u_short> &common_ports_to_scan = {}
    );

    std::vector<DiscoveredDevice> discoverByDNSZoneTransfer(const std::string& domain_name, const std::string& dns_server_ip);

    std::vector<DiscoveredDevice> discoverByActiveDirectory(const std::string& ad_domain, const std::string& username, const std::string& password);

    DiscoveredDevice addManualDevice(const std::string& ip_address, const std::string& mac_address = "");

    void performSNMPDiscovery(
        std::map<std::string, DiscoveredDevice> &devices,
        const std::string& snmp_version, // v1, v2, v3
        const std::string& community_or_username,
        const std::string& auth_passphrase = "",
        const std::string& priv_passphrase = ""
    );

    std::unique_ptr<NetworkScanner> arp_scanner_;
private:
    std::unique_ptr<PingScanner> ping_scanner_;
    std::unique_ptr<PortScanner> port_scanner_;
    std::unique_ptr<SNMPClient> snmp_client_;

    pcap_t* pcap_handle_ = nullptr;
};

#endif //DISCOVERYMANAGER_H
