//
// Created by HomePC on 5/31/2025.
//

#include "DiscoveryManager.h"
#include <iostream>
#include <algorithm>

DiscoveryManager::DiscoveryManager() :
    arp_scanner_(std::make_unique<NetworkScanner>()),
    ping_scanner_(std::make_unique<PingScanner>()),
    port_scanner_(std::make_unique<PortScanner>()),
    snmp_client_(std::make_unique<SNMPClient>())
{
    std::cout << "Creating DiscoveryManager..." << std::endl;
}

DiscoveryManager::~DiscoveryManager() {
    std::cout << "Destroying DiscoveryManager..." << std::endl;
}

std::map<std::string, DiscoveredDevice> DiscoveryManager::discoverByIpRange(const std::vector<u_char> &source_mac_address, const std::string &source_ip_address, const std::string &network_prefix, int start_host_ip, int end_host_ip, bool perform_ping, const std::vector<u_short> &common_ports_to_scan) {
    std::map<std::string, DiscoveredDevice> discovered_devices;
    std::cout << "Creating DiscoveryManager... Starting IP discovery range." << std::endl;
    if (pcap_handle_) {
        std::cout << "PCAP handle created. Performing ARP scan" << std::endl;
        if (arp_scanner_->performArpScan(pcap_handle_, source_mac_address, source_ip_address, network_prefix, start_host_ip, end_host_ip)) {
            for (const auto &[fst, snd] : arp_scanner_->getDiscoveredHosts()) {
                discovered_devices[fst].ip_address = fst;
                discovered_devices[fst].mac_address = snd;
            }
            std::cout << "DiscoveryManager: ARP scan completed. Discovered hosts will be integrated." << std::endl;
        } else {
            std::cout << "DiscoveryManager: ARP scan failed." << std::endl;
        }
    } else {
        std::cerr << "DiscoveryManager: PCAP handle not created. Skipping ARP." << std::endl;
    }

    if (perform_ping) {
        std::cout << "DiscoveryManager: Performing ping..." << std::endl;
        std::map<std::string, bool> ping_results = ping_scanner_->pingScan(network_prefix, start_host_ip, end_host_ip);
        for (const auto &[fst, snd] : ping_results) {
            if (snd) {
                DiscoveredDevice &device = discovered_devices[fst];
                device.ip_address = snd;
                device.connected = true;
            }
        }
        std::cout << "DiscoveryManager: ICMP Ping completed." << std::endl;
    }

    if (!common_ports_to_scan.empty()) {
        std::cout << "DiscoveryManager: Common port scan starting..." << std::endl;

        std::vector<std::string> ips_to_scan;
        if (perform_ping) {
            for (auto const &[fst, snd] : discovered_devices) {
                if (snd.connected) {
                    ips_to_scan.push_back(fst);
                }
            }
        } else {
            for (int i = start_host_ip; i <= end_host_ip; ++i) {
                ips_to_scan.push_back(network_prefix + "." + std::to_string(i));
            }
        }

        for (const std::string &ip : ips_to_scan) {
            std::set<u_short> open_ports = port_scanner_->scanPorts(ip, common_ports_to_scan);
            if (open_ports.empty()) {
                DiscoveredDevice &device = discovered_devices[ip];
                device.ip_address = ip;
                device.open_ports = open_ports;
                std::cout << "Found open ports on "<< ip << std::endl;
                for (u_short port : open_ports) {
                    std::cout << "Found port " << port << " ";
                }
                std::cout << std::endl;
            }
        }
        std::cout << "DiscoveryManager: IP scan completed." << std::endl;
    }
    std::cout << "DiscoveryManager: IP range discovery complete." << std::endl;
    return discovered_devices;
}

// DNS Zone Transfer (Conceptual Implementation)
std::vector<DiscoveredDevice> DiscoveryManager::discoverByDNSZoneTransfer(const std::string& domain_name, const std::string& dns_server_ip) {
    std::vector<DiscoveredDevice> discovered;
    std::cout << "\nDiscoveryManager: Performing DNS Zone Transfer for domain '" << domain_name
              << "' via DNS server " << dns_server_ip << " (Conceptual)." << std::endl;

    // In a real implementation, you would:
    // 1. Create a TCP socket to dns_server_ip:53.
    // 2. Construct a DNS AXFR (Zone Transfer) query.
    // 3. Send the query.
    // 4. Parse the stream of DNS records received (A, AAAA, PTR, CNAME, MX, NS, etc.).
    // 5. Populate DiscoveredDevice objects based on the parsed records.
    // This requires a robust DNS client implementation.

    std::cout << "  (Simulating discovery of a few devices from DNS zone transfer)" << std::endl;
    DiscoveredDevice dev1;
    dev1.ip_address = "192.168.1.10";
    dev1.mac_address = "AA:BB:CC:DD:EE:F0";
    discovered.push_back(dev1);

    DiscoveredDevice dev2;
    dev2.ip_address = "192.168.1.11";
    dev2.mac_address = "AA:BB:CC:DD:EE:F1";
    discovered.push_back(dev2);

    std::cout << "DiscoveryManager: DNS Zone Transfer finished (Conceptual)." << std::endl;
    return discovered;
}
// Active Directory Integration (Conceptual Implementation)
std::vector<DiscoveredDevice> DiscoveryManager::discoverByActiveDirectory(const std::string& ad_domain, const std::string& username, const std::string& password) {
    std::vector<DiscoveredDevice> discovered;
    std::cout << "\nDiscoveryManager: Integrating with Active Directory domain '" << ad_domain
              << "' (Conceptual)." << std::endl;

    // In a real implementation, you would:
    // 1. Use an LDAP library (e.g., OpenLDAP client library, or Windows ADSI/LDAP APIs).
    // 2. Bind to the AD server using the provided credentials.
    // 3. Perform LDAP queries to enumerate computers, users, network devices, etc.
    // 4. Extract IP addresses, hostnames, and other relevant information.
    // 5. Populate DiscoveredDevice objects.

    std::cout << "  (Simulating discovery of a few devices from Active Directory)" << std::endl;
    DiscoveredDevice dev3;
    dev3.ip_address = "10.0.0.50";
    dev3.mac_address = "00:11:22:33:44:55";
    dev3.snmp_info["sysName.0"] = "AD-Server-01";  // Changed from single quotes to double quotes
    discovered.push_back(dev3);

    DiscoveredDevice dev4;
    dev4.ip_address = "10.0.0.51";
    dev4.mac_address = "00:11:22:33:44:56";
    dev4.snmp_info["sysName.0"] = "Workstation-01";  // Changed from single quotes to double quotes
    discovered.push_back(dev4);

    std::cout << "DiscoveryManager: Active Directory Integration finished (Conceptual)." << std::endl;
    return discovered;
}

// Sets the pcap handle for the NetworkScanner (ARP)
void DiscoveryManager::setPcapHandle(pcap_t* handle) {
    pcap_handle_ = handle;
}

// Manual Device Addition
DiscoveredDevice DiscoveryManager::addManualDevice(const std::string& ip_address, const std::string& mac_address) {
    DiscoveredDevice new_device;
    new_device.ip_address = ip_address;
    new_device.mac_address = mac_address;
    new_device.connected = false; // Unknown unless explicitly pinged later
    std::cout << "\nDiscoveryManager: Manually added device: IP=" << ip_address;
    if (!mac_address.empty()) {
        std::cout << ", MAC=" << mac_address;
    }
    std::cout << std::endl;
    return new_device;
}

// SNMP Discovery (Queries discovered devices for SNMP info)
void  DiscoveryManager::performSNMPDiscovery(std::map<std::string, DiscoveredDevice>& devices,
                                            const std::string& snmp_version,
                                            const std::string& community_or_username,
                                            const std::string& auth_passphrase,
                                            const std::string& priv_passphrase) {
    std::cout << "\nDiscoveryManager: Performing SNMP Discovery (Conceptual) on " << devices.size() << " devices..." << std::endl;
    std::cout << "  SNMP Version: " << snmp_version << std::endl;

    // In a real implementation, you would iterate through 'devices' and for each:
    // 1. Check if the device is ping-reachable or has open SNMP ports (161/UDP).
    // 2. Use the SNMPClient to send GET requests for common OIDs (e.g., sysDescr.0, sysName.0).
    // 3. Parse the SNMP responses.
    // 4. Update the device's snmp_info map.

    // Example conceptual usage:
    for (auto& pair : devices) {
        DiscoveredDevice& device = pair.second;
        std::cout << "  Attempting SNMP GET on " << device.ip_address << "..." << std::endl;
        // Simulate SNMP query
        std::map<std::string, std::string> result = snmp_client_->get(
            device.ip_address,
            {"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"}, // Example OIDs: sysDescr.0, sysName.0
            snmp_version,
            community_or_username,
            auth_passphrase,
            priv_passphrase
        );

        if (!result.empty()) {
            std::cout << "    SNMP info for " << device.ip_address << ": " << std::endl;
            for (const auto& [fst, snd] : result) {
                device.snmp_info[fst] = snd;
                std::cout << "      " << fst << ": " << snd << std::endl;
            }
        } else {
            std::cout << "    No SNMP info retrieved from " << device.ip_address << "." << std::endl;
        }
    }
    std::cout << "DiscoveryManager: SNMP Discovery finished (Conceptual)." << std::endl;
}




