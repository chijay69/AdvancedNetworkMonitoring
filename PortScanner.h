//
// Created by HomePC on 5/30/2025.
//

#ifndef PORTSCANNER_H
#define PORTSCANNER_H

#include <string>
#include <vector>
#include <map>
#include <set>
#include <pcap/pcap.h>

// platform specific implementation
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h> // For close()
#include <fcntl.h>  // For fcntl (non-blocking sockets)
#endif

class PortScanner {

public:
    PortScanner();
    ~PortScanner();

    bool scanPort(const std::string& target_ip, u_short target_port, int timeout_ms = 1000);
    std::set<u_short> scanPorts(const std::string& target_ip, const std::vector<u_short> &target_port, int timeout_ms = 1000);
    std::set<u_short> scanPortRange(const std::string& target_ip, u_short start_port, u_short end_port, int timeout_ms = 1000);
    private:
};

#endif //PORTSCANNER_H
