//
// Created by HomePC on 5/30/2025.
//

#ifndef PINGSCANNER_H
#define PINGSCANNER_H

#include <string>
#include <vector>
#include <map>
#include <pcap/pcap.h>
#include "PacketStructs.h"

// platform dependant
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

// define constants

constexpr u_char ICMP_TYPE_ECHO_REQUEST = 8;
constexpr u_char ICMP_TYPE_ECHO_REPLY = 0;


class PingScanner {

    public:
    PingScanner();
    ~PingScanner();

    bool ping(const std::string& target_ip, int timeout_ms = 1000, int retries = 3);

    std::map<std::string, bool> pingScan(
        const std::string& network_prefix,
        int start_host_ip,
        int end_host_ip,
        int timeout_ms = 1000,
        int retries = 1
        );
private:
    SOCKET raw_socket_;

    static u_short calculate_icmp_checksum(const u_char* data, int len);

    static std::vector<u_char> build_icmp_echo_request(int id, int seq);

    static std::string ip_to_string(const u_char* ip_bytes);
};

#endif //PINGSCANNER_H
