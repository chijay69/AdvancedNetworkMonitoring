//
// Created by HomePC on 5/30/2025.
//

#include "PingScanner.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <array>
#include <cstring>
#include <memory>


PingScanner::PingScanner(): raw_socket_(INVALID_SOCKET) {
#ifdef WIN32
    WSAData wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cout << "WSAStartup failed with error: " << iResult << std::endl;
        return;
    }
#endif
    // create a raw timeout for the socket
    raw_socket_ = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (raw_socket_ == INVALID_SOCKET) {
        std::cerr << "Failed to create raw socket" << std::endl;
#ifdef _WIN32
        WSAGetLastError();
#else
        <<strerror(errno)
        #endif
    } else {
        int timeout = 1000;
#ifdef _WIN32
        setsockopt(raw_socket_, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
#else
        struct timeval tv;
        tv.tv_sec = timeout/ 1000;
        tv.tv_usec = = (timeout % 1000) * 1000;
        setsockopt(raw_socket_, SOL_SOCKET, SO_RCVITIMEO, (const *char)&tv, sizeof(tv));
#endif
    }
    std::cout << "PingScanner::PingScanner() - Socket initialized." << std::endl;
}

// Destructor
PingScanner::~PingScanner() {
    if (raw_socket_ != INVALID_SOCKET) {
#ifdef WIN32
        closesocket(raw_socket_);
        WSACleanup();
#else
        close(raw_socket_);
#endif
    }
}

// function to calculate ICMP Checksum
u_short PingScanner::calculate_icmp_checksum(const u_char *data, int len) {
    u_long sum = 0;
    const u_short *ip_data = reinterpret_cast<const u_short *>(data);

    while (len >= 2) {
        sum += *ip_data++;
        len -= 2;
    }
    if (len == 1) {
        sum += reinterpret_cast<const u_char &>(*ip_data);
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return static_cast<u_short>(~sum);
}

std::vector<u_char> PingScanner::build_icmp_echo_request(int id, int seq) {
    std::vector<u_char> packet_buffer(sizeof(icmp_header) + 32);
    icmp_header *icmp_h = reinterpret_cast<icmp_header *>(packet_buffer.data());
    memset(icmp_h, 0, packet_buffer.size());
    icmp_h->icmp_type = ICMP_TYPE_ECHO_REQUEST;
    icmp_h->icmp_code = 0;
    icmp_h->echo.icmp_id = htons(static_cast<u_short>(id));
    icmp_h->echo.icmp_seq = htons(static_cast<u_short>(seq));

    for (int i = 0; i < 32; i++) {
        packet_buffer[sizeof(icmp_header) + i] = static_cast<u_char>('A' + (i + 26));
    }

    // calculate checksum
    icmp_h->icmp_checksum = 0;
    icmp_h->icmp_checksum = calculate_icmp_checksum(packet_buffer.data(), packet_buffer.size());
    return packet_buffer;
}

// Helper function to convert IP Address to string
std::string PingScanner::ip_to_string(const u_char *ip_bytes) {
    char str_ip[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, ip_bytes, str_ip, INET_ADDRSTRLEN) != nullptr) {
        return std::string(str_ip);
    };
    return "N/A";
}

// ICMP constants are now defined in the header file

// Performs a single ICMP ping
bool PingScanner::ping(const std::string &target_ip, int timeout_ms, int retries) {
    if (raw_socket_ == INVALID_SOCKET) {
        std::cerr << "Failed to create raw socket" << std::endl;
        return false;
    }

    sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, target_ip.c_str(), &dest_addr.sin_addr.s_addr) != 1) {
        std::cerr << "Failed to parse IP address" << std::endl;
        return false;
    }

#ifdef WIN32
    setsockopt(raw_socket_, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
#else
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(raw_socket_, SOL_SOCKET, SO_RCVTIMEO, (const char*) &tv, sizeof(tv)); // Fixed cast
#endif

    std::vector<u_char> send_buffer = build_icmp_echo_request(GetCurrentProcessId(), 1);

    for (int i = 0; i < retries; i++) {
        auto start_time = std::chrono::high_resolution_clock::now();
        // send ICMP ECHO request
        int bytes_sent = sendto(raw_socket_, reinterpret_cast<const char*>(send_buffer.data()), send_buffer.size(),
            0, reinterpret_cast<sockaddr*>(&dest_addr), sizeof(dest_addr));
        if (bytes_sent == SOCKET_ERROR) {
            std::cerr << "Failed to send ICMP echo request to " << target_ip << ": "
#ifdef _WIN32
                      << WSAGetLastError()
#else
                      << strerror(errno)
#endif
                      << std::endl;
            continue;
        }

        std::array<u_char, 1500> recv_buffer;
        sockaddr_in src_addr;
        socklen_t src_addr_len = sizeof(src_addr);
        int bytes_received = recvfrom(raw_socket_, reinterpret_cast<char*>(recv_buffer.data()), recv_buffer.size(), 0, reinterpret_cast<sockaddr*>(&src_addr), &src_addr_len);
        if (bytes_received == SOCKET_ERROR) {
#ifdef _WIN32
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT) {
                std::cout << "Ping to " << target_ip << " timed out." << std::endl; // Too verbose
            } else {
                std::cerr << "RECV from " << target_ip << " failed: " << WSAGetLastError() << std::endl;
            }
#endif
            continue;
        }
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();

        if (bytes_received >= sizeof(ip_header) + sizeof(icmp_header)) {
            const ip_header *ip_h = reinterpret_cast<const ip_header *>(recv_buffer.data());
            u_int ip_header_len = (ip_h->ip_vhl & 0x0F) * 4;

            if (bytes_received < ip_header_len + sizeof(icmp_header)) {
                continue;
            }

            const icmp_header *icmp_h = reinterpret_cast<const icmp_header *>(recv_buffer.data() + ip_header_len);

            if (icmp_h->icmp_type == ICMP_TYPE_ECHO_REPLY && ntohs(icmp_h->echo.icmp_id) == GetCurrentProcessId()) {
                std::cout << "Ping reply from " << ip_to_string(ip_h->ip_src) << " in " << duration << "ms" << std::endl; // Added space
                return true;
            }
        }
    }

    std::cout << "ping to " << target_ip << " failed." << std::endl;
    return false;
}


std::map<std::string, bool> PingScanner::pingScan(const std::string &network_prefix, int start_host_ip, int end_host_ip, int timeout_ms, int retries) {
    std::map<std::string, bool> reachable_host;
    std::cout << "Starting ICMP Ping scan for "<< network_prefix<<"."<<end_host_ip<<"..." << std::endl;
    for (int i = start_host_ip; i <= end_host_ip; ++i) {
        std::string target_ip = network_prefix + "." + std::to_string(i);
        if (ping(target_ip, timeout_ms, retries)) {
            reachable_host[target_ip] = true;
        } else {
            reachable_host[target_ip] = false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
        std::cout << "ICMP Ping SCAN FINISHED "<< std::endl;
    return reachable_host;
}




