//
// Created by HomePC on 5/30/2025.
//

#include "PortScanner.h"
#include <iostream>
#include <chrono>
#include <thread>

PortScanner::PortScanner() {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed!" << std::endl;
    }
#endif
    std::cout << "PortScanner::PortScanner() - Initialized." << std::endl;
}

PortScanner::~PortScanner () {
    #ifdef _WIN32
    WSACleanup();
    #endif
    std::cout << "PortScanner::PortScanner() - Deinitialized." << std::endl;
}

bool PortScanner::scanPort(const std::string &target_ip, u_short target_port, int timeout_ms) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "socket() failed! for "<<target_ip<<":"<<target_port<<":"
#ifdef _WIN32
        << WSAGetLastError()
#else
        << strerror(errno)
#endif
        << std::endl;
        return false;
    }
#ifdef _WIN32
    u_long mode = 1; // 1 to enable non-blocking and 0 to disable
    ioctlsocket(sock, FIONBIO, &mode);
#else
    fnctl(sock, F_SETFL, O_NONBLOCK);
    #endif
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(target_port);
    if (inet_pton(AF_INET, target_ip.c_str(), &serv_addr.sin_addr) != 1) {
        std::cerr << "Invalid target ip. Failed." << std::endl;
#ifdef _WIN32
            closesocket(sock);
            #else
                close(sock);
#endif
        return false;
    }

    int connect_status = connect(sock, reinterpret_cast<struct sockaddr *>(&serv_addr), sizeof(serv_addr));

    if (connect_status == SOCKET_ERROR) {
#ifdef _WIN32
        int error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK || error == WSAEINPROGRESS) {
            fd_set write_fds;
            FD_ZERO(&write_fds);
            FD_SET(sock, &write_fds);

            timeval tv;
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;

            int select_result = select(sock + 1, nullptr, &write_fds, nullptr, &tv);
            if (select_result > 0) {
                int optval;
                int optlen = sizeof(optval);
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(optval), &optlen) == 0 && optval == 0) {
                    std::cout << "Port " << target_port << " on " << target_ip << " is OPEN." << std::endl;
#ifdef _WIN32
                    closesocket(sock);
                    #else
                    close(sock);
#endif
                    return true;
                }
            }
        }
        #else
        if (errno == EINPROGRESS || errno == EWOULDBLOCK) {
            fd_set write_fds;
            FD_ZERO(&write_fds);
            FD_SET(sock, &write_fds);
            timeval tv;
            tv->tv_sec = timeout_ms / 1000;
            tv->tv_usec = (timeout_ms % 1000) * 1000;

            int select_result = select(sock + 1, nullptr, &write_fds, nullptr, &tvs)
            if (select_result > 0) {
                int optval;
                socklen_t optlen = sizeof(optval);
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &optval , &optlen) == 0 && optval == 0) {
                    std::cout << "Port " << target_port << " on " << target_ip << " is OPEN." << std::endl;
                    close(sock);
                    return true;
                }
            }
        }
#endif
    } else {
        #ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
        #endif
        return true;
    }
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    return false;
}

std::set<u_short> PortScanner::scanPorts(const std::string &target_ip, const std::vector<u_short> &target_port, int timeout_ms) {
    std::set<u_short> open_ports;
    std::cout << "Starting port scan for IP "<< target_ip << std::endl;
    for (u_short port: target_port) {
        if (scanPort(target_ip, port, timeout_ms)) {
            open_ports.insert(port);
            std::cout << "Port " << port  << " on " << target_ip << " is OPEN." << std::endl;
        } else {
            std::cout << "Port " << port  << " on " << target_ip << " is CLOSED." << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1)); // small delay
    }
    std::cout << "PortScan Closing for IP "<< target_ip << std::endl;
    return open_ports;
}

std::set<u_short> PortScanner::scanPortRange(const std::string &target_ip, u_short start_port, u_short end_port, int timeout_ms) {
    std::set<u_short> open_ports;
    std::cout << "Starting port scan for IP "<< target_ip << "start: "<<start_port<<" end: "<<end_port<< std::endl;
    for (u_short port = start_port; port <= end_port; port++) {
        if (scanPort(target_ip, port, timeout_ms)) {
            open_ports.insert(port);
            std::cout << "Port " << port  << " on " << target_ip << " is OPEN." << std::endl;
        } else {
            std::cout << "Port " << port  << " on " << target_ip << " is CLOSED." << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1)); // small delay
    }
    std::cout << "PortScan Closing for IP "<< target_ip << std::endl;
    return open_ports;
}


