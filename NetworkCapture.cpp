#include "NetworkCapture.h"
#include <iostream>
#include <pcap/pcap.h>
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")

bool NetworkCapture::listDevices() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = nullptr;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return false;
    }

    int idx = 0;
    for (pcap_if_t *d = alldevs; d; d = d->next) {
        std::cout << ++idx << ". " << (d->name ? d->name : "[no name]");
        if (d->description) std::cout << " (" << d->description << ")";
        std::cout << std::endl;
    }
    if (idx == 0) {
        std::cerr << "No interfaces found. Make sure Npcap is installed and run as admin.\n";
        pcap_freealldevs(alldevs);
        return false;
    }
    // If you rely on the member, ensure it's in a non-static context 
    this->all_devices = alldevs; // inside a non-static method
    return true;
}

bool NetworkCapture::selectDevice() {
    if (!all_devices) {
        std::cerr << "No devices available. Call listDevices first.\n";
        return false;
    }

    int choice = 0;
    std::cout << "Enter interface number to capture from: ";
    if (!(std::cin >> choice) || choice <= 0) {
        std::cerr << "Invalid input. Please enter a positive integer.\n";
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return false;
    }
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');  // Clear remaining input

    // Navigate to the selected device
    pcap_if_t* d = all_devices;
    for (int i = 1; d && i < choice; ++i) {
        d = d->next;
    }

    if (!d) {
        std::cerr << "Invalid interface number.\n";
        return false;
    }

    selected_device_name_ = d->name;

    // Fetch MAC and IP
    if (!getDeviceMacAndIp(d)) {
        std::cerr << "Failed to get MAC/IP for device: " << selected_device_name_ << std::endl;
        return false;
    }

    // Open pcap handle for capturing
    char errbuf[PCAP_ERRBUF_SIZE];
    live_pcap_handler = pcap_open_live(selected_device_name_.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!live_pcap_handler) {
        std::cerr << "Failed to open device " << selected_device_name_ << ": " << errbuf << std::endl;
        return false;
    }

    std::cout << "Successfully selected device: " << selected_device_name_ << std::endl;
    return true;
}

// Constructor, just moves unique_ptr
NetworkCapture::NetworkCapture(std::unique_ptr<PacketWriter> writer_impl)
    : packet_writer_(std::move(writer_impl)), stop_capture_flag_(false), live_pcap_handler(nullptr) {
}

// Destructor ensures clean stop and resource release
NetworkCapture::~NetworkCapture() {
    stop_capture();
    if (capture_thread_.joinable())
        capture_thread_.join();

    if (live_pcap_handler) {
        pcap_close(live_pcap_handler);
        live_pcap_handler = nullptr;
    }
    // ... and in your destructor
    if (all_devices) {
        pcap_freealldevs(all_devices);
        all_devices = nullptr;
    }
}

// Starts the thread running capture loop
bool NetworkCapture::startCapture(int duration_s, const std::string &output_destination) {
    if (capture_thread_.joinable()) {
        std::cerr << "Capture already running.\n";
        return false;
    }
    stop_capture_flag_ = false;

    // Open device handle
    char errbuf[PCAP_ERRBUF_SIZE];
    live_pcap_handler = pcap_open_live(selected_device_name_.c_str(), 65536, 1, 1000, errbuf);
    if (!live_pcap_handler) {
        std::cerr << "Failed to open device: " << errbuf << "\n";
        return false;
    }

    // Open packet writer with output destination (file name or empty)
    if (packet_writer_ && !packet_writer_->open(output_destination, live_pcap_handler)) {
        std::cerr << "Failed to open packet writer\n";
        pcap_close(live_pcap_handler);
        live_pcap_handler = nullptr;
        return false;
    }

    // Launch capture thread (auto joins in destructor)
    capture_thread_ = std::thread([this, duration_s]() {
        // Run capture loop with timeout or until stopped
        captureLoop();

        // Close writer and pcap handle inside thread, safe
        if (packet_writer_) {
            packet_writer_->close();
        }
        if (live_pcap_handler) {
            pcap_close(live_pcap_handler);
            live_pcap_handler = nullptr;
        }
    });

    // Optional: wait for a specified duration_s, then stop
    if (duration_s > 0) {
        for (int i = duration_s; i > 0; --i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            std::cout << "Capture running... " << i << " second(s) left" << std::endl << std::flush;
        }
        stop_capture();
        if (capture_thread_.joinable()) {
            capture_thread_.join();
        }
    }

    return true;
}

// Method to stop capture by setting flag and breaking pcap loop
void NetworkCapture::stop_capture() {
    stop_capture_flag_ = true;
    if (live_pcap_handler) {
        pcap_breakloop(live_pcap_handler);
    }
}

// Static callback passed to pcap_loop
void NetworkCapture::packetHandler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    NetworkCapture* self = reinterpret_cast<NetworkCapture*>(user_data);
    if (!self || !pkthdr || !packet)
        return;

    // Forward packet to packet writer if enabled
    if (self->packet_writer_) {
        self->packet_writer_->writePacket(pkthdr, packet);
    }
}

// The capture loop, blocking call inside thread
void NetworkCapture::captureLoop() {
    if (!live_pcap_handler) {
        std::cerr << "Capture handle not initialized!\n";
        return;
    }

    int ret = pcap_loop(live_pcap_handler, 0, &NetworkCapture::packetHandler, reinterpret_cast<u_char*>(this));
    if (ret == -1) {
        std::cerr << "Error capturing packets: " << pcap_geterr(live_pcap_handler) << "\n";
    } else if (ret == -2) {
        std::cout << "Capture loop terminated by stop_capture or error\n";
    } else {
        std::cout << "Capture finished, returned " << ret << "\n";
    }
}

bool NetworkCapture::getDeviceMacAndIp(pcap_if_t* d) {
    source_mac_.clear();
    source_ip_str_.clear();
    network_prefix_str_.clear();

    // 1. Get IPv4 address and prefix
    for (pcap_addr_t *a = d->addresses; a != nullptr; a = a->next) {
        if (a->addr && a->addr->sa_family == AF_INET) {
            sockaddr_in* sa_in = reinterpret_cast<sockaddr_in*>(a->addr);
            char ip_buf[INET_ADDRSTRLEN] = {0};
            if (inet_ntop(AF_INET, &(sa_in->sin_addr), ip_buf, INET_ADDRSTRLEN)) {
                source_ip_str_ = ip_buf;
                // Get network prefix (e.g. "192.168.1")
                std::string ip = ip_buf;
                size_t last_dot = ip.rfind('.');
                if (last_dot != std::string::npos)
                    network_prefix_str_ = ip.substr(0, last_dot);
                break; // Use first IPv4 found
            }
        }
    }
    if (source_ip_str_.empty()) {
        std::cerr << "No IPv4 address found for interface!\n";
        return false;
    }

    // 2. Get MAC address using Windows GetAdaptersAddresses
#ifdef _WIN32
    // Helper: Extract GUID from d->name, which looks like "\\Device\\NPF_{GUID}"
    std::string dev_name = d->name ? d->name : "";
    std::string guid;
    size_t start = dev_name.find("{");
    size_t end = dev_name.find("}");
    if (start != std::string::npos && end != std::string::npos && end > start)
        guid = dev_name.substr(start, end - start + 1); // keep braces

    ULONG outBufLen = 15000;
    std::vector<BYTE> buffer(outBufLen);
    PIP_ADAPTER_ADDRESSES pAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, pAddresses, &outBufLen) == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES pCurr = pAddresses; pCurr; pCurr = pCurr->Next) {
            std::string adapterName = pCurr->AdapterName ? pCurr->AdapterName : "";
            // Compare only the {GUID} part
            if (!guid.empty() && adapterName.find(guid) != std::string::npos) {
                if (pCurr->PhysicalAddressLength == 6) {
                    source_mac_.assign(pCurr->PhysicalAddress, pCurr->PhysicalAddress + 6);
                    break;
                }
            }
        }
    }
#else
    // For Linux, use ioctl(SIOCGIFHWADDR)...
#endif

    if (source_mac_.size() != 6) {
        std::cerr << "Could not determine MAC address for interface\n";
        return false;
    }
    return true;
}

