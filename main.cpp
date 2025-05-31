// #include <iostream>
// #include <string>
// #include <memory> // For std::unique_ptr
// #include <limits> // For std::numeric_limits
// // Your custom headers
// #include "NetworkCapture.h"
// #include "PcapFileWriter.h"
// #include "ConsoleWriter.h"
// #include "PcapFileReader.h"
// #include "NetworkScanner.h" // New
// #include "InputClass.h"     // Assuming you still want to demonstrate InputClass
// #include "NetworkMonitor.h"
// #include "MonitorWriter.h"
//
//
// int main() {
//     std::cout << "--- Advanced Network Analyzer ---" << std::endl;
//
//     // --- InputClass Demonstration (Optional) ---
//     std::string textInput;
//     InputClass inputClass;
//     std::cout << "\nEnter some text (for InputClass demo): ";
//     std::getline(std::cin, textInput);
//     inputClass.setInput(textInput);
//     std::cout << "InputClass demo: You entered: \"" << inputClass.getInput() << "\"" << std::endl;
//
//     // --- Network Capture Setup ---
//     std::cout << "\n--- Capture Setup ---" << std::endl;
//
//     std::string capture_filename;
//     std::cout << "Enter filename for captured packets (e.g., my_capture.pcap): ";
//     std::getline(std::cin >> std::ws, capture_filename);
//
//     int capture_duration;
//     std::cout << "Enter capture duration in seconds (e.g., 5): ";
//     std::cin >> capture_duration;
//     std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
//
//     std::cout << "Choose output for live capture: (1) To File (2) To Console (Detailed Parse): ";
//     int capture_output_choice;
//     std::cin >> capture_output_choice;
//     std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
//
//     // --- Initialize Network monitoring ---
//     NetworkMonitor monitor(60);
//
//     // set monitoring threshold
//     monitor.setBandwidthThresholdMbps(100);
//     monitor.setPacketRateThreshold(1000);
//
//     // setup PacketWriter
//     std::unique_ptr<PacketWriter> base_writer;
//     std::string actual_capture_destination;
//
//     if (capture_output_choice == 1) {
//         base_writer = std::make_unique<PcapFileWriter>();
//         actual_capture_destination = capture_filename;
//         std::cout << "Capturing to file: " << actual_capture_destination << std::endl;
//     } else {
//         base_writer = std::make_unique<ConsoleWriter>(); // ConsoleWriter now uses PacketParser
//         actual_capture_destination = "";
//         std::cout << "Capturing to console with detailed parsing." << std::endl;
//     }
//
//     // wrap base_writer with a monitoring writer
//     auto monitoring_writer = std::make_unique<MonitorWriter>(std::move(base_writer), monitor);
//
//     // --- Initialize Network Capture ---
//     NetworkCapture capturer(std::move(monitoring_writer));
//
//     if (!capturer.listDevices()) {
//         std::cerr << "Failed to list devices. Exiting." << std::endl;
//         return 1;
//     }
//
//     if (!capturer.selectDevice()) { // This now also gets MAC/IP
//         std::cerr << "Failed to select device. Exiting." << std::endl;
//         return 1;
//     }
//
//     // --- Network Scanning (ARP Scan) ---
//     std::cout << "\n--- Network Scanning (ARP) ---" << std::endl;
//     NetworkScanner scanner;
//
//     // Get IP and MAC from the selected network adapter
//     std::vector<u_char> source_mac = capturer.getSourceMacAddress();
//     std::string source_ip = capturer.getSourceIpAddress();
//     std::string network_prefix = capturer.getNetworkPrefix();
//
//     if (source_mac.empty() || source_ip.empty() || network_prefix.empty()) {
//         std::cerr << "Error: Could not determine source MAC/IP/Network for ARP scan. Skipping scan." << std::endl;
//     } else {
//         // Perform ARP scan on the common home network range (e.g., .1 to .254)
//         if (!scanner.performArpScan(capturer.getPcapHandle(), source_mac, source_ip, network_prefix, 1, 254)) {
//             std::cerr << "ARP scan failed or was incomplete." << std::endl;
//         }
//         scanner.printDiscoveredHosts();
//     }
//
//     // start Network monitoring
//     std::cout << "\nStarting Network monitoring..." << std::endl;
//     monitor.startMonitoring();
//
//     // create a thread to print periodically
//     std::atomic<bool> stop_stats_thread = false;
//     std::thread stats_thread([&monitor, &stop_stats_thread, capture_duration]() {
//         for (int i = 0; i < capture_duration && !stop_stats_thread; i++) {
//             std::this_thread::sleep_for(std::chrono::seconds(1));
//             if (i % 5 == 0) { // Print stats every 5 seconds
//                 monitor.printCurrentStats();
//             }
//         }
//     });
//
//     // --- Start Live Packet Capture ---
//     std::cout << "\n--- Live Packet Capture ---" << std::endl;
//
//     if (!capturer.startCapture(capture_duration, actual_capture_destination)) {
//         std::cerr << "Failed to start live capture. Exiting." << std::endl;
//         stop_stats_thread = true;
//         if (stats_thread.joinable()) stats_thread.join();
//         return 1;    }
//
//     // Wait for stats thread to finish
//     stop_stats_thread = true;
//     if (stats_thread.joinable()) stats_thread.join();
//
//     // Stop monitoring
//     monitor.stopMonitoring();
//
//
//     // --- Read Captured Output (if written to file) ---
//     if (capture_output_choice == 1) { // Only read if it was written to a file
//         std::cout << "\n--- Reading Captured File ---" << std::endl;
//
//         std::cout << "Choose output for reading file: (1) To Console (Detailed Parse) (2) To (new) File: ";
//         int read_output_choice;
//         std::cin >> read_output_choice;
//         std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
//
//         std::unique_ptr<PacketWriter> read_writer;
//
//         if (read_output_choice == 1) {
//             read_writer = std::make_unique<ConsoleWriter>();
//             std::cout << "Reading from '" << capture_filename << "' and printing to console with detailed parsing." << std::endl;
//         } else {
//             std::string new_output_filename;
//             std::cout << "Enter a new filename to re-dump captured packets (e.g., redump.pcap): ";
//             std::getline(std::cin, new_output_filename);
//             read_writer = std::make_unique<PcapFileWriter>();
//             read_writer->open(new_output_filename, nullptr); // Open the PcapFileWriter for writing
//             std::cout << "Reading from '" << capture_filename << "' and re-dumping to: " << new_output_filename << std::endl;
//         }
//
//         PcapFileReader file_reader;
//         if (!read_writer) {
//             std::cerr << "No PacketWriter available." << std::endl;
//             return 1;
//         }
//         if (!file_reader.readFromFile(capture_filename, *read_writer)) {
//             std::cerr << "Failed to read packets from file." << std::endl;
//             return 1;
//         }
//     } else {
//         std::cout << "\nSkipping file read as capture was sent to console (live parsing)." << std::endl;
//     }
//
//     // Final network statistics summary
//     std::cout << "\n--- Final Network Statistics Summary ---" << std::endl;
//     monitor.printCurrentStats();
//
//     std::cout << "\nApplication finished gracefully." << std::endl;
//     return 0;
// }


#include <iostream>
#include <vector>
#include <string>
#include <limits> // Required for std::numeric_limits
#include <thread>
#include <chrono> // Required for std::chrono
#include <memory> // Required for std::unique_ptr
#include <cctype> // For tolower

#include <pcap.h> // Libpcap header

#include "NetworkMonitor.h" // Our main monitoring class
#include "ConsoleWriter.h"  // Your existing ConsoleWriter
#include "PcapFileWriter.h" // Your existing PcapFileWriter

// Forward declarations for menu functions
void displayMenu();
void handleMonitorOption(NetworkMonitor& monitor);
void handleDiscoveryOption(NetworkMonitor& monitor);

// Function to get user input for an integer
int getIntegerInput(const std::string& prompt, int min_val, int max_val) {
    int value;
    while (true) {
        std::cout << prompt;
        std::cin >> value;
        if (std::cin.fail() || value < min_val || value > max_val) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cerr << "Invalid input. Please enter a number between " << min_val << " and " << max_val << "." << std::endl;
        } else {
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            return value;
        }
    }
}

// Function to get user input for a string
std::string getStringInput(const std::string& prompt) {
    std::string value;
    std::cout << prompt;
    // Use std::ws to consume leading whitespace (like newline from previous std::cin >> int)
    std::getline(std::cin >> std::ws, value);
    return value;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    std::cout << "--- Advanced Network Analyzer ---" << std::endl;
    std::cout << "Initializing network monitor..." << std::endl;

    // Retrieve the list of devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Available network interfaces:" << std::endl;
    int i = 0; // This will count the number of interfaces
    std::vector<std::string> device_names; // Stores names to select from
    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
        std::cout << ++i << ". " << d->name;
        device_names.push_back(d->name); // Add the name to our vector
        if (d->description) {
            std::cout << " (" << d->description << ")";
        }
        std::cout << std::endl;
    }

    if (i == 0) {
        std::cerr << "No interfaces found! Make sure Npcap/WinPcap is installed (Windows) or you have sufficient permissions." << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    int choice;
    std::string selected_interface_name;

    while (true) {
        std::cout << "Enter the number of the interface to monitor: ";
        std::cin >> choice;

        // Validate user input against the actual number of found interfaces ('i')
        if (std::cin.fail() || choice < 1 || choice > i) {
            std::cout << "Invalid choice. Please enter a number between 1 and " << i << "." << std::endl;
            std::cin.clear(); // Clear error flags
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Discard invalid input
        } else {
            selected_interface_name = device_names[choice - 1]; // Get the name using the 0-based index
            break;
        }
    }

    pcap_freealldevs(alldevs); // Free the device list after selection

    // Create and initialize the NetworkMonitor instance
    NetworkMonitor monitor;

    // Initialize the monitor with the selected interface
    if (!monitor.initialize(selected_interface_name, 65535, 1, 100, errbuf)) {
        std::cerr << "Failed to initialize network monitor for " << selected_interface_name << std::endl;
        return 1;
    }

    // Set monitoring thresholds (example values)
    monitor.setBandwidthThresholdMbps(100.0); // Set a bandwidth threshold
    monitor.setPacketRateThreshold(10000);   // Set a packet rate threshold

    int mainMenuChoice;
    do {
        displayMenu();
        std::cout << "Enter your choice: ";
        std::cin >> mainMenuChoice;

        // Clear input buffer in case of non-integer input or extra characters
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        switch (mainMenuChoice) {
            case 1:
                handleMonitorOption(monitor);
                break;
            case 2:
                handleDiscoveryOption(monitor);
                break;
            case 3:
                std::cout << "Exiting program. Goodbye!" << std::endl;
                break;
            default:
                std::cout << "Invalid choice. Please try again." << std::endl;
                break;
        }
    } while (mainMenuChoice != 3);

    return 0;
}

// --- Menu and Option Handlers ---

void displayMenu() {
    std::cout << "\n--- Main Menu ---" << std::endl;
    std::cout << "1. Start Network Monitoring (Live Capture)" << std::endl;
    std::cout << "2. Perform Network Discovery" << std::endl;
    std::cout << "3. Exit" << std::endl;
}

void handleMonitorOption(NetworkMonitor& monitor) {
    int duration;
    std::cout << "Enter capture duration in seconds (e.g., 60 for 1 minute): ";
    std::cin >> duration;
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    if (std::cin.fail() || duration <= 0) {
        std::cout << "Invalid duration. Please enter a positive integer." << std::endl;
        return;
    }

    int output_choice;
    std::cout << "Choose output for live capture: (1) To Console (Detailed Parse) (2) To .pcap File: ";
    std::cin >> output_choice;
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    std::unique_ptr<PacketWriter> outputWriter;
    std::string output_filename;

    if (output_choice == 1) {
        outputWriter = std::make_unique<ConsoleWriter>();
        std::cout << "Capturing raw packets and parsing details to console." << std::endl;
    } else if (output_choice == 2) {
        output_filename = getStringInput("Enter filename for .pcap output (e.g., my_capture.pcap): ");
        outputWriter = std::make_unique<PcapFileWriter>(); // PcapFileWriter needs pcap_t* to open
        std::cout << "Capturing raw packets to .pcap file: " << output_filename << std::endl;
    } else {
        std::cout << "Invalid output choice. Defaulting to console output." << std::endl;
        outputWriter = std::make_unique<ConsoleWriter>();
    }

    // Pass the raw pointer from the unique_ptr to startLiveCapture.
    // NetworkMonitor does NOT take ownership of this pointer; it just uses it.
    // The writer's open method will be called inside startLiveCapture,
    // where it can access NetworkMonitor's pcap_handle_ via getPcapHandle().
    monitor.startLiveCapture(duration, outputWriter.get());

    std::cout << "\n--- Final Network Statistics ---" << std::endl;
    monitor.printCurrentStats(); // Print final summary after capture ends
}

void handleDiscoveryOption(NetworkMonitor& monitor) {
    int discoveryChoice;
    std::string network_prefix;
    int start_host, end_host;
    std::string domain_name, dns_server_ip, ad_domain, username, password;
    std::string ip_address, mac_address;
    std::string snmp_version, community_or_username;
    std::vector<u_short> common_ports = {21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389, 8080}; // Example common ports

    std::cout << "\n--- Network Discovery Menu ---" << std::endl;
    std::cout << "1. Perform ARP Scan" << std::endl;
    std::cout << "2. Perform IP Range Scan (Ping & Port Scan)" << std::endl;
    std::cout << "3. Perform DNS Zone Transfer Discovery (Conceptual)" << std::endl;
    std::cout << "4. Perform Active Directory Integration Discovery (Conceptual)" << std::endl;
    std::cout << "5. Add Manual Device" << std::endl;
    std::cout << "6. Perform SNMP Discovery on Discovered Devices" << std::endl;
    std::cout << "7. Back to Main Menu" << std::endl;
    std::cout << "Enter your choice: ";
    std::cin >> discoveryChoice;
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    switch (discoveryChoice) {
        case 1:
            std::cout << "Enter network prefix (e.g., 192.168.1.): ";
            std::cin >> network_prefix;
            std::cout << "Enter start host IP (e.g., 1): ";
            std::cin >> start_host;
            std::cout << "Enter end host IP (e.g., 254): ";
            std::cin >> end_host;
            monitor.performArpScan(network_prefix, start_host, end_host);
            break;
        case 2: {
            bool perform_ping;
            char ping_choice;
            std::cout << "Enter network prefix (e.g., 192.168.1.): ";
            std::cin >> network_prefix;
            std::cout << "Enter start host IP (e.g., 1): ";
            std::cin >> start_host;
            std::cout << "Enter end host IP (e.g., 254): ";
            std::cin >> end_host;
            std::cout << "Perform ICMP ping? (y/n): ";
            std::cin >> ping_choice;
            perform_ping = (tolower(ping_choice) == 'y');
            monitor.performIpRangeDiscovery(network_prefix, start_host, end_host, perform_ping, common_ports);
            break;
        }
        case 3:
            std::cout << "Enter domain name (e.g., example.com): ";
            std::cin >> domain_name;
            std::cout << "Enter DNS server IP (e.g., 8.8.8.8): ";
            std::cin >> dns_server_ip;
            monitor.performDNSDiscovery(domain_name, dns_server_ip);
            break;
        case 4:
            std::cout << "Enter Active Directory Domain (e.g., mydomain.local): ";
            std::cin >> ad_domain;
            std::cout << "Enter Username: ";
            std::cin >> username;
            std::cout << "Enter Password: ";
            std::cin >> password;
            monitor.performADDiscovery(ad_domain, username, password);
            break;
        case 5:
            std::cout << "Enter IP Address (e.g., 192.168.1.100): ";
            std::cin >> ip_address;
            std::cout << "Enter MAC Address (optional, e.g., AA:BB:CC:DD:EE:FF, or leave empty for N/A): ";
            std::cin >> mac_address;
            monitor.performManualDeviceAddition(ip_address, mac_address);
            break;
        case 6:
            std::cout << "Enter SNMP Version (e.g., v1, v2c, v3): ";
            std::cin >> snmp_version;
            std::cout << "Enter Community String (for v1/v2c) or Username (for v3): ";
            std::cin >> community_or_username;
            monitor.performSNMPDiscoveryOnDiscoveredDevices(snmp_version, community_or_username);
            break;
        case 7:
            std::cout << "Returning to Main Menu." << std::endl;
            break;
        default:
            std::cout << "Invalid choice. Please try again." << std::endl;
            break;
    }
}
