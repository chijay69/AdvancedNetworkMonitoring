#include <iostream>
#include <string>
#include <memory> // For std::unique_ptr
#include <limits> // For std::numeric_limits

// Your custom headers
#include "NetworkCapture.h"
#include "PcapFileWriter.h"
#include "ConsoleWriter.h"
#include "PcapFileReader.h"
#include "NetworkScanner.h" // New
#include "InputClass.h"     // Assuming you still want to demonstrate InputClass
#include "NetworkMonitor.h"
#include "MonitorWriter.h"


int main() {
    std::cout << "--- Advanced Network Analyzer ---" << std::endl;

    // --- InputClass Demonstration (Optional) ---
    std::string textInput;
    InputClass inputClass;
    std::cout << "\nEnter some text (for InputClass demo): ";
    std::getline(std::cin, textInput);
    inputClass.setInput(textInput);
    std::cout << "InputClass demo: You entered: \"" << inputClass.getInput() << "\"" << std::endl;

    // --- Network Capture Setup ---
    std::cout << "\n--- Capture Setup ---" << std::endl;

    std::string capture_filename;
    std::cout << "Enter filename for captured packets (e.g., my_capture.pcap): ";
    std::getline(std::cin >> std::ws, capture_filename);

    int capture_duration;
    std::cout << "Enter capture duration in seconds (e.g., 5): ";
    std::cin >> capture_duration;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    std::cout << "Choose output for live capture: (1) To File (2) To Console (Detailed Parse): ";
    int capture_output_choice;
    std::cin >> capture_output_choice;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    // --- Initialize Network monitoring ---
    NetworkMonitor monitor(60);

    // set monitoring threshold
    monitor.setBandwidthThresholdMbps(100);
    monitor.setPacketRateThreshold(1000);

    // setup PacketWriter
    std::unique_ptr<PacketWriter> base_writer;
    std::string actual_capture_destination;

    if (capture_output_choice == 1) {
        base_writer = std::make_unique<PcapFileWriter>();
        actual_capture_destination = capture_filename;
        std::cout << "Capturing to file: " << actual_capture_destination << std::endl;
    } else {
        base_writer = std::make_unique<ConsoleWriter>(); // ConsoleWriter now uses PacketParser
        actual_capture_destination = "";
        std::cout << "Capturing to console with detailed parsing." << std::endl;
    }

    // wrap base_writer with a monitoring writer
    auto monitoring_writer = std::make_unique<MonitorWriter>(std::move(base_writer), monitor);

    // --- Initialize Network Capture ---
    NetworkCapture capturer(std::move(monitoring_writer));

    if (!capturer.listDevices()) {
        std::cerr << "Failed to list devices. Exiting." << std::endl;
        return 1;
    }

    if (!capturer.selectDevice()) { // This now also gets MAC/IP
        std::cerr << "Failed to select device. Exiting." << std::endl;
        return 1;
    }

    // --- Network Scanning (ARP Scan) ---
    std::cout << "\n--- Network Scanning (ARP) ---" << std::endl;
    NetworkScanner scanner;

    // Get IP and MAC from the selected network adapter
    std::vector<u_char> source_mac = capturer.getSourceMacAddress();
    std::string source_ip = capturer.getSourceIpAddress();
    std::string network_prefix = capturer.getNetworkPrefix();

    if (source_mac.empty() || source_ip.empty() || network_prefix.empty()) {
        std::cerr << "Error: Could not determine source MAC/IP/Network for ARP scan. Skipping scan." << std::endl;
    } else {
        // Perform ARP scan on the common home network range (e.g., .1 to .254)
        if (!scanner.performArpScan(capturer.getPcapHandle(), source_mac, source_ip, network_prefix, 1, 254)) {
            std::cerr << "ARP scan failed or was incomplete." << std::endl;
        }
        scanner.printDiscoveredHosts();
    }

    // start Network monitoring
    std::cout << "\nStarting Network monitoring..." << std::endl;
    monitor.startMonitoring();

    // create a thread to print periodically
    std::atomic<bool> stop_stats_thread = false;
    std::thread stats_thread([&monitor, &stop_stats_thread, capture_duration]() {
        for (int i = 0; i < capture_duration && !stop_stats_thread; i++) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            if (i % 5 == 0) { // Print stats every 5 seconds
                monitor.printCurrentStats();
            }
        }
    });

    // --- Start Live Packet Capture ---
    std::cout << "\n--- Live Packet Capture ---" << std::endl;

    if (!capturer.startCapture(capture_duration, actual_capture_destination)) {
        std::cerr << "Failed to start live capture. Exiting." << std::endl;
        stop_stats_thread = true;
        if (stats_thread.joinable()) stats_thread.join();
        return 1;    }

    // Wait for stats thread to finish
    stop_stats_thread = true;
    if (stats_thread.joinable()) stats_thread.join();

    // Stop monitoring
    monitor.stopMonitoring();


    // --- Read Captured Output (if written to file) ---
    if (capture_output_choice == 1) { // Only read if it was written to a file
        std::cout << "\n--- Reading Captured File ---" << std::endl;

        std::cout << "Choose output for reading file: (1) To Console (Detailed Parse) (2) To (new) File: ";
        int read_output_choice;
        std::cin >> read_output_choice;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        std::unique_ptr<PacketWriter> read_writer;

        if (read_output_choice == 1) {
            read_writer = std::make_unique<ConsoleWriter>();
            std::cout << "Reading from '" << capture_filename << "' and printing to console with detailed parsing." << std::endl;
        } else {
            std::string new_output_filename;
            std::cout << "Enter a new filename to re-dump captured packets (e.g., redump.pcap): ";
            std::getline(std::cin, new_output_filename);
            read_writer = std::make_unique<PcapFileWriter>();
            read_writer->open(new_output_filename, nullptr); // Open the PcapFileWriter for writing
            std::cout << "Reading from '" << capture_filename << "' and re-dumping to: " << new_output_filename << std::endl;
        }

        PcapFileReader file_reader;
        if (!read_writer) {
            std::cerr << "No PacketWriter available." << std::endl;
            return 1;
        }
        if (!file_reader.readFromFile(capture_filename, *read_writer)) {
            std::cerr << "Failed to read packets from file." << std::endl;
            return 1;
        }
    } else {
        std::cout << "\nSkipping file read as capture was sent to console (live parsing)." << std::endl;
    }

    // Final network statistics summary
    std::cout << "\n--- Final Network Statistics Summary ---" << std::endl;
    monitor.printCurrentStats();

    std::cout << "\nApplication finished gracefully." << std::endl;
    return 0;
}