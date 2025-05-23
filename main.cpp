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

    std::unique_ptr<PacketWriter> capture_writer;
    std::string actual_capture_destination;

    if (capture_output_choice == 1) {
        capture_writer = std::make_unique<PcapFileWriter>();
        actual_capture_destination = capture_filename;
        std::cout << "Capturing to file: " << actual_capture_destination << std::endl;
    } else {
        capture_writer = std::make_unique<ConsoleWriter>(); // ConsoleWriter now uses PacketParser
        actual_capture_destination = "";
        std::cout << "Capturing to console with detailed parsing." << std::endl;
    }

    // --- Initialize Network Capture ---
    NetworkCapture capturer(std::move(capture_writer));

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

    // --- Start Live Packet Capture ---
    std::cout << "\n--- Live Packet Capture ---" << std::endl;
    // Note: The ARP filter from the scan is removed by pcap_setfilter(handle, NULL) in NetworkScanner,
    // so general capture will resume.
    if (!capturer.startCapture(capture_duration, actual_capture_destination)) {
        std::cerr << "Failed to start live capture. Exiting." << std::endl;
        return 1;
    }

    // --- Read Captured Output (if written to file) ---
    if (capture_output_choice == 1) { // Only read if it was written to a file
        std::cout << "\n--- Reading Captured File ---" << std::endl;

        std::cout << "Choose output for reading file: (1) To Console (Detailed Parse) (2) To (new) File: ";
        int read_output_choice;
        std::cin >> read_output_choice;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        std::unique_ptr<PacketWriter> read_writer;
        // std::string actual_read_destination; // This line is now removed

        if (read_output_choice == 1) {
            read_writer = std::make_unique<ConsoleWriter>();
            // actual_read_destination = ""; // This line is now removed
            // The ConsoleWriter doesn't need a filename for its open() method, it just prints.
            std::cout << "Reading from '" << capture_filename << "' and printing to console with detailed parsing." << std::endl;
        } else {
            std::string new_output_filename;
            std::cout << "Enter a new filename to re-dump captured packets (e.g., redump.pcap): ";
            std::getline(std::cin, new_output_filename);
            read_writer = std::make_unique<PcapFileWriter>();
            // actual_read_destination = new_output_filename; // This line is now removed
            // The PcapFileWriter's open() method takes the filename directly.
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

    std::cout << "\nApplication finished gracefully." << std::endl;
    return 0;
}