## Project Structure

- **Core Network Components**:
  - `NetworkCapture`: Manages network interfaces, device selection, MAC/IP detection, and packet capture
  - `NetworkScanner`: Implements ARP scanning to discover active hosts on local networks
  - `PacketParser`: Provides deep packet inspection and protocol analysis capabilities

- **Packet Processing Pipeline**:
  - `PacketWriter`: Abstract interface for all packet output methods
  - `PcapFileWriter`: Serializes captured packets to industry-standard PCAP files
  - `ConsoleWriter`: Formats and displays detailed packet analysis in human-readable format
  - `PcapFileReader`: Reads and processes packets from saved PCAP capture files

- **Protocol Support**:
  - `PacketStructs.h`: Defines cross-platform data structures for packet headers
  - Comprehensive protocol parsing for Ethernet, IPv4, IPv6, TCP, UDP, ICMP, and ARP

- **Utility Components**:
  - `InputClass`: Demonstrates basic input processing functionality
  - Helper functions for MAC/IP conversion, formatting, and presentation

## Implementation Details

- **Modern C++ Design**:
  - Leverages C++20 features including ranges, concepts, and improved smart pointers
  - RAII principles for resource management and automatic cleanup
  - Strong type safety with appropriate use of constexpr and compile-time constants

- **Architectural Patterns**:
  - Strategy pattern for packet output methods (abstraction via PacketWriter)
  - Observer pattern for packet processing callbacks
  - Factory methods for packet structure creation

- **Performance Optimization**:
  - Thread-safe packet capture with minimal copy operations
  - Efficient memory management with pre-allocated buffers
  - Optimized protocol parsers with boundary checking

- **Robust Error Handling**:
  - Comprehensive error detection and reporting
  - Graceful degradation for partial or corrupted packets
  - Clear user feedback for administrative permission issues

- **Cross-Platform Considerations**:
  - Windows-specific optimizations for network adapter information
  - Conditional compilation for platform-specific features
  - Abstraction layer for platform-dependent network functions