cmake_minimum_required(VERSION 3.31)
project(cppTutorial) # Project name

set(CMAKE_CXX_STANDARD 20)


# --- Npcap/WinPcap specific configuration for Windows ---
set(NPCAP_ROOT "C:/Program Files/npcap-sdk-1.15") # IMPORTANT: Adjust this path!
set(NPCAP_INCLUDE_DIR "${NPCAP_ROOT}/Include")
set(NPCAP_LIB_DIR "${NPCAP_ROOT}/Lib/x64") # Use x86 for 32-bit builds


add_executable(cppTutorial main.cpp
        InputClass.cpp
        InputClass.h
        PacketWriter.h
        PcapFileWriter.h
        PcapFileWriter.cpp
        ConsoleWriter.h
        ConsoleWriter.cpp
        NetworkCapture.h
        NetworkCapture.cpp
        PcapFileReader.h
        PcapFileReader.cpp
        PacketStructs.h
        PacketParser.h
        packetParser.cpp
        NetworkScanner.h
        NetworkScanner.cpp
        NetworkMonitor.h
        NetworkMonitor.cpp
        MonitorWriter.h
        MonitorWriter.cpp) # Defines the executable target named 'cppTutorial'


# Add Npcap include directory
target_include_directories(cppTutorial PRIVATE ${NPCAP_INCLUDE_DIR}) # <--- CHANGED FROM 'untitled'

# Link Npcap libraries
target_link_libraries(cppTutorial PRIVATE # <--- CHANGED FROM 'untitled'
        ${NPCAP_LIB_DIR}/wpcap.lib
        ${NPCAP_LIB_DIR}/Packet.lib
        Ws2_32.lib # Often needed for Winsock functions on Windows
        Iphlpapi.lib # Needed for GetAdaptersAddresses (Windows-specific MAC/IP lookup)
)