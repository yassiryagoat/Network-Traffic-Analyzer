package com.alok.trafficanalyzer;

import org.pcap4j.core.*;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.packet.ArpPacket.ArpHeader;
import org.pcap4j.packet.IcmpV4CommonPacket.IcmpV4CommonHeader;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.TcpPort;

import java.io.EOFException;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.TimeoutException;
//import org.pcap4j.packet.Dot11Packet;


public class PacketCapture {

    private static final String PCAP_FILE = "captured_packets2.pcap";
    private static final int SNAPSHOT_LENGTH = 65536; // bytes
    private static final int READ_TIMEOUT = 50; // ms
    private static final int MAX_PACKETS = 100;

//me
        public static String data;
        //


    public static void main(String[] args) {
        try {
            // Find all network devices
            List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
            if (allDevs == null || allDevs.isEmpty()) {
                System.out.println("No devices found!");
                return;
            }

            // Print all devices
            System.out.println("Available network devices:");
            for (int i = 0; i < allDevs.size(); i++) {
                PcapNetworkInterface dev = allDevs.get(i);
                System.out.println(i + ": " + dev.getName() + 
                                  (dev.getDescription() != null ? " (" + dev.getDescription() + ")" : "") +
                                  " - Addresses: " + dev.getAddresses());
            }

            // Ask user to select device
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter the device number to capture: ");
            int deviceIndex = scanner.nextInt();
            scanner.nextLine(); // Consume newline

            if (deviceIndex < 0 || deviceIndex >= allDevs.size()) {
                System.out.println("Invalid device index!");
                return;
            }

            // Ask for optional filter
            System.out.print("Enter capture filter (leave blank for no filter): ");
            String filter = scanner.nextLine().trim();
            
            System.out.print("Save packets to file? (y/n): ");
            boolean saveToFile = scanner.nextLine().trim().toLowerCase().startsWith("y");
            
            System.out.print("Number of packets to capture (default 100): ");
            String packetCountStr = scanner.nextLine().trim();
            int packetLimit = packetCountStr.isEmpty() ? MAX_PACKETS : Integer.parseInt(packetCountStr);
            
            scanner.close();

            // Open selected device
            PcapNetworkInterface device = allDevs.get(deviceIndex);
            System.out.println("\nOpening device: " + device.getName());
            
            final PcapHandle handle = device.openLive(
                    SNAPSHOT_LENGTH,
                    PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                    READ_TIMEOUT
            );
            
            // Set filter if provided
            if (!filter.isEmpty()) {
                handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
                System.out.println("Filter applied: " + filter);
            }

            // Create PCAP file dumper if requested
            PcapDumper dumper = null;
            if (saveToFile) {
                dumper = handle.dumpOpen(PCAP_FILE);
                System.out.println("Saving packets to: " + PCAP_FILE);
            }
            
            // Create CSV log file for detailed packet info
            FileWriter csvWriter = new FileWriter("packet_details.csv");
            csvWriter.write("Number,Timestamp,Type,Source,Destination,Protocol,Length,Info\n");
            
            final PcapDumper finalDumper = dumper;
            final FileWriter finalCsvWriter = csvWriter;
            
            System.out.println("\nStarting packet capture... Press Ctrl+C to stop");
            System.out.println("------------------------------------------------");

            // Get start time
            long startTime = System.currentTimeMillis();
            final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
            
            // Create packet listener
            PacketListener listener = new PacketListener() {
                private int packetCount = 0;
                
                @Override
                public void gotPacket(Packet packet) {
                    try {
                        packetCount++;
                        
                        // Get timestamp
                        String timestamp = sdf.format(new Date(handle.getTimestamp().getTime()));
                        
                        // Parse and print packet details
                        System.out.println("\nPacket #" + packetCount + " [" + timestamp + "]");
                        
                        // Store to file if requested
                        if (finalDumper != null) {
                            finalDumper.dump(packet);
                        }
                        
                        // Format packet info
                        PacketInfo info = formatPacket(packet);
                        
                        // Write to CSV
                        finalCsvWriter.write(String.format("%d,%s,%s,%s,%s,%s,%d,%s\n",
                                packetCount, timestamp, info.getType(), info.getSource(),
                                info.getDestination(), info.getProtocol(), packet.length(), 
                                info.getInfo().replace(",", ";")));
                        
                        // Flush CSV to ensure data is written even if program crashes
                        finalCsvWriter.flush();
                    } catch (NotOpenException | IOException e) {
                        e.printStackTrace();
                    }
                }
            };

            try {
                // Start the capture with limit
                handle.loop(packetLimit, listener);
                System.out.println("\nCapture complete. " + packetLimit + " packets processed.");
            } catch (InterruptedException e) {
                System.out.println("\nCapture interrupted.");
            }

            // Calculate stats
            long duration = System.currentTimeMillis() - startTime;
            System.out.println("Capture duration: " + (duration / 1000.0) + " seconds");
            
            // Close handles
            if (dumper != null) {
                dumper.close();
                System.out.println("Packets saved to: " + new File(PCAP_FILE).getAbsolutePath());
            }
            
            csvWriter.close();
            System.out.println("Packet details saved to: " + new File("packet_details.csv").getAbsolutePath());
            
            handle.close();
            
        } catch (PcapNativeException | NotOpenException | IOException e) {
            e.printStackTrace();
        }
        PacketClassifier.main(args);
    }

    /**
     * Formats packet for display and returns structured information
     */
    private static PacketInfo formatPacket(Packet packet) {
        PacketInfo info = new PacketInfo();
        StringBuilder display = new StringBuilder();
        
        
        try {
            // Handle RadioTap header (wireless specific)
            if (packet.contains(RadiotapPacket.class)) {
                RadiotapPacket radiotapPacket = packet.get(RadiotapPacket.class);
                
                info.setType("RadioTap");
                display.append("RadioTap Header:\n");
                display.append("  Length: " + radiotapPacket.getHeader().length() + " bytes\n");
                
                // If we have 802.11 frame inside
                
                /*if (packet.contains(Dot11Packet.class)) {
                    Dot11Packet dot11Packet = packet.get(Dot11Packet.class);
                    Dot11FrameType frameType = dot11Packet.getHeader().getType();
                    
                    display.append("802.11 Frame:\n");
                    display.append("  Type: " + frameType + "\n");
                    display.append("  Subtype: " + dot11Packet.getHeader().getSubtype() + "\n");
                    
                    // Get MAC addresses (varies by frame type)
                    String transmitter = dot11Packet.getHeader().getAddress1() != null ? 
                                         dot11Packet.getHeader().getAddress1().toString() : "unknown";
                    String receiver = dot11Packet.getHeader().getAddress2() != null ? 
                                     dot11Packet.getHeader().getAddress2().toString() : "unknown";
                    
                    info.setSource(transmitter);
                    info.setDestination(receiver);
                    info.setProtocol("802.11");
                    
                    display.append("  Transmitter: " + transmitter + "\n");
                    display.append("  Receiver: " + receiver + "\n");
                    if (dot11Packet.getHeader().getAddress3() != null) {
                        display.append("  BSSID: " + dot11Packet.getHeader().getAddress3() + "\n");
                    }
                }
                */
                
                // Add the RadioTap info to the packet info
                info.setInfo(display.toString().replace("\n", " "));
                System.out.println(display.toString());
                return info;
            }
            
            // Handle Ethernet frames
            if (packet.contains(EthernetPacket.class)) {
                EthernetPacket ethPacket = packet.get(EthernetPacket.class);
                EthernetPacket.EthernetHeader ethHeader = ethPacket.getHeader();
                
                info.setType("Ethernet");
                info.setSource(ethHeader.getSrcAddr().toString());
                info.setDestination(ethHeader.getDstAddr().toString());
                
                display.append("Ethernet Frame:\n");
                display.append("  Source MAC: " + ethHeader.getSrcAddr() + "\n");
                display.append("  Destination MAC: " + ethHeader.getDstAddr() + "\n");
                display.append("  Type: 0x" + Integer.toHexString(ethHeader.getType().value() & 0xffff) + "\n");
                
                // Handle ARP packets
                if (packet.contains(ArpPacket.class)) {
                    ArpPacket arpPacket = packet.get(ArpPacket.class);
                    ArpHeader arpHeader = arpPacket.getHeader();
                    
                    info.setProtocol("ARP");
                    String operation = arpHeader.getOperation() == ArpOperation.REQUEST ? "Request" : "Reply";
                    
                    display.append("ARP Packet (" + operation + "):\n");
                    display.append("  Sender MAC: " + arpHeader.getSrcHardwareAddr() + "\n");
                    display.append("  Sender IP: " + arpHeader.getSrcProtocolAddr() + "\n");
                    display.append("  Target MAC: " + arpHeader.getDstHardwareAddr() + "\n");
                    display.append("  Target IP: " + arpHeader.getDstProtocolAddr() + "\n");
                    
                    info.setInfo("ARP " + operation + " " + arpHeader.getSrcProtocolAddr() + 
                                 " -> " + arpHeader.getDstProtocolAddr());
                }
                
                // Handle IPv4 packets
                else if (packet.contains(IpV4Packet.class)) {
                    IpV4Packet ipv4Packet = packet.get(IpV4Packet.class);
                    IpV4Packet.IpV4Header ipv4Header = ipv4Packet.getHeader();
                    
                    InetAddress srcAddr = ipv4Header.getSrcAddr();
                    InetAddress dstAddr = ipv4Header.getDstAddr();
                    
                    info.setProtocol("IPv4");
                    info.setSource(info.getSource() + " (" + srcAddr.getHostAddress() + ")");
                    info.setDestination(info.getDestination() + " (" + dstAddr.getHostAddress() + ")");
                    
                    display.append("IPv4 Packet:\n");
                    display.append("  Version: " + ipv4Header.getVersion() + "\n");
                    display.append("  Source IP: " + srcAddr.getHostAddress() + "\n");
                    display.append("  Destination IP: " + dstAddr.getHostAddress() + "\n");
                    display.append("  Protocol: " + ipv4Header.getProtocol() + "\n");
                    display.append("  TTL: " + ipv4Header.getTtl() + "\n");
                    
                    // Handle TCP packets
                    if (packet.contains(TcpPacket.class)) {
                        TcpPacket tcpPacket = packet.get(TcpPacket.class);
                        TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
                        
                        int srcPort = tcpHeader.getSrcPort().valueAsInt();
                        int dstPort = tcpHeader.getDstPort().valueAsInt();
                        info.setProtocol("TCP");
                        
                        // Try to determine application protocol based on port
                        String appProtocol = getApplicationProtocol(srcPort, dstPort);
                        if (!appProtocol.isEmpty()) {
                            info.setProtocol(appProtocol);
                        }
                        
                        display.append("TCP Segment:\n");
                        display.append("  Source Port: " + srcPort + "\n");
                        display.append("  Destination Port: " + dstPort + "\n");
                        display.append("  Sequence Number: " + tcpHeader.getSequenceNumber() + "\n");
                        display.append("  Acknowledgment Number: " + tcpHeader.getAcknowledgmentNumber() + "\n");
                        display.append("  Flags: " + getTcpFlags(tcpHeader) + "\n");
                        display.append("  Window Size: " + tcpHeader.getWindow() + "\n");
                        
                        info.setInfo(info.getProtocol() + " " + srcAddr.getHostAddress() + ":" + srcPort + 
                                     " -> " + dstAddr.getHostAddress() + ":" + dstPort + 
                                     " [" + getTcpFlags(tcpHeader) + "]");
                        
                        // Handle HTTP if present
                        if (appProtocol.equals("HTTP") && tcpPacket.getPayload() != null) {
                            byte[] payload = tcpPacket.getPayload().getRawData();
                            String payloadStr = new String(payload);
                            
                            // Simple HTTP detection
                            if (payloadStr.startsWith("GET ") || payloadStr.startsWith("POST ") || 
                                payloadStr.startsWith("HTTP/")) {
                                display.append("HTTP Data:\n");
                                // Show first line of HTTP request/response
                                String firstLine = payloadStr.split("\r\n")[0];
                                display.append("  " + firstLine + "\n");
                                info.setInfo("HTTP: " + firstLine);
                            }
                        }
                    }
                    
                    // Handle UDP packets
                    else if (packet.contains(UdpPacket.class)) {
                        UdpPacket udpPacket = packet.get(UdpPacket.class);
                        UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();
                        
                        int srcPort = udpHeader.getSrcPort().valueAsInt();
                        int dstPort = udpHeader.getDstPort().valueAsInt();
                        info.setProtocol("UDP");
                        
                        // Try to determine application protocol based on port
                        String appProtocol = getApplicationProtocol(srcPort, dstPort);
                        if (!appProtocol.isEmpty()) {
                            info.setProtocol(appProtocol);
                        }
                        
                        display.append("UDP Datagram:\n");
                        display.append("  Source Port: " + srcPort + "\n");
                        display.append("  Destination Port: " + dstPort + "\n");
                        display.append("  Length: " + udpHeader.getLength() + "\n");
                        
                        info.setInfo(info.getProtocol() + " " + srcAddr.getHostAddress() + ":" + srcPort + 
                                     " -> " + dstAddr.getHostAddress() + ":" + dstPort);
                        
                        // Handle DNS if it's on port 53
                        if (srcPort == 53 || dstPort == 53) {
                            display.append("DNS Packet\n");
                            // Advanced DNS parsing could be added here
                        }
                    }
                    
                    // Handle ICMP packets
                    else if (packet.contains(IcmpV4CommonPacket.class)) {
                        IcmpV4CommonPacket icmpPacket = packet.get(IcmpV4CommonPacket.class);
                        IcmpV4CommonHeader icmpHeader = icmpPacket.getHeader();
                        
                        info.setProtocol("ICMP");
                        
                        display.append("ICMP Packet:\n");
                        display.append("  Type: " + icmpHeader.getType() + "\n");
                        display.append("  Code: " + icmpHeader.getCode() + "\n");
                        
                        // Format ICMP information based on type
                        String icmpInfo = "Type " + icmpHeader.getType() + ", Code " + icmpHeader.getCode();
                        if (icmpHeader.getType().value() == 8) {
                            icmpInfo = "Echo Request (Ping)";
                        } else if (icmpHeader.getType().value() == 0) {
                            icmpInfo = "Echo Reply (Ping)";
                        }
                        
                        info.setInfo("ICMP: " + icmpInfo);
                    }
                }
                
                // Handle IPv6 packets
                else if (packet.contains(IpV6Packet.class)) {
                    IpV6Packet ipv6Packet = packet.get(IpV6Packet.class);
                    IpV6Packet.IpV6Header ipv6Header = ipv6Packet.getHeader();
                    
                    InetAddress srcAddr = ipv6Header.getSrcAddr();
                    InetAddress dstAddr = ipv6Header.getDstAddr();
                    
                    info.setProtocol("IPv6");
                    info.setSource(info.getSource() + " (" + srcAddr.getHostAddress() + ")");
                    info.setDestination(info.getDestination() + " (" + dstAddr.getHostAddress() + ")");
                    
                    display.append("IPv6 Packet:\n");
                    display.append("  Version: " + ipv6Header.getVersion() + "\n");
                    display.append("  Source IP: " + srcAddr.getHostAddress() + "\n");
                    display.append("  Destination IP: " + dstAddr.getHostAddress() + "\n");
                    display.append("  Next Header: " + ipv6Header.getNextHeader() + "\n");
                    display.append("  Hop Limit: " + ipv6Header.getHopLimit() + "\n");
                    
                    // Further protocol handling can be added for IPv6
                }
            }
            
        } catch (Exception e) {
            display.append("Error parsing packet: " + e.getMessage() + "\n");
            e.printStackTrace();
        }
        
        // If we couldn't identify the packet format, just dump raw data
        if (display.length() == 0) {
            display.append("Unknown Packet Format:\n");
            display.append("  Raw data: " + ByteArrays.toHexString(packet.getRawData(), " ") + "\n");
            
            info.setType("Unknown");
            info.setProtocol("Unknown");
            info.setInfo("Raw data packet");
        }
        data=display.toString();
        // Print the formatted packet
        System.out.println(data);
        
        
        // If info details are missing, provide defaults
        if (info.getSource() == null) info.setSource("unknown");
        if (info.getDestination() == null) info.setDestination("unknown");
        if (info.getInfo() == null) info.setInfo(info.getProtocol());
        
        return info;
    }
    
    /**
     * Helper class to hold packet information
     */
    static class PacketInfo {
        private String type = "";
        private String source = "";
        private String destination = "";
        private String protocol = "";
        private String info = "";
        
        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        
        public String getSource() { return source; }
        public void setSource(String source) { this.source = source; }
        
        public String getDestination() { return destination; }
        public void setDestination(String destination) { this.destination = destination; }
        
        public String getProtocol() { return protocol; }
        public void setProtocol(String protocol) { this.protocol = protocol; }
        
        public String getInfo() { return info; }
        public void setInfo(String info) { this.info = info; }
    }
    
    /**
     * Helper method to get TCP flags as string
     */
    private static String getTcpFlags(TcpPacket.TcpHeader header) {
        StringBuilder flags = new StringBuilder();
        if (header.getUrg()) flags.append("URG ");
        if (header.getAck()) flags.append("ACK ");
        if (header.getPsh()) flags.append("PSH ");
        if (header.getRst()) flags.append("RST ");
        if (header.getSyn()) flags.append("SYN ");
        if (header.getFin()) flags.append("FIN ");
        return flags.toString().trim();
    }
    
    /**
     * Helper method to identify application protocol based on port numbers
     */
    private static String getApplicationProtocol(int srcPort, int dstPort) {
        // Check the most common ports
        int port = (srcPort == 80 || dstPort == 80) ? 80 :
                   (srcPort == 443 || dstPort == 443) ? 443 :
                   (srcPort == 53 || dstPort == 53) ? 53 :
                   (srcPort == 22 || dstPort == 22) ? 22 :
                   (srcPort == 21 || dstPort == 21) ? 21 :
                   (srcPort == 25 || dstPort == 25) ? 25 :
                   (srcPort == 110 || dstPort == 110) ? 110 :
                   (srcPort == 143 || dstPort == 143) ? 143 :
                   (srcPort == 3389 || dstPort == 3389) ? 3389 : 0;
        
        switch (port) {
            case 80: return "HTTP";
            case 443: return "HTTPS";
            case 53: return "DNS";
            case 22: return "SSH";
            case 21: return "FTP";
            case 25: return "SMTP";
            case 110: return "POP3";
            case 143: return "IMAP";
            case 3389: return "RDP";
            default: return "";
        }
    }
    
}