package com.alok.trafficanalyzer;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.ByteArrays;

import java.io.EOFException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.TimeoutException;
import java.io.File;
import java.util.stream.Collectors;

public class PcapReader {
    
    public static String PacketToString = null;
    // Static variables to store classification results
    public static Map<String, IpClassification> ipClassificationMap = new HashMap<>();
    public static Map<Integer, PortClassification> portClassificationMap = new HashMap<>();
    
    // Static inner classes for classification results
    public static class IpClassification {
        public String ipAddress;
        public int sent;
        public int received;
        public int totalBytes;
        public String classification; // "Sender", "Receiver", "Balanced"
        
        @Override
        public String toString() {
            return String.format("IP: %s, Classification: %s, Sent: %d, Received: %d, Total Bytes: %d",
                    ipAddress, classification, sent, received, totalBytes);
        }
    }
    
    public static class PortClassification {
        public int port;
        public String service;
        public int packets;
        public int bytes;
        public int connections;
        public String classification; // "High usage", "Moderate usage", "Low usage"
        
        @Override
        public String toString() {
            return String.format("Port: %d, Service: %s, Classification: %s, Packets: %d, Bytes: %d, Connections: %d",
                    port, service, classification, packets, bytes, connections);
        }
    }
    
    // Static method to display IP classification information
    public static void displayIpClassification(String ipAddress) {
        IpClassification ipClass = ipClassificationMap.get(ipAddress);
        if (ipClass != null) {
            System.out.println(ipClass);
        } else {
            System.out.println("IP " + ipAddress + " has no classification data.");
        }
    }
    
    // Static method to display Port classification information
    public static void displayPortClassification(int port) {
        PortClassification portClass = portClassificationMap.get(port);
        if (portClass != null) {
            System.out.println(portClass);
        } else {
            System.out.println("Port " + port + " has no classification data.");
        }
    }
    
    // Static method to display all IP classifications
    public static void displayAllIpClassifications() {
        System.out.println("\n=== IP CLASSIFICATIONS ===");
        System.out.printf("%-20s %-12s %-8s %-10s %-12s\n", "IP Address", "Type", "Sent", "Received", "Total Bytes");
        for (int i = 0; i < 70; i++) {
            System.out.print("-");
        }
        System.out.println();
        
        for (IpClassification ip : ipClassificationMap.values()) {
            System.out.printf("%-20s %-12s %-8d %-10d %-12d\n", 
                ip.ipAddress, ip.classification, ip.sent, ip.received, ip.totalBytes);
        }
    }
    
    // Static method to display all Port classifications
    public static void displayAllPortClassifications() {
        System.out.println("\n=== PORT CLASSIFICATIONS ===");
        System.out.printf("%-8s %-12s %-14s %-10s %-12s %-10s\n", 
            "Port", "Service", "Classification", "Packets", "Bytes", "Connections");
        for (int i = 0; i < 70; i++) {
            System.out.print("-");
        }
        System.out.println();
        
        for (PortClassification port : portClassificationMap.values()) {
            System.out.printf("%-8d %-12s %-14s %-10d %-12d %-10d\n", 
                port.port, port.service, port.classification, port.packets, port.bytes, port.connections);
        }
    }
    
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java PcapReader <pcap-file> [options]");
            System.out.println("Options:");
            System.out.println("  --classify       Classify packets by IP and port");
            System.out.println("  --limit <num>    Limit the number of packets to process");
            System.out.println("  --verbose        Show packet payloads");
            System.out.println("  --top <num>      Number of top entries to show in classification (default: 10)");
            System.out.println("  --ip <ip-addr>   Display classification for specific IP");
            System.out.println("  --port <port>    Display classification for specific port");
            return;
        }

        String pcapFile = args[0];
        boolean classify = false;
        int limit = -1;
        boolean verbose = false;
        int topN = 10;
        String specificIp = null;
        int specificPort = -1;

        // Parse command line arguments
        for (int i = 1; i < args.length; i++) {
            if (args[i].equals("--classify")) {
                classify = true;
            } else if (args[i].equals("--limit") && i + 1 < args.length) {
                try {
                    limit = Integer.parseInt(args[++i]);
                } catch (NumberFormatException e) {
                    System.err.println("Invalid limit value: " + args[i]);
                    return;
                }
            } else if (args[i].equals("--verbose")) {
                verbose = true;
            } else if (args[i].equals("--top") && i + 1 < args.length) {
                try {
                    topN = Integer.parseInt(args[++i]);
                } catch (NumberFormatException e) {
                    System.err.println("Invalid top value: " + args[i]);
                    return;
                }
            } else if (args[i].equals("--ip") && i + 1 < args.length) {
                specificIp = args[++i];
            } else if (args[i].equals("--port") && i + 1 < args.length) {
                try {
                    specificPort = Integer.parseInt(args[++i]);
                } catch (NumberFormatException e) {
                    System.err.println("Invalid port value: " + args[i]);
                    return;
                }
            }
        }

        try {
            // Create a new PcapReaderAnalyzer
            PcapReaderAnalyzer analyzer = new PcapReaderAnalyzer(pcapFile);

            // Process packets
            if (classify) {
                analyzer.classifyPackets(topN);
            } else {
                analyzer.processPackets(limit, verbose);
                analyzer.classifyPackets(topN);
            }
            
            // Display specific IP or port classification if requested
            if (specificIp != null) {
                displayIpClassification(specificIp);
            }
            
            if (specificPort != -1) {
                displayPortClassification(specificPort);
            }
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

class PcapReaderAnalyzer {
    private String pcapFile;
    private PcapHandle handle;
    private int packetNumber = 0;
    
    // Statistics maps for classification
    private Map<String, IpStats> ipStatsMap = new HashMap<>();
    private Map<Integer, PortStats> portStatsMap = new HashMap<>();
    private Map<String, Integer> protocolStatsMap = new HashMap<>();
    
    // Inner classes for statistics
    static class IpStats {
        int sent = 0;
        int received = 0;
        int totalBytes = 0;
    }
    
    static class PortStats {
        Set<String> connections = new HashSet<>();
        int packets = 0;
        int bytes = 0;
    }

    public PcapReaderAnalyzer(String pcapFile) throws PcapNativeException {
        this.pcapFile = pcapFile;
        
        // Verify file exists
        File file = new File(pcapFile);
        if (!file.exists() || !file.isFile()) {
            throw new IllegalArgumentException("PCAP file not found: " + pcapFile);
        }
        
        // Open the PCAP file
        handle = Pcaps.openOffline(pcapFile);
        System.out.println("Successfully opened PCAP file: " + pcapFile);
    }

    public void processPackets(int limit, boolean verbose) {
        int packetCount = 0;
        
        try {
            while (limit < 0 || packetCount < limit) {
                try {
                    // Read next packet
                    Packet packet = handle.getNextPacketEx();
                    packetCount++;
                    
                    // Convert packet to string and print
                    String packetStr = packetToString(packet, verbose);
                    System.out.println(packetStr);
                    
                } catch (EOFException e) {
                    // End of file reached
                    break;
                } catch (TimeoutException e) {
                    // Timeout, continue
                    continue;
                }
            }
            
            System.out.println("Processed " + packetCount + " packets from " + pcapFile);
            
        } catch (Exception e) {
            System.err.println("Error processing packets: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public String packetToString(Packet packet, boolean verbose) {
        StringBuilder sb = new StringBuilder();
        // Get timestamp
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
        Date timestamp = new Date(handle.getTimestamp().getTime());

        sb.append("Packet captured at ").append(sdf.format(timestamp)).append("\n");
        sb.append("Length: ").append(packet.length()).append(" bytes\n");
        
        // Layer 2 - Ethernet
        if (packet.contains(EthernetPacket.class)) {
            EthernetPacket ethPacket = packet.get(EthernetPacket.class);
            sb.append("Ethernet: ")
              .append(ethPacket.getHeader().getSrcAddr())
              .append(" → ")
              .append(ethPacket.getHeader().getDstAddr())
              .append(", type: ")
              .append(String.format("0x%04x", ethPacket.getHeader().getType().value() & 0xFFFF))
              .append("\n");
            
            // Layer 3 - IP
            if (packet.contains(IpPacket.class)) {
                IpPacket ipPacket = packet.get(IpPacket.class);
                sb.append("IP: ")
                  .append(ipPacket.getHeader().getSrcAddr())
                  .append(" -> ")
                  .append(ipPacket.getHeader().getDstAddr());
                
                if (ipPacket.getHeader() instanceof IpV4Packet.IpV4Header) {
                    IpV4Packet.IpV4Header ipv4Header = (IpV4Packet.IpV4Header) ipPacket.getHeader();
                    sb.append(" (TTL: ").append(ipv4Header.getTtl()).append(")");
                }
                sb.append("\n");
                
                // Layer 4 - TCP/UDP/ICMP
                if (packet.contains(TcpPacket.class)) {
                    TcpPacket tcpPacket = packet.get(TcpPacket.class);
                    TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
                    
                    sb.append("TCP: ")
                      .append(ipPacket.getHeader().getSrcAddr()).append(":").append(tcpHeader.getSrcPort().valueAsInt())
                      .append(" -> ")
                      .append(ipPacket.getHeader().getDstAddr()).append(":").append(tcpHeader.getDstPort().valueAsInt())
                      .append(" ");
                    
                    // TCP flags
                    List<String> flags = new ArrayList<>();
                    if (tcpHeader.getSyn()) flags.add("SYN");
                    if (tcpHeader.getAck()) flags.add("ACK");
                    if (tcpHeader.getFin()) flags.add("FIN");
                    if (tcpHeader.getRst()) flags.add("RST");
                    if (tcpHeader.getPsh()) flags.add("PSH");
                    if (tcpHeader.getUrg()) flags.add("URG");
                    
                    sb.append("Flags: [").append(String.join(" ", flags)).append("] ");
                    sb.append("Seq: ").append(tcpHeader.getSequenceNumber()).append(" ");
                    sb.append("Ack: ").append(tcpHeader.getAcknowledgmentNumber()).append("\n");
                    
                    // Payload
                    if (verbose && tcpPacket.getPayload() != null) {
                        byte[] payload = tcpPacket.getPayload().getRawData();
                        sb.append("Payload (").append(payload.length).append(" bytes): ");
                        
                        try {
                            // Try to decode as text
                            String textPayload = new String(payload, "UTF-8");
                            boolean isPrintable = true;
                            
                            for (char c : textPayload.toCharArray()) {
                                if ((c < 32 || c > 126) && c != '\n' && c != '\r' && c != '\t') {
                                    isPrintable = false;
                                    break;
                                }
                            }
                            
                            if (isPrintable) {
                                sb.append("\n'''\n").append(textPayload).append("\n'''\n");
                            } else {
                                sb.append(ByteArrays.toHexString(payload, " ")).append("\n");
                            }
                        } catch (Exception e) {
                            sb.append(ByteArrays.toHexString(payload, " ")).append("\n");
                        }
                    }
                    
                } else if (packet.contains(UdpPacket.class)) {
                    UdpPacket udpPacket = packet.get(UdpPacket.class);
                    UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();
                    
                    sb.append("UDP: ")
                      .append(ipPacket.getHeader().getSrcAddr()).append(":").append(udpHeader.getSrcPort().valueAsInt())
                      .append(" → ")
                      .append(ipPacket.getHeader().getDstAddr()).append(":").append(udpHeader.getDstPort().valueAsInt())
                      .append(" Length: ").append(udpHeader.getLength()).append("\n");
                    
                    // Payload
                    if (verbose && udpPacket.getPayload() != null) {
                        byte[] payload = udpPacket.getPayload().getRawData();
                        sb.append("Payload (").append(payload.length).append(" bytes): ");
                        
                        try {
                            // Try to decode as text
                            String textPayload = new String(payload, "UTF-8");
                            boolean isPrintable = true;
                            
                            for (char c : textPayload.toCharArray()) {
                                if ((c < 32 || c > 126) && c != '\n' && c != '\r' && c != '\t') {
                                    isPrintable = false;
                                    break;
                                }
                            }
                            
                            if (isPrintable) {
                                sb.append("\n'''\n").append(textPayload).append("\n'''\n");
                            } else {
                                sb.append(ByteArrays.toHexString(payload, " ")).append("\n");
                            }
                        } catch (Exception e) {
                            sb.append(ByteArrays.toHexString(payload, " ")).append("\n");
                        }
                    }
                    
                } else if (packet.contains(IcmpV4CommonPacket.class)) {
                    IcmpV4CommonPacket icmpPacket = packet.get(IcmpV4CommonPacket.class);
                    IcmpV4CommonPacket.IcmpV4CommonHeader icmpHeader = icmpPacket.getHeader();
                    
                    sb.append("ICMP: Type ").append(icmpHeader.getType().value())
                      .append(" Code ").append(icmpHeader.getCode().value()).append("\n");
                }
            }
            
            // IPv6 support
            else if (packet.contains(IpV6Packet.class)) {
                IpV6Packet ipv6Packet = packet.get(IpV6Packet.class);
                IpV6Packet.IpV6Header ipv6Header = ipv6Packet.getHeader();
                
                sb.append("IPv6: ")
                  .append(ipv6Header.getSrcAddr())
                  .append(" → ")
                  .append(ipv6Header.getDstAddr())
                  .append("\n");
                
                // TCP/UDP over IPv6
                if (packet.contains(TcpPacket.class)) {
                    TcpPacket tcpPacket = packet.get(TcpPacket.class);
                    sb.append("TCP: ")
                      .append(ipv6Header.getSrcAddr()).append(":").append(tcpPacket.getHeader().getSrcPort().valueAsInt())
                      .append(" → ")
                      .append(ipv6Header.getDstAddr()).append(":").append(tcpPacket.getHeader().getDstPort().valueAsInt())
                      .append("\n");
                } else if (packet.contains(UdpPacket.class)) {
                    UdpPacket udpPacket = packet.get(UdpPacket.class);
                    sb.append("UDP: ")
                      .append(ipv6Header.getSrcAddr()).append(":").append(udpPacket.getHeader().getSrcPort().valueAsInt())
                      .append(" → ")
                      .append(ipv6Header.getDstAddr()).append(":").append(udpPacket.getHeader().getDstPort().valueAsInt())
                      .append("\n");
                } else if (packet.contains(IcmpV6CommonPacket.class)) {
                    IcmpV6CommonPacket icmpv6Packet = packet.get(IcmpV6CommonPacket.class);
                    sb.append("ICMPv6: Type ").append(icmpv6Packet.getHeader().getType().value())
                      .append(" Code ").append(icmpv6Packet.getHeader().getCode().value())
                      .append("\n");
                }
            }
            
            // ARP
            else if (packet.contains(ArpPacket.class)) {
                ArpPacket arpPacket = packet.get(ArpPacket.class);
                ArpPacket.ArpHeader arpHeader = arpPacket.getHeader();
                
                String op = arpHeader.getOperation().value() == 1 ? "request" : "reply";
                sb.append("ARP ").append(op).append(": ")
                  .append(arpHeader.getSrcProtocolAddr()).append(" (").append(arpHeader.getSrcHardwareAddr()).append(")")
                  .append(" → ")
                  .append(arpHeader.getDstProtocolAddr()).append(" (").append(arpHeader.getDstHardwareAddr()).append(")")
                  .append("\n");
            }
        }
        
        // Add separator
        for (int i = 0; i < 60; i++) {
            sb.append("-");
        }
        sb.append("\n");

        PcapReader.PacketToString = sb.toString();
        
        return sb.toString();
    }

    public void classifyPackets(int topN) {
        int packetCount = 0;
        int totalBytes = 0;
        
        try {
            // Reset the handle to start from the beginning
            if (handle != null && handle.isOpen()) {
                handle.close();
            }
            handle = Pcaps.openOffline(pcapFile);
            
            while (true) {
                try {
                    // Read next packet
                    Packet packet = handle.getNextPacketEx();
                    packetCount++;
                    totalBytes += packet.length();
                    
                    // Analyze this packet for classification
                    analyzePacketForStats(packet);
                    
                } catch (EOFException e) {
                    // End of file reached
                    break;
                } catch (TimeoutException e) {
                    // Timeout, continue
                    continue;
                }
            }
            
            // Generate classifications based on collected statistics
            generateClassifications();
            
            // Display classification results
            displayClassification(topN, packetCount, totalBytes);
            
        } catch (Exception e) {
            System.err.println("Error classifying packets: " + e.getMessage());
            e.printStackTrace();
        } finally {
            // Close the handle
            if (handle != null && handle.isOpen()) {
                handle.close();
            }
        }
    }

    // Generate classifications based on collected statistics
    private void generateClassifications() {
        // Clear previous classifications
        PcapReader.ipClassificationMap.clear();
        PcapReader.portClassificationMap.clear();
        
        // Generate IP classifications
        for (Map.Entry<String, IpStats> entry : ipStatsMap.entrySet()) {
            String ip = entry.getKey();
            IpStats stats = entry.getValue();
            
            PcapReader.IpClassification ipClass = new PcapReader.IpClassification();
            ipClass.ipAddress = ip;
            ipClass.sent = stats.sent;
            ipClass.received = stats.received;
            ipClass.totalBytes = stats.totalBytes;
            
            // Determine classification
            if (stats.sent > stats.received * 2) {
                ipClass.classification = "Sender";
            } else if (stats.received > stats.sent * 2) {
                ipClass.classification = "Receiver";
            } else {
                ipClass.classification = "Balanced";
            }
            
            PcapReader.ipClassificationMap.put(ip, ipClass);
        }
        
        // Generate Port classifications
        for (Map.Entry<Integer, PortStats> entry : portStatsMap.entrySet()) {
            int port = entry.getKey();
            PortStats stats = entry.getValue();
            
            PcapReader.PortClassification portClass = new PcapReader.PortClassification();
            portClass.port = port;
            portClass.service = getServiceName(port);
            portClass.packets = stats.packets;
            portClass.bytes = stats.bytes;
            portClass.connections = stats.connections.size();
            
            // Determine classification
            if (stats.packets > 100) {
                portClass.classification = "High usage";
            } else if (stats.packets > 10) {
                portClass.classification = "Moderate usage";
            } else {
                portClass.classification = "Low usage";
            }
            
            PcapReader.portClassificationMap.put(port, portClass);
        }
    }

    private void analyzePacketForStats(Packet packet) {
        int packetSize = packet.length();
        
        // Process IP layer
        if (packet.contains(IpPacket.class)) {
            IpPacket ipPacket = packet.get(IpPacket.class);
            String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
            String dstIp = ipPacket.getHeader().getDstAddr().getHostAddress();
            
            // Get protocol
            String protocol = "Unknown";
            if (packet.contains(TcpPacket.class)) {
                protocol = "TCP";
            } else if (packet.contains(UdpPacket.class)) {
                protocol = "UDP";
            } else if (packet.contains(IcmpV4CommonPacket.class) || packet.contains(IcmpV6CommonPacket.class)) {
                protocol = "ICMP";
            }
            
            // Update protocol stats
            protocolStatsMap.put(protocol, protocolStatsMap.getOrDefault(protocol, 0) + 1);
            
            // Update source IP stats
            IpStats srcStats = ipStatsMap.getOrDefault(srcIp, new IpStats());
            srcStats.sent++;
            srcStats.totalBytes += packetSize;
            ipStatsMap.put(srcIp, srcStats);
            
            // Update destination IP stats
            IpStats dstStats = ipStatsMap.getOrDefault(dstIp, new IpStats());
            dstStats.received++;
            dstStats.totalBytes += packetSize;
            ipStatsMap.put(dstIp, dstStats);
            
            // Process TCP/UDP
            if (packet.contains(TcpPacket.class)) {
                TcpPacket tcpPacket = packet.get(TcpPacket.class);
                int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
                int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
                
                // Update source port stats
                PortStats srcPortStats = portStatsMap.getOrDefault(srcPort, new PortStats());
                srcPortStats.packets++;
                srcPortStats.bytes += packetSize;
                srcPortStats.connections.add(dstIp + ":" + dstPort);
                portStatsMap.put(srcPort, srcPortStats);
                
                // Update destination port stats
                PortStats dstPortStats = portStatsMap.getOrDefault(dstPort, new PortStats());
                dstPortStats.packets++;
                dstPortStats.bytes += packetSize;
                dstPortStats.connections.add(srcIp + ":" + srcPort);
                portStatsMap.put(dstPort, dstPortStats);
                
            } else if (packet.contains(UdpPacket.class)) {
                UdpPacket udpPacket = packet.get(UdpPacket.class);
                int srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
                int dstPort = udpPacket.getHeader().getDstPort().valueAsInt();
                
                // Update source port stats
                PortStats srcPortStats = portStatsMap.getOrDefault(srcPort, new PortStats());
                srcPortStats.packets++;
                srcPortStats.bytes += packetSize;
                srcPortStats.connections.add(dstIp + ":" + dstPort);
                portStatsMap.put(srcPort, srcPortStats);
                
                // Update destination port stats
                PortStats dstPortStats = portStatsMap.getOrDefault(dstPort, new PortStats());
                dstPortStats.packets++;
                dstPortStats.bytes += packetSize;
                dstPortStats.connections.add(srcIp + ":" + srcPort);
                portStatsMap.put(dstPort, dstPortStats);
            }
        }
    }

    private void displayClassification(int topN, int packetCount, int totalBytes) {
        System.out.println("Total packets: " + packetCount + " | Total bytes: " + totalBytes);
        for (int i = 0; i < 70; i++) {
            System.out.print("-");
        }
        System.out.println();

        
        // Display IP statistics
        System.out.println("\n=== TOP IP ADDRESSES BY TRAFFIC ===");
        System.out.printf("%-20s %-10s %-8s %-10s %-12s\n", "IP Address", "Type", "Sent", "Received", "Total Bytes");
        for (int i = 0; i < 70; i++) {
            System.out.print("-");
        }
        System.out.println();
        
        // Sort IPs by total bytes
        List<Map.Entry<String, IpStats>> sortedIps = ipStatsMap.entrySet().stream()
            .sorted((e1, e2) -> Integer.compare(e2.getValue().totalBytes, e1.getValue().totalBytes))
            .limit(topN)
            .collect(Collectors.toList());
        
        for (Map.Entry<String, IpStats> entry : sortedIps) {
            String ip = entry.getKey();
            IpStats stats = entry.getValue();
            String classification = PcapReader.ipClassificationMap.get(ip).classification;
            System.out.printf("%-20s %-10s %-8d %-10d %-12d\n", ip, classification, stats.sent, stats.received, stats.totalBytes);
        }
        
        // Display port statistics
        System.out.println("\n=== TOP PORTS BY TRAFFIC ===");
        System.out.printf("%-8s %-12s %-14s %-10s %-12s %-10s\n", "Port", "Service", "Classification", "Packets", "Bytes", "Connections");
        for (int i = 0; i < 70; i++) {
            System.out.print("-");
        }
        System.out.println();
        
        // Sort ports by bytes
        List<Map.Entry<Integer, PortStats>> sortedPorts = portStatsMap.entrySet().stream()
            .sorted((e1, e2) -> Integer.compare(e2.getValue().bytes, e1.getValue().bytes))
            .limit(topN)
            .collect(Collectors.toList());
        
        for (Map.Entry<Integer, PortStats> entry : sortedPorts) {
            int port = entry.getKey();
            PortStats stats = entry.getValue();
            String service = getServiceName(port);
            String classification = PcapReader.portClassificationMap.get(port).classification;
            
            System.out.printf("%-8d %-12s %-14s %-10d %-12d %-10d\n", 
                port, service, classification, stats.packets, stats.bytes, stats.connections.size());
        }
        
        // Display protocol statistics
        System.out.println("\n=== PROTOCOL STATISTICS ===");
        System.out.printf("%-12s %-8s\n", "Protocol", "Count");
        for (int i = 0; i < 70; i++) {
            System.out.print("-");
        }
        System.out.println();
        
        // Sort protocols by count
        List<Map.Entry<String, Integer>> sortedProtocols = protocolStatsMap.entrySet().stream()
            .sorted((e1, e2) -> Integer.compare(e2.getValue(), e1.getValue()))
            .collect(Collectors.toList());
        
        for (Map.Entry<String, Integer> entry : sortedProtocols) {
            System.out.printf("%-12s %-8d\n", entry.getKey(), entry.getValue());
        }
    }
    
    private String getServiceName(int port) {
        Map<Integer, String> commonPorts = new HashMap<>();
        commonPorts.put(20, "FTP-data");
        commonPorts.put(21, "FTP");
        commonPorts.put(22, "SSH");
        commonPorts.put(23, "Telnet");
        commonPorts.put(25, "SMTP");
        commonPorts.put(53, "DNS");
        commonPorts.put(67, "DHCP");
        commonPorts.put(68, "DHCP");
        commonPorts.put(80, "HTTP");
        commonPorts.put(110, "POP3");
        commonPorts.put(123, "NTP");
        commonPorts.put(143, "IMAP");
        commonPorts.put(161, "SNMP");
        commonPorts.put(443, "HTTPS");
        commonPorts.put(3389, "RDP");
        
        return commonPorts.getOrDefault(port, "Unknown");
    }
}