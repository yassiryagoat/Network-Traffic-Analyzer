
package com.alok.trafficanalyzer;
import java.util.*;
import java.util.regex.*;
import java.io.*;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.Packet;

import com.alok.trafficanalyzer.*;




public class PacketClassifier {


        String timestamp;
        String packetNumber;
        EthernetFrame ethernetFrame;
        IPPacket ipPacket;
        TransportSegment transportSegment;

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("Packet #").append(packetNumber).append(" [").append(timestamp).append("]\n");

            if (ethernetFrame != null) sb.append(ethernetFrame.toString());
            if (ipPacket != null) sb.append(ipPacket.toString());
            if (transportSegment != null) sb.append(transportSegment.toString());

            return sb.toString();
        }



    // Main data structures for classification
    private List<AnalyzedPacket> packets = new ArrayList<>();

    private Map<String, IPStatistics> ipStats = new HashMap<>();
    private Map<Integer, PortStatistics> portStats = new HashMap<>();

    // Parse input packet data
    public void parsePacketData(String inputData) {
    // Split the input into packet blocks
    String[] packetBlocks = inputData.split("(?=Packet #)");

    for (String block : packetBlocks) {
        if (block.trim().isEmpty()) continue;

        AnalyzedPacket packet = new AnalyzedPacket();

        // Packet number and timestamp
        Matcher packetMatcher = Pattern.compile("Packet #(\\d+) \\[(.*?)\\]").matcher(block);
        if (packetMatcher.find()) {
            packet.packetNumber = packetMatcher.group(1);
            packet.timestamp = packetMatcher.group(2);
        }

        // Ethernet frame
        Matcher ethernetMatcher = Pattern.compile(
            "Ethernet Frame:\\s*\\n\\s*Source MAC: (.*?)\\n\\s*Destination MAC: (.*?)\\n\\s*Type: (.*?)\\n"
        ).matcher(block);
        if (ethernetMatcher.find()) {
            EthernetFrame frame = new EthernetFrame();
            frame.sourceMAC = ethernetMatcher.group(1).trim();
            frame.destMAC = ethernetMatcher.group(2).trim();
            frame.type = ethernetMatcher.group(3).trim();
            packet.ethernetFrame = frame;
        }

        // IPv4 packet
        Matcher ipMatcher = Pattern.compile(
            "IPv4 Packet:\\s*\\n\\s*Version: (\\d+) .*?\\n\\s*Source IP: ([\\d.]+)\\n\\s*Destination IP: ([\\d.]+)\\n\\s*Protocol: (\\d+) \\(.*?\\)\\n\\s*TTL: (-?\\d+)",
            Pattern.DOTALL
        ).matcher(block);
        if (ipMatcher.find()) {
            IPPacket ipPacket = new IPPacket();
            ipPacket.version = Integer.parseInt(ipMatcher.group(1));
            ipPacket.sourceIP = ipMatcher.group(2);
            ipPacket.destIP = ipMatcher.group(3);
            ipPacket.protocol = Integer.parseInt(ipMatcher.group(4));
            ipPacket.ttl = Integer.parseInt(ipMatcher.group(5));
            packet.ipPacket = ipPacket;
        }

        // TCP Segment
        Matcher tcpMatcher = Pattern.compile(
            "TCP Segment:\\s*\\n\\s*Source Port: (\\d+)\\n\\s*Destination Port: (\\d+)\\n\\s*Sequence Number: (-?\\d+)\\n\\s*Acknowledgment Number: (-?\\d+)\\n\\s*Flags: ([\\w\\s]+)\\n\\s*Window Size: (\\d+)"
        ).matcher(block);
        if (tcpMatcher.find()) {
            TransportSegment segment = new TransportSegment();
            segment.type = "TCP";
            segment.sourcePort = Integer.parseInt(tcpMatcher.group(1));
            segment.destPort = Integer.parseInt(tcpMatcher.group(2));
            segment.sequenceNumber = Long.parseLong(tcpMatcher.group(3));
            segment.ackNumber = Long.parseLong(tcpMatcher.group(4));
            segment.flags = tcpMatcher.group(5).trim();
            segment.windowSize = Integer.parseInt(tcpMatcher.group(6));
            packet.transportSegment = segment;
        }

        // UDP Segment (optional fallback)
        Matcher udpMatcher = Pattern.compile(
            "UDP Segment:\\s*\\n\\s*Source Port: (\\d+)\\n\\s*Destination Port: (\\d+)"
        ).matcher(block);
        if (udpMatcher.find()) {
            TransportSegment segment = new TransportSegment();
            segment.type = "UDP";
            segment.sourcePort = Integer.parseInt(udpMatcher.group(1));
            segment.destPort = Integer.parseInt(udpMatcher.group(2));
            packet.transportSegment = segment;
        }

        packets.add(packet);
    }

    // Final classification after parsing
    classifyPackets();
}


    // Classify packets by IP and port
    private void classifyPackets() {
        for (AnalyzedPacket packet : packets) {
            if (packet.ipPacket != null) {
                // Process source IP
                String sourceIP = packet.ipPacket.sourceIP;
                IPStatistics sourceStats = ipStats.computeIfAbsent(sourceIP, IPStatistics::new);
                sourceStats.packetCount++;
                sourceStats.communicationPartners.add(packet.ipPacket.destIP);

                // Process destination IP
                String destIP = packet.ipPacket.destIP;
                IPStatistics destStats = ipStats.computeIfAbsent(destIP, IPStatistics::new);
                destStats.packetCount++;
                destStats.communicationPartners.add(sourceIP);

                if (packet.transportSegment != null) {
                    // Process source port
                    int sourcePort = packet.transportSegment.sourcePort;
                    sourceStats.portDistribution.put(sourcePort,
                        sourceStats.portDistribution.getOrDefault(sourcePort, 0) + 1);

                    PortStatistics sourcePortStats = portStats.computeIfAbsent(sourcePort, PortStatistics::new);
                    sourcePortStats.packetCount++;
                    sourcePortStats.associatedIPs.add(sourceIP);

                    // Process destination port
                    int destPort = packet.transportSegment.destPort;
                    destStats.portDistribution.put(destPort,
                        destStats.portDistribution.getOrDefault(destPort, 0) + 1);

                    PortStatistics destPortStats = portStats.computeIfAbsent(destPort, PortStatistics::new);
                    destPortStats.packetCount++;
                    destPortStats.associatedIPs.add(destIP);
                }
            }
        }
    }

    public void printIPStatistics() {
        System.out.println("\n=== IP Address Statistics ===");
        // Sort by packet count (highest first)
        ipStats.values().stream()
            .sorted((ip1, ip2) -> Integer.compare(ip2.packetCount, ip1.packetCount))
            .forEach(System.out::println);
    }

    public void printPortStatistics() {
        System.out.println("\n=== Port Statistics ===");
        // Sort by packet count (highest first)
        portStats.values().stream()
            .sorted((p1, p2) -> Integer.compare(p2.packetCount, p1.packetCount))
            .forEach(System.out::println);
    }

    public void printPacketsByIP(String ip) {
        System.out.println("\n=== Packets involving IP: " + ip + " ===");
        int count = 0;
        for (AnalyzedPacket packet : packets) {
            if (packet.ipPacket != null &&
                (packet.ipPacket.sourceIP.equals(ip) || packet.ipPacket.destIP.equals(ip))) {
                System.out.println(packet);
                count++;
            }
            
        }
        System.out.println("Total packets: " + count);
    }

    public void printPacketsByPort(int port) {
        System.out.println("\n=== Packets involving Port: " + port + " ===");
        int count = 0;
        for (AnalyzedPacket packet : packets) {
            if (packet.transportSegment != null &&
                (packet.transportSegment.sourcePort == port || packet.transportSegment.destPort == port)) {
                System.out.println(packet);
                count++;
            }
        }
        System.out.println("Total packets: " + count);
    }

    // Main method with example usage
    public static void main(String[] args) {
        // Example packet data - you would replace this with your actual packet data
        String packetData =
            "Packet #100 [2025-05-13 14:39:54.231]\n" +
            "Ethernet Frame:\n" +
            "  Source MAC: 3c:93:f4:f2:a2:13\n" +
            "  Destination MAC: f8:a2:d6:34:b4:91\n" +
            "  Type: 0x800\n" +
            "IPv4 Packet:\n" +
            "  Version: 4 (IPv4)\n" +
            "  Source IP: 173.194.16.233\n" +
            "  Destination IP: 192.168.100.91\n" +
            "  Protocol: 6 (TCP)\n" +
            "  TTL: 121\n" +
            "TCP Segment:\n" +
            "  Source Port: 443\n" +
            "  Destination Port: 53612\n" +
            "  Sequence Number: -1843830570\n" +
            "  Acknowledgment Number: 1616922772\n" +
            "  Flags: ACK PSH\n" +
            "  Window Size: 1029\n" +
            "\n" +
            "Packet #101 [2025-05-13 14:39:54.245]\n" +
            "Ethernet Frame:\n" +
            "  Source MAC: f8:a2:d6:34:b4:91\n" +
            "  Destination MAC: 3c:93:f4:f2:a2:13\n" +
            "  Type: 0x800\n" +
            "IPv4 Packet:\n" +
            "  Version: 4 (IPv4)\n" +
            "  Source IP: 192.168.100.91\n" +
            "  Destination IP: 173.194.16.233\n" +
            "  Protocol: 6 (TCP)\n" +
            "  TTL: 64\n" +
            "TCP Segment:\n" +
            "  Source Port: 53612\n" +
            "  Destination Port: 443\n" +
            "  Sequence Number: 1616922772\n" +
            "  Acknowledgment Number: -1843830570\n" +
            "  Flags: ACK\n" +
            "  Window Size: 4096\n" +
            "\n" +
            "Packet #102 [2025-05-13 14:39:54.301]\n" +
            "Ethernet Frame:\n" +
            "  Source MAC: 3c:93:f4:f2:a2:13\n" +
            "  Destination MAC: ff:ff:ff:ff:ff:ff\n" +
            "  Type: 0x806\n" +
            "IPv4 Packet:\n" +
            "  Version: 4 (IPv4)\n" +
            "  Source IP: 192.168.100.1\n" +
            "  Destination IP: 192.168.100.255\n" +
            "  Protocol: 17 (UDP)\n" +
            "  TTL: 64\n" +
            "UDP Segment:\n" +
            "  Source Port: 53\n" +
            "  Destination Port: 5353\n";

        PacketClassifier classifier = new PacketClassifier();
        /*cpmment this */
        //classifier.parsePacketData(packetData);
        /*replace it with this */
        
        String[] args1 = {"captured_packets.pcap", "10","--ip-stats", "--top", "3"};
        PcapReader.main(args1);

        
       // System.out.println("----------------------------------------------HELLO------------------------------");
       // String data = PacketCapture.data;
       // System.out.println(data);
        //classifier.parsePacketData(data);
        // Print statistics
        //classifier.printIPStatistics();
        //classifier.printPortStatistics();
        
        
//--------------------------
/*what i comment */
/*
        // Print packets for a specific IP
        classifier.printPacketsByIP("192.168.100.91");

        // Print packets for a specific port
        classifier.printPacketsByPort(443);
*/
        /* */
/* what i replace it with */ 
/*
Scanner scanner = new Scanner(System.in);

System.out.print("Enter IP to filter (or press Enter to skip): ");
String ip = scanner.nextLine().trim();

System.out.print("Enter Port to filter (or press Enter to skip): ");
String portInput = scanner.nextLine().trim();
Integer port = portInput.isEmpty() ? null : Integer.parseInt(portInput);

// Filter and print
classifier.printPacketsByIP(ip);
classifier.printPacketsByPort(port);


scanner.close();



/* */

//----------------------------------------------
}

    // For real-world usage, we would want to read from a file or capture interface
    public void processPacketFile(String filePath) throws IOException {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        }
        parsePacketData(content.toString());
    }

    // Advanced classification methods could be added here
    public void identifyConversations() {
        // Group packets by source/dest IP pairs and protocols
        // Identify related packet sequences and conversations
    }


    public void detectAnomalies() {
        // Look for unusual patterns, port scans, etc.
    }

    public void generateTimelineReport() {
        // Create a timeline of packet activity
    }
}
    