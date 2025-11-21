package com.alok.trafficanalyzer;
import java.util.Map;
import java.util.Set;
import java.util.HashMap;
import java.util.HashSet;

    // Statistics classes
     class IPStatistics {
        String ip;
        int packetCount = 0;
        int bytesTransferred = 0; // Would need packet size for accurate calculation
        Map<Integer, Integer> portDistribution = new HashMap<>();
        Set<String> communicationPartners = new HashSet<>();

        public IPStatistics(String ip) {
            this.ip = ip;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("IP: ").append(ip).append("\n");
            sb.append("  Total Packets: ").append(packetCount).append("\n");

            if (!portDistribution.isEmpty()) {
                sb.append("  Port Distribution:\n");
                portDistribution.entrySet().stream()
                    .sorted((e1, e2) -> e2.getValue().compareTo(e1.getValue()))
                    .forEach(entry -> sb.append("    Port ").append(entry.getKey())
                                      .append(": ").append(entry.getValue()).append(" packets\n"));
            }

            if (!communicationPartners.isEmpty()) {
                sb.append("  Communication Partners: ").append(String.join(", ", communicationPartners)).append("\n");
            }

            return sb.toString();
        }
    }
