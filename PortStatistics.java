package com.alok.trafficanalyzer;
import java.util.Map;
import java.util.Set;
import java.util.HashMap;
import java.util.HashSet;

     class PortStatistics {
        int port;
        int packetCount = 0;
        Set<String> associatedIPs = new HashSet<>();

        public PortStatistics(int port) {
            this.port = port;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("Port: ").append(port).append(getPortService(port)).append("\n");
            sb.append("  Total Packets: ").append(packetCount).append("\n");

            if (!associatedIPs.isEmpty()) {
                sb.append("  Associated IPs: ").append(String.join(", ", associatedIPs)).append("\n");
            }

            return sb.toString();
        }

        private String getPortService(int port) {
            switch (port) {
                case 80: return " (HTTP)";
                case 443: return " (HTTPS)";
                case 22: return " (SSH)";
                case 21: return " (FTP)";
                case 23: return " (Telnet)";
                case 25: return " (SMTP)";
                case 53: return " (DNS)";
                default: return "";
            }
        }
    }
