package com.alok.trafficanalyzer;
import java.util.Map;
import java.util.Set;
import java.util.HashMap;
import java.util.HashSet;

 class IPPacket {
        int version;
        String sourceIP;
        String destIP;
        int protocol;
        int ttl;

        @Override
        public String toString() {
            return "IPv" + version + " Packet:\n" +
                   "  Version: " + version + (version == 4 ? " (IPv4)" : " (IPv6)") + "\n" +
                   "  Source IP: " + sourceIP + "\n" +
                   "  Destination IP: " + destIP + "\n" +
                   "  Protocol: " + protocol + getProtocolName(protocol) + "\n" +
                   "  TTL: " + ttl + "\n";
        }

        private String getProtocolName(int protocol) {
            switch (protocol) {
                case 6: return " (TCP)";
                case 17: return " (UDP)";
                case 1: return " (ICMP)";
                default: return "";
            }
        }
    }