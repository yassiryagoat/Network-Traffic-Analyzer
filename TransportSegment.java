package com.alok.trafficanalyzer;
import java.util.Map;
import java.util.Set;
import java.util.HashMap;
import java.util.HashSet;

    class TransportSegment {
        int sourcePort;
        int destPort;
        long sequenceNumber;
        long ackNumber;
        String flags;
        int windowSize;
        String type; // TCP or UDP

        @Override
        public String toString() {
            return type + " Segment:\n" +
                   "  Source Port: " + sourcePort + getPortService(sourcePort) + "\n" +
                   "  Destination Port: " + destPort + getPortService(destPort) + "\n" +
                   (type.equals("TCP") ?
                   "  Sequence Number: " + sequenceNumber + "\n" +
                   "  Acknowledgment Number: " + ackNumber + "\n" +
                   "  Flags: " + flags + "\n" +
                   "  Window Size: " + windowSize + "\n" : "");
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