package com.alok.trafficanalyzer;
import java.util.Map;
import java.util.Set;
import java.util.HashMap;
import java.util.HashSet;

 class EthernetFrame {
        String sourceMAC;
        String destMAC;
        String type;

        @Override
        public String toString() {
            return "Ethernet Frame:\n" +
                   "  Source MAC: " + sourceMAC + "\n" +
                   "  Destination MAC: " + destMAC + "\n" +
                   "  Type: " + type + "\n";
        }
    }