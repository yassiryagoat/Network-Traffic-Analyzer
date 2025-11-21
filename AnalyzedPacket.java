package com.alok.trafficanalyzer;

public class AnalyzedPacket {
    public String timestamp;
    public String packetNumber;
    public EthernetFrame ethernetFrame;
    public IPPacket ipPacket;
    public TransportSegment transportSegment;

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Packet #").append(packetNumber).append(" [").append(timestamp).append("]\n");

        if (ethernetFrame != null) sb.append(ethernetFrame.toString());
        if (ipPacket != null) sb.append(ipPacket.toString());
        if (transportSegment != null) sb.append(transportSegment.toString());

        return sb.toString();
    }
}
