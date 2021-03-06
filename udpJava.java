package demo;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.List;

public class udpJava
{
	private static Logger logger =
	Logger.getLogger(udpJava.class.getName());
	private Pcap pcap = null;
	private int headerLength = getHeaderLength();
	private int UDP_SOURCE_PORT = 7006;
	private byte[] sourceMacAddress;
	private byte[] destinationMacAddress;
	public udpJava(){
		String macAddress= System.getProperty("gateway_mac_address", "192.168.197.128");
		//dest addr must configured
		destinationMacAddress = hexStringToByteArray(macAddress);
		try {
			pcap = createPcap();
		} catch (IOException e){
			logger.log(Lever.SEVERE, "failed to start pcap library.",e);
		}
	}
	public void sendPacket(URI destination, byte[] packet)
		throws IOException {
		int port = destination.getPort();
		InetAddress address = InetAddress.getByName(destination.getHost());
		byte[] destinationAddress = address.getAddress();
		sendPacket(destinationAddress, port, packet);
	}
	private Pcap createPcap() throws IOException {
		PcapIf device = getPcapDevice();
		if(device == null){
			return null;
		}
		sourceMacAddress = device.getHardwareAddress();
		StringBuilder errorBUffer = new StringBuilder();
		int snapLen = 64 * 1024;
		int flags = Pcap.MODE_NON_PROMISCUOUS;
		int timeout = 10 * 1000;
		Pcap pcap = Pcap.openLive(device.getName(), snapLen, flags,timeout, errorBuffer);
		if(logger.isLoggable(Level.INFO)){
			logger.info(String.format("Pcap start for device %s successfully.",device));
		}
		return pcap;
	}
	private PcapIf getPcapDevice(){
		List<PcapIf>allDevs = new ArrayList<PcapIf>();
		StringBuilder errorBuffer = new StringBuilder();
		int r = Pcap.findAllDevs(allDevs,errorBuffer);
		if (r == Pcap.NOT_OK || allDevs.isEmpty()){
			logger.log(Level.SEVERE, String.format("cant read list of devices, error is %s", errorBuffer.toString()));
			return null;
		}
		String deviceName = 
			System.getProperty("raw_packet_network_interface", "eth0");
		for(PcapIf device : allDevs){
			if (deviceName.equals(device.getName())){
				return device;
			}
		}
		return allDevs.get(0);
	}
	private int getHeaderLength(){
		return 14+20+8; //ethernet header + ipv4 header + udp header
	}
	private void sendPacket(byte[] destinationAddress, int port, byte[] data)
		throws IOException {
		int dataLength = data.length;
		int packetSize = headerLength + dataLength;
		Jpacket packet = new JMemoryPacket(packetsize);
		packet.order(ByteOrder.BIG_ENDIAN);
		packet.setUsShort(12,0x0800);
		packet.scan(JProtocol.ETHERNET_ID);
		Ethernet ethernet = packet.getHeader(new Ethernet());
		ethernet.source(sourceMacAddress);
		ethernet.destination(destinationMacAddress);
		ethernet.checksum(ethernet.calculateChecksum());

		//ipv4 packet
		packet.setUByte(14, 0x40 | 0x05);
		packet.scan(JProtocol.ETHERNET_ID);
		Ip4 ip4 = packet.getHeader(new Ip4());
		ip4.type(Ip4.Ip4Type.UDP);
		ip4.length(packetSize - ehternet.size());
		byte[] sourceAddress = 
			InetAddress.getLocalHost().getAddress();
		ip4.source(sourceAddress);
		ip4.destination(destinationAddress);
		ip4.ttl(32);
		ip4.flags(0);
		ip4.offset(0);
		ip4.checksum(ip4.calculateChecksum());

		//udp packet
		packet.scan(JProtocol.ETHERNET_ID);
		Udp udp = packet.getHeader(new Udp());
		udp.source(UDP_SOURCE_PORT);
		udp.destination(port);
		udp.length(packetSize-ethernet.size() - ip4.size());
		udp.checksum(udp.calculateChecksum());
		packet.setByteArray(headerLength,data);
		packet.scan(Ethernet.ID);
		if(pcap.sendPacket(packet) != Pcap.OK){
			throw new IOException(String.format(
				"Failed to send UDP packet with error : %s",pcap.getErr()));
		}
	}
	private byte[] hexStringToByteArray(String s){
		int len = s.length();
		byte[] data = new byte[len/2];
		for (int i=0; i<len; i+=2){
			data[i/2] = (byte)((Character.digit(s.charAt(i),16)<<4) + Character.digit(s.charAt(i+1),16));
		}
		return data;
	}
	public static void main(String[] args)throws IOException{
		udpJava sender = new udpJava();
		byte[] packet = "Hello".getBytes();
		URI destination = URI.create("udp://192.168.197.128:6006");
		sender.sendPacket(destination, packet);
	}
}

