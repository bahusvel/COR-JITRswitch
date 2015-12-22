__author__ = 'denislavrov'
from action.jitrswitch.switch import SwitchLogic, Packet
import socket
import struct

IP_MF = 0x2000  # more fragments (not last frag)
IP_OFFMASK = 0x1fff  # mask for fragment offset


def checksum(msg):
	s = 0
	for i in range(0, len(msg), 2):
		w = msg[i] + (msg[i + 1] << 8)
		s += w
	s = (s >> 16) + (s & 0xffff)
	s += s >> 16
	return ~s & 0xffff


def tcp_checksum(packet):
	data = bytearray(packet.pktdata)
	dest_address = packet.pktdata[14 + 16: 14 + 20]
	source_address = packet.pktdata[14 + 12: 14 + 16]
	ihl = (packet.pktdata[14] & 0xf) * 4
	tcp_length = struct.unpack(">H", packet.pktdata[14 + 2: 14 + 4])[0] - ihl
	protocol = socket.IPPROTO_TCP
	tcp = data[14 + ihl: 14 + ihl + tcp_length]
	tcp[16] = 0
	tcp[17] = 0
	s = struct.pack('>4s4sxBH', source_address, dest_address, protocol, tcp_length)
	sum = checksum(s + bytes(tcp))
	data[14 + ihl + 16] = sum & 0xff
	data[14 + ihl + 17] = sum >> 8
	packet.pktdata = bytes(data)
	return sum


class TCPChecksum(SwitchLogic):
	def process_packet(self, packet):
		if packet.srcport in self.interfaces and packet.pktdata[14 + 9] == 0x06:  # check if TCP
			off = struct.unpack(">H", packet.pktdata[14 + 6: 14 + 8])[0]
			if (off & (IP_MF | IP_OFFMASK)) == 0:
				tcp_checksum(packet)

	def __init__(self, switch, interfaces):
		super().__init__(switch)
		self.interfaces = interfaces
