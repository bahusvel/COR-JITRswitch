__author__ = 'denislavrov'
from action.jitrswitch.switch import SwitchLogic, Packet
import struct
from cpython cimport array

IP_MF = 0x2000  # more fragments (not last frag)
IP_OFFMASK = 0x1fff  # mask for fragment offset

cdef extern from "netinet/in.h":
	short ntohs(short netshort)
	short htons(short hostshort)

cdef struct pshdr:
	unsigned int srcip
	unsigned int dstip
	char rsrv
	char proto
	unsigned short tcp_len

cdef unsigned short checksumcy(array.array msg):
	cdef unsigned int s = 0
	cdef unsigned int w = 0
	cdef unsigned int i = 0
	for i in range(0, len(msg), 2):
		w = msg[i] + (msg[i + 1] << 8)
		s += w
	s = (s >> 16) + (s & 0xffff)
	s += s >> 16
	return ~s & 0xffff

cdef unsigned short tcp_checksumcy(packet):
	cdef array.array pktdata = array.array("B", packet.pktdata)
	cdef unsigned char* data = pktdata.data.as_uchars
	cdef unsigned int* source_address = <unsigned int*> (data + 14 + 12)
	cdef unsigned int ihl = (<int>(data[14] & 0xf)) * 4
	cdef unsigned short tcp_length = ntohs((<unsigned short *> (data + 14 + 2))[0]) - ihl
	tcp = <unsigned char*>(data + 14 + ihl)
	tcp[16] = 0
	tcp[17] = 0
	cdef pshdr phdr
	phdr.srcip = source_address[0]
	phdr.dstip = source_address[1]
	phdr.rsrv = 0
	phdr.proto = 0x06
	phdr.tcp_len = htons(tcp_length)
	cdef array.array tmp = array.array("B", [])
	array.extend_buffer(tmp, <char *>&phdr, sizeof(phdr))
	array.extend_buffer(tmp, <char *>tcp, tcp_length)
	sum = checksumcy(tmp)
	data[14 + ihl + 16] = sum & 0xff
	data[14 + ihl + 17] = sum >> 8
	packet.pktdata = bytes(pktdata)
	return sum


class TCPChecksum(SwitchLogic):
	def process_packet(self, packet):
		if packet.srcport in self.interfaces and packet.pktdata[14 + 9] == 0x06:  # check if TCP
			off = struct.unpack(">H", packet.pktdata[14 + 6: 14 + 8])[0]
			if (off & (IP_MF | IP_OFFMASK)) == 0:
				tcp_checksumcy(packet)

	def __init__(self, switch, interfaces):
		super().__init__(switch)
		self.interfaces = interfaces
