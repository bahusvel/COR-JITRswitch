__author__ = 'denislavrov'
import socket
import os
import select
import threading


def setifpromisc(ifname, to=True):
	if to:
		return os.system("ip link set " + ifname + " promisc on") == 0
	else:
		return os.system("ip link set " + ifname + " promisc off") == 0


class SwitchLogic:
	def __init__(self, switch, autoadd=True):
		super().__init__()
		self.switch = switch
		self.position = -1
		if autoadd:
			self.switch.addlogic(self)

	def inject_start(self, packet):
		self.inject(packet, 0)

	def inject_end(self, packet):
		self.inject(packet, len(self.switch.switchlogics))

	def inject_after(self, packet):
		self.inject(packet, self.position + 1)

	def inject_before(self, packet):
		self.inject(packet, self.position - 1)

	def inject(self, packet, to):
		self.switch.deliverpacket(packet, inject=to)

	def process_packet(self, packet):
		return packet


class Packet:
	NETHDR_OFFSET = 14

	class Action:
		ALLOW = 1
		DROP = 2
		FLOOD = 3
		NONE = 4

	def allow(self, port):
		self.action = Packet.Action.ALLOW
		if port is not None:
			self.dstport = port

	def drop(self):
		self.action = Packet.Action.DROP

	def flood(self):
		self.action = Packet.Action.FLOOD

	def net_header_offset(self):
		# check for packets with 802.1Q (VLAN TAG)
		return self.NETHDR_OFFSET

	def __init__(self, pktdata, srcport):
		super().__init__()
		self.srcport = srcport
		self.pktdata = pktdata
		self.dstport = None
		self.action = Packet.Action.NONE


class Switch:

	def run(self):
		try:
			while True:
				events = self.e.poll()
				for fd, event_type in events:
					rsocket = self.fd2sock[fd]
					pktdata = rsocket.recv(self.mtu)
					packet = Packet(pktdata, self.sock2if[rsocket])
					self.deliverpacket(packet)

		except KeyboardInterrupt:
			for sock in self.sockets:
				sock.close()

	def deliverpacket(self, packet, inject=0):
		try:
			for switchlogic in self.switchlogics[inject:]:
				switchlogic.process_packet(packet)
				if packet.action == Packet.Action.DROP:
					break
			if packet.action == Packet.Action.ALLOW and packet.dstport is not None:
				self.if2sock[packet.dstport].send(packet.pktdata)
			elif packet.action == Packet.Action.FLOOD:
				srcsock = self.if2sock[packet.srcport]
				# Send packet to every interface except for source
				for sock in self.sockets:
					if sock is not srcsock:
						sock.send(packet.pktdata)
		except Exception as e:
			print(e)

	def addlogic(self, switchlogic):
		self.switchlogics.append(switchlogic)
		switchlogic.position = len(self.switchlogics) - 1

	def addport(self, iface):
			if setifpromisc(iface):
				sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x3))
				sock.bind((iface, 0))
				sock.setblocking(0)
				self.if2sock[iface] = sock
				self.sock2if[sock] = iface
				self.sockets.append(sock)
				self.e.register(sock.fileno(), select.EPOLLIN)
				self.fd2sock[sock.fileno()] = sock
				return sock

	def __init__(self, ports, mtu=2000):
		super().__init__()
		self.thread = threading.Thread(target=self.run)
		self.mtu = mtu
		self.fd2sock = {}
		self.if2sock = {}
		self.sock2if = {}
		self.sockets = []
		self.switchlogics = []
		self.e = select.epoll()
		for port in ports:
			self.addport(port)
		self.thread.start()

