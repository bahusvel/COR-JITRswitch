__author__ = 'denislavrov'

from action.jitrswitch.switch import SwitchLogic, Packet
import socket
import enum


def ip_addr(a):
	return socket.inet_ntoa(a)


def byte_ip_addr(astr):
	return socket.inet_aton(astr)


class IPTableRule:
	class RuleType(enum.Enum):
		SOURCE = 1
		DESTINATION = 2

	def __init__(self, srcport, type, addr, action, port):
		super().__init__()
		self.type = type
		self.port = port
		self.addr = addr
		self.srcport = srcport
		self.action = action


class Layer3Switch(SwitchLogic):

	def process_packet(self, packet):
		dstip = packet.pktdata[14+16:14+20]  # 14 is offset into layer3 header
		srcip = packet.pktdata[14+12:14+16]

		def check_table(addr, table):
			return addr in table and (
				table[addr].srcport is None or packet.srcport == table[addr].srcport)

		if check_table(dstip, self.dstiptable):
			if self.debug:
				print("Iptable match,  DESTINATION: %s, SOURCE: %s" % (ip_addr(dstip), ip_addr(srcip)))
			rule = self.dstiptable[dstip]
			if rule.action == Packet.Action.ALLOW:
				packet.allow(rule.port)
			elif rule.action == Packet.Action.FLOOD:
				packet.flood()
		elif check_table(srcip, self.srciptable):
			if self.debug:
				print("Reverse Iptable match, SOURCE: %s, DESTINATION: %s" % (ip_addr(srcip), ip_addr(dstip)))
			rule = self.srciptable[srcip]
			if rule.action == Packet.Action.ALLOW:
				packet.allow(rule.port)
			elif rule.action == Packet.Action.FLOOD:
				packet.flood()

	def addrule(self, rule):
		if rule.type == IPTableRule.RuleType.DESTINATION:
			self.dstiptable[byte_ip_addr(rule.addr)] = rule
		elif rule.type == IPTableRule.RuleType.SOURCE:
			self.srciptable[byte_ip_addr(rule.addr)] = rule

	def removerule(self, rule):
		if rule.type == IPTableRule.RuleType.DESTINATION:
			return self.dstiptable.pop(byte_ip_addr(rule.addr))
		elif rule.type == IPTableRule.RuleType.SOURCE:
			return self.srciptable.pop(byte_ip_addr(rule.addr))

	def __init__(self, switch, debug=False, ruletable=[]):
		super().__init__(switch)
		self.dstiptable = {}
		self.srciptable = {}
		self.debug = debug

		for iptablerule in ruletable:
			self.addrule(iptablerule)


