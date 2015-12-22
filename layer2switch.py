__author__ = 'denislavrov'
from action.jitrswitch.switch import SwitchLogic, Packet
import binascii


def eth_addr(a):
	b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0], a[1], a[2], a[3], a[4], a[5])
	return b


def byte_eth_addr(astr):
	bts = bytes(astr, "ascii")
	macbytes = binascii.unhexlify(bts.replace(b':', b''))
	return macbytes


class MacTableRule:
	class RuleType:
		SOURCE = 1
		DESTINATION = 2

	def __init__(self, srcport, type, addr, action, port):
		super().__init__()
		self.type = type
		self.port = port
		self.addr = addr
		self.srcport = srcport
		self.action = action


class Layer2Switch(SwitchLogic):

	def process_packet(self, packet):
		dstmac = packet.pktdata[0:6]
		srcmac = packet.pktdata[6:12]

		def check_table(addr, table):
			return addr in table and (
				table[addr].srcport is None or packet.srcport == table[addr].srcport)

		if check_table(dstmac, self.dstmactable):
			if self.debug:
				print("Mactable match: " + eth_addr(dstmac))
			rule = self.dstmactable[dstmac]
			if rule.action == Packet.Action.ALLOW:
				packet.allow(rule.port)
			elif rule.action == Packet.Action.FLOOD:
				packet.flood()
		elif check_table(srcmac, self.srcmactable):
			if self.debug:
				print("Rmactable match: " + eth_addr(srcmac))
			rule = self.srcmactable[srcmac]
			if rule.action == Packet.Action.ALLOW:
				packet.allow(rule.port)
			elif rule.action == Packet.Action.FLOOD:
				packet.flood()

	def addrule(self, rule):
		if rule.type == MacTableRule.RuleType.DESTINATION:
			self.dstmactable[byte_eth_addr(rule.addr)] = rule
		elif rule.type == MacTableRule.RuleType.SOURCE:
			self.srcmactable[byte_eth_addr(rule.addr)] = rule

	def removerule(self, rule):
		if rule.type == MacTableRule.RuleType.DESTINATION:
			return self.dstmactable.pop(byte_eth_addr(rule.addr))
		elif rule.type == MacTableRule.RuleType.SOURCE:
			return self.srcmactable.pop(byte_eth_addr(rule.addr))

	def __init__(self, switch, debug=False, ruletable=[]):
		super().__init__(switch)
		self.dstmactable = {}
		self.srcmactable = {}
		self.debug = debug

		for mactablerule in ruletable:
			self.addrule(mactablerule)
