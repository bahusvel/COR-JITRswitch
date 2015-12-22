__author__ = 'denislavrov'
from action.jitrswitch.switch import Switch, Packet
from action.jitrswitch.layer3switch import Layer3Switch, IPTableRule
import os
try:
	os.remove("cychecksum.cpython-34m.so")
	os.remove("cychecksum.c")
except FileNotFoundError:
	pass
os.chdir("../../")
os.system("python3 setup.py build_ext --inplace")

from action.jitrswitch.cychecksum import TCPChecksum




switch = Switch(["br0", "veth0"])
layer3 = Layer3Switch(switch, [IPTableRule("br0", IPTableRule.RuleType.SOURCE, "192.168.2.55", Packet.Action.ALLOW, "veth0")])

TCPChecksum(switch, ["br0"])
