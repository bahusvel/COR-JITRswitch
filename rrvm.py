__author__ = 'denis'
from .switch import Switch, Packet
from .layer2switch import Layer2Switch, MacTableRule

switch = Switch(["eth0", "vif2.0"])
logic = Layer2Switch(switch,
                     [MacTableRule(None, MacTableRule.RuleType.DESTINATION, "ff:ff:ff:ff:ff:ff", Packet.Action.FLOOD, None),
                      MacTableRule("eth0", MacTableRule.RuleType.DESTINATION, "VMMAC", Packet.Action.ALLOW, "vif2.0"),
                      MacTableRule("vif2.0", MacTableRule.RuleType.SOURCE, "VMMAC", Packet.Action.ALLOW, "eth0")]
                     )
