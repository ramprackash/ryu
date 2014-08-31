# A simplified HUB with a simplified l2 firewall.
# Write firewall rules as a CSV file (/opt/firewall.csv) where the format is
# <src-mac> <dst-mac> <permit/deny>
# Note that even though it is named csv, the separator is a whitespace and not a
# comma. Example entry for /opt/firewall.csv
# 00:00:00:00:00:01 00:00:00:00:00:03 deny
# 00:00:00:00:00:01 00:00:00:00:00:02 permit
# 00:00:00:00:00:03 00:00:00:00:00:01 deny


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

import csv 

class SimpleFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    my_firewall_file = ""
    def __init__(self, *args, **kwargs):
        self.my_firewall_file = "/opt/firewall.csv"
        super(SimpleFirewall, self).__init__(*args, **kwargs)
        print(">>> Done initializing <<<")


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        in_port = msg.match['in_port']
        dp  = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src
        match_action = "nomatch"
        with open('/opt/firewall.csv', 'r') as csvfile:
            fw_reader = csv.reader(csvfile, delimiter=' ')
            for row in fw_reader:
                fw_src = row[0]
                fw_dst = row[1]
                fw_act = row[2]
                if (fw_src == src and fw_dst == dst):
                    match_action = fw_act
                    break

        if (match_action == "nomatch"):
            match_action = "permit"

        print ("%s -> %s (%s)")%(src, dst, match_action)
        match = ofp_parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
        if (match_action == "permit"):
            actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        else:
            actions = ""

        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
            actions)]
        mod = ofp_parser.OFPFlowMod(datapath=dp, priority=0, match=match,
                instructions=inst)
        dp.send_msg(mod)
