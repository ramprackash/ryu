import flows
import ids_state_machine
import traffic_monitor
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib import hub
from ryu.ofproto import ether
from ryu.ofproto import inet

class IDSDatapath:

    def __init__(self, datapath, owner):
        print "Datapath init for %s" % str(datapath.id)
        self.datapath = datapath
        self.owner    = owner
        self.flows = flows.Flows(self)
        self.fsm = ids_state_machine.IDSStateMachine(self)
        self.traffic_mon = traffic_monitor.TrafficMonitor(self.fsm, self)
        self.ip_to_port = {}

    def drop_this_rogue_ip(self, src):
        ofp = self.datapath.ofproto
        ofp_parser = self.datapath.ofproto_parser

        cookie = cookie_mask = 0
        table_id = 0
        idle_timeout = hard_timeout = 0
        priority = 32768
        buffer_id = ofp.OFP_NO_BUFFER
        match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=src)

        actions = ""
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        req = ofp_parser.OFPFlowMod(self.datapath, cookie, cookie_mask,
                                    table_id, ofp.OFPFC_ADD,
                                    idle_timeout, hard_timeout,
                                    priority, buffer_id,
                                    ofp.OFPP_ANY, ofp.OFPG_ANY,
                                    ofp.OFPFF_SEND_FLOW_REM,
                                    match, inst)
        self.datapath.send_msg(req)


    def send_ip_flow(self, command, in_port, out_port, proto="any", 
            src_ip="any", src_port="any", dst_ip="any", dst_port="any", 
            drop=False):
        ofp = self.datapath.ofproto
        ofp_parser = self.datapath.ofproto_parser

        cookie = cookie_mask = 0
        table_id = 0
        idle_timeout = hard_timeout = 0
        priority = 32768
        ip_proto = 0
        buffer_id = ofp.OFP_NO_BUFFER
        if proto == "icmp":
            ip_proto = inet.IPPROTO_ICMP
        if proto == "tcp":
            ip_proto = inet.IPPROTO_TCP
        if proto == "udp":
            ip_proto = inet.IPPROTO_UDP

        if (ip_proto != 0):
            match = ofp_parser.OFPMatch(in_port=in_port,eth_type=ether.ETH_TYPE_IP,
                                         ipv4_src=src_ip, ipv4_dst=dst_ip,
                                         ip_proto=ip_proto)
            #if ip_proto == inet.IPPROTO_TCP and src_port != "any":
            if ip_proto == inet.IPPROTO_TCP:
                match = ofp_parser.OFPMatch(in_port=in_port, 
                    eth_type=ether.ETH_TYPE_IP,
                    ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=ip_proto)
                    #tcp_src=int(src_port), tcp_dst=int(dst_port))
            #if ip_proto == inet.IPPROTO_UDP and src_port != "any":
            if ip_proto == inet.IPPROTO_UDP:
                match = ofp_parser.OFPMatch(in_port=in_port, 
                    eth_type=ether.ETH_TYPE_IP,
                    ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=ip_proto)
                    #udp_src=int(src_port), udp_dst=int(dst_port))
        else:
            match = ofp_parser.OFPMatch(in_port=in_port, 
                    eth_type=ether.ETH_TYPE_IP,
                    ipv4_src=src_ip, ipv4_dst=dst_ip)

        #print("Proto = %s (%d)" % (proto, ip_proto))
        #Always mirror to controller
        if drop == False:
            actions = [ofp_parser.OFPActionOutput(out_port),
                    ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER)]
        else:
            actions = ""
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        req = ofp_parser.OFPFlowMod(self.datapath, cookie, cookie_mask,
                                    table_id, command,
                                    idle_timeout, hard_timeout,
                                    priority, buffer_id,
                                    ofp.OFPP_ANY, ofp.OFPG_ANY,
                                    ofp.OFPFF_SEND_FLOW_REM,
                                    match, inst)
        self.datapath.send_msg(req)

