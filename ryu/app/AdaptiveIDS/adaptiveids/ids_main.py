'''
Created on Oct 16, 2014

@author: nav
'''
from operator import attrgetter
from netaddr import *
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
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

import sys
import ids_state_machine
import traffic_monitor
import simple_snort_rules

import time

# For parsing packet_in 
ETHERNET = ethernet.ethernet.__name__
IPV4 = ipv4.ipv4.__name__
ARP = arp.arp.__name__
ICMP = icmp.icmp.__name__
TCP = tcp.tcp.__name__
UDP = udp.udp.__name__

class IDSMain(simple_switch_13.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(IDSMain, self).__init__(*args, **kwargs)
        self.ip_to_port = {}
        self.mac_to_port = {}
        self.datapaths = {}
        self.lp_rules = simple_snort_rules.SnortParser(self, rule_file="./light_probe.rules")
        self.dp_rules = simple_snort_rules.SnortParser(self, rule_file="./deep_probe.rules")
        if (self.lp_rules == "error") or (self.dp_rules == "error"):
            sys.exit(-1)

        self.lp_rules.dumpRules()
            
        self.monitor_thread = hub.spawn(self._monitor)                
        
        self.state_machine = ids_state_machine.IDSStateMachine()
        self.traffic_mon = traffic_monitor.TrafficMonitor(self.state_machine,
                self)
    
    def inspect_traffic(self):
        self.traffic_mon.process_flow_stats()
    
    def start_processing(self):
        while(True):
            self.inspect_traffic()
            time.sleep(10)
    
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
            elif ev.state == DEAD_DISPATCHER:
                if datapath.id in self.datapaths:
                    self.logger.debug('unregister datapath: %016x', datapath.id)
                    del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)
    
    def _request_stats(self, datapath):
        #self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        self.traffic_mon.process_flow_stats(ev)

    def send_ip_flow(self, datapath, in_port, src_ip, dst_ip, out_port, drop=False):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
 
        cookie = cookie_mask = 0
        table_id = 0
        idle_timeout = hard_timeout = 0
        priority = 32768
        buffer_id = ofp.OFP_NO_BUFFER
        match = ofp_parser.OFPMatch(in_port=in_port, eth_type=ether.ETH_TYPE_IP,
                                    ipv4_src=src_ip, ipv4_dst=dst_ip)
        if drop == False:
            actions = [ofp_parser.OFPActionOutput(out_port)]
        else:
            actions = ""
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                    table_id, ofp.OFPFC_ADD,
                                    idle_timeout, hard_timeout,
                                    priority, buffer_id,
                                    ofp.OFPP_ANY, ofp.OFPG_ANY,
                                    ofp.OFPFF_SEND_FLOW_REM,
                                    match, inst)
        datapath.send_msg(req)
    

    # Learn a host's presence based on the received ARP packet and program flow
    # accordingly using L3 fields rather than like the simple_switch.py
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']
        self.mac_to_port.setdefault(dpid, {})
        self.ip_to_port.setdefault(dpid, {})

        pkt = packet.Packet(msg.data)
        #TODO: Check if str(pkt) can be used for content based inspections viz.:
        #where the rules contain options with (content:"0xba 0xad 0xca 0xfe";)
        #print("Pkt IN : %s" % str(pkt))

        header_list = dict((p.protocol_name, p) 
                for p in pkt.protocols if type(p) != str)

        if ARP in header_list:
            src_ip = header_list[ARP].src_ip
            self.ip_to_port[dpid][src_ip] = in_port
            eth = pkt.get_protocols(ethernet.ethernet)[0]
            dst = eth.dst
            src = eth.src
            self.mac_to_port[dpid][src] = in_port
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, 
                                      buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

        elif IPV4 in header_list:
            drop_flag = False
            eth = pkt.get_protocols(ethernet.ethernet)[0]
            dst = eth.dst
            src = eth.src
            proto = "any"
            sport  = "any"
            dport  = "any"
            src_ip = header_list[IPV4].src
            dst_ip = header_list[IPV4].dst
            self.ip_to_port[dpid][src_ip] = in_port
            if TCP in header_list:
                proto="tcp"
                sport = header_list[TCP].src_port
                dport = header_list[TCP].dst_port
            if UDP in header_list:
                proto="udp"
                sport = header_list[UDP].src_port
                dport = header_list[UDP].dst_port
            if ICMP in header_list:
                proto="icmp"
            if dst_ip in self.ip_to_port[dpid]:
                out_port = self.ip_to_port[dpid][dst_ip]
            else:
                out_port = ofproto.OFPP_FLOOD

            result = self.lp_rules.getMatch(src_ip=src_ip, dst_ip=dst_ip)
            print result
            if (result != None):
                if "alert" in result: 
                    print("ALERT : %s" % result[1])
                if "drop" in result:
                    drop_flag = True
                    actions = ""
                else:
                    actions = [parser.OFPActionOutput(out_port)]

            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port= in_port, ipv4_src=src_ip, 
                                        ipv4_dst=dst_ip)
                match.set_dl_type(ether.ETH_TYPE_IP)
                #print "Adding IP flow with matching %s->%s" % (src_ip, dst_ip)
                self.send_ip_flow(datapath, in_port, src_ip, dst_ip, out_port,
                        drop=drop_flag)
            #else:
                #print "Need to flood"


            if drop_flag == False:
                actions = [parser.OFPActionOutput(out_port)]
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath=datapath, 
                                      buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)

            
#if __name__ == "__main__":
#    ids_main = IDSMain()
#    ids_main.start_processing()
            
