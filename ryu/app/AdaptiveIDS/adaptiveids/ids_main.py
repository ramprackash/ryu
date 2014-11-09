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
from ryu.ofproto import inet

import sys
import ids_state_machine
import traffic_monitor
import simple_snort_rules

import time

import flows

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
        self.set_paths = {}
        self.flows = flows.Flows(self)
        self.lp_rules = simple_snort_rules.SnortParser(self, 
                                           rule_file="./light_probe.rules")
        self.dp_rules = simple_snort_rules.SnortParser(self, 
                                           rule_file="./deep_probe.rules")
        if (self.lp_rules == "error") or (self.dp_rules == "error"):
            sys.exit(-1)

        self.monitor_thread = hub.spawn(self._monitor)                
        
        self.state_machine = ids_state_machine.IDSStateMachine(self)
        self.traffic_mon = traffic_monitor.TrafficMonitor(self.state_machine,
                self)
    
    def inspect_traffic(self):
        self.traffic_mon.process_flow_stats()
    
    def start_processing(self):
        while(True):
            self.inspect_traffic()
            time.sleep(10)
    
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, 
                                                DEAD_DISPATCHER])
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

    def send_ip_flow(self, datapath, command, in_port, out_port, proto="any", 
            src_ip="any", src_port="any", dst_ip="any", dst_port="any", 
            drop=False):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
 
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
            match = ofp_parser.OFPMatch(in_port=in_port, 
                    eth_type=ether.ETH_TYPE_IP,
                    ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=ip_proto)
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
        req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                    table_id, command,
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
        flow_exists = 0

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

            # Check if this packet hits any light probe rule and take
            # necessary action
            #print ("%d : %d : %s : %s : %s : %s : %s" % (in_port, out_port,
            #    proto, src_ip, sport, dst_ip, dport))
            result = self.lp_rules.impose(datapath, in_port, out_port,
                    proto=proto, src_ip=src_ip, src_port=sport, dst_ip=dst_ip,
                    dst_port=dport, pkt_data=pkt)
            if (result != None):
                if "drop" in result:
                    drop_flag = True
                    actions = ""
                else:
                    actions = [parser.OFPActionOutput(out_port)]

            if drop_flag == False:
                actions = [parser.OFPActionOutput(out_port)]

                if (out_port != ofproto.OFPP_FLOOD):
                    reinstate_flag = False
                    #key = str(dpid)+str(src_ip)+str(dst_ip)+str(out_port)
                    #if key not in self.set_paths.keys():
                    #    self.send_ip_flow(datapath, in_port, out_port,
                    #        proto=proto, 
                    #        src_ip=src_ip,
                    #        src_port=sport,
                    #        dst_ip=dst_ip, 
                    #        dst_port=dport,
                    #        drop=drop_flag)
                    #    self.set_paths[str(dpid)+str(src_ip)+str(dst_ip)+str(out_port)] = 1
                    if self.flows.getflow(datapath, src_ip, dst_ip, proto, 
                            sport, dport) == None:
                        self.send_ip_flow(datapath, ofproto.OFPFC_ADD, 
                            in_port, out_port,
                            proto=proto, 
                            src_ip=src_ip,
                            src_port=sport,
                            dst_ip=dst_ip, 
                            dst_port=dport,
                            drop=drop_flag)
                        if result != None:
                            matches_rule = True
                            if "reinstate" in result:
                                reinstate_flag = True
                        else:
                            matches_rule = False
                        self.flows.addflow(datapath, proto, src_ip, 
                                sport, dst_ip, 
                                dport, out_port=out_port,
                                matches_rule=matches_rule,
                                reinstate=reinstate_flag)
                    else:
                        flow_exists = 1

                #Now deal with the incoming packet if there is no flow
                if flow_exists == 0:
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
            
