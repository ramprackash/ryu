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
from ryu.lib import ofctl_v1_3

import sys
import ids_state_machine
import traffic_monitor
import simple_snort_rules
import datapath

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
	f = open('ryu/app/AdaptiveIDS/alert_output', 'w')
	f.write('')
        #self.set_paths = {}
        #self.flows = flows.Flows(self)
        #self.lp_rules = simple_snort_rules.SnortParser(self, 
        #                                   rule_file="./light_probe.rules")
        #self.dp_rules = simple_snort_rules.SnortParser(self, 
        #                                   rule_file="./deep_probe.rules")
        #if (self.lp_rules == "error") or (self.dp_rules == "error"):
        #    sys.exit(-1)

        self.monitor_thread = hub.spawn(self._monitor)                
        
        #self.fsm = ids_state_machine.IDSStateMachine(self)
        #self.traffic_mon = traffic_monitor.TrafficMonitor(self.fsm,
        #        self)
    
    def inspect_traffic(self):
        self.traffic_mon.process_flow_stats()
    
    def start_processing(self):
        while(True):
            self.inspect_traffic()
            time.sleep(10)
    
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, 
                                                DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not dp.id in self.datapaths:
                self.logger.debug('register datapath: %016x', dp.id)
                self.datapaths[dp.id] = datapath.IDSDatapath(dp)
                self.logger.debug('Removing all flows from dp: %016', dp.id)
                ofctl_v1_3.mod_flow_entry(dp, {}, dp.ofproto.OFPFC_DELETE)
            elif ev.state == DEAD_DISPATCHER:
                if dp.id in self.datapaths:
                    self.logger.debug('unregister datapath: %016x', dp.id)
                    del self.datapaths[dp.id]

    def _monitor(self):
        while True:
            log_file = open("./ryu/app/AdaptiveIDS/tmlogs.txt", "w")
            log_file.close()
            for dp in self.datapaths.values():
                self._request_stats(dp.datapath)
            hub.sleep(10)
    
    def _request_stats(self, datapath):
        #self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        dp = self.datapaths[ev.msg.datapath.id]
        dp.traffic_mon.process_flow_stats(ev)

    

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

        #Ignore LLDP as it is used by the topology discovery module
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether.ETH_TYPE_LLDP:
            return

        #header_list = {}
        #pkt_data = None
        #for p in pkt.protocols:
        #    if type(p) != str:
        #        header_list[p.protocol_name] = p
        #    else :
        #        pkt_data = p
        #        #print pkt_data
    
        header_list = dict((p.protocol_name, p) 
                for p in pkt.protocols if type(p) != str)

        if ARP in header_list:
            src_ip = header_list[ARP].src_ip
            self.ip_to_port[dpid][src_ip] = in_port
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
            result = self.datapaths[datapath.id].fsm.inspect_packets(datapath, in_port, out_port,
                    proto=proto, src_ip=src_ip, src_port=sport, dst_ip=dst_ip,
                    dst_port=dport, pkt_data=pkt)
            sport = "any"
            dport = "any"
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
                    if self.datapaths[datapath.id].flows.getflow(datapath, src_ip, dst_ip, proto, 
                            sport, dport) == None:
                        self.datapaths[datapath.id].send_ip_flow(ofproto.OFPFC_ADD, 
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
                        self.datapaths[datapath.id].flows.addflow(datapath, proto, src_ip, 
                                "any", dst_ip, 
                                "any", out_port=out_port,
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
            
