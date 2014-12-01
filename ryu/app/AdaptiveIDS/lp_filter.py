'''
Created on Oct 16, 2014

@author: nav
'''

import random

import simple_snort_rules

#RULES_DIR
RULES_DIR = "ryu/app/AdaptiveIDS/"

#Switches for Sampling and PortScanning
PORT_SCANNING = True
SAMPLING_ENABLE = True

class PortScanDetector:
    def __init__(self):
        self.packet_logs = {}
        self.packet_logs_keys = self.packet_logs.keys()
    
    def port_scan_detected(self, proto, src_ip, dst_ip, dst_port, scan_window=3):
        port_scan_detected = False
        dest_ports = []
        port_scan_probe = str(proto) + str(src_ip) + str(dst_ip) + str(dst_port)
        for i in range(1, scan_window):
            dest_ports.append(str(int(dst_port)-i))
        for dest_port in dest_ports:
            candidate = str(proto) + str(src_ip) + str(dst_ip) + str(dest_port)
            if candidate not in self.packet_logs_keys:
                self.packet_logs[port_scan_probe] = 1
                self.packet_logs_keys = self.packet_logs.keys()
                port_scan_detected = False
            else:
                port_scan_detected = True

        return port_scan_detected
    

class LPFilter:
    def __init__(self, owner):
        self.lp_rules = simple_snort_rules.SnortParser(owner,
                                           rule_file=RULES_DIR + "light_probe.rules")
        self.ps_detector = PortScanDetector()
        self.flows_keeper = {}
        self.flows_keeper_keys = self.flows_keeper.keys()
    
    def __name__(self):
        return 'LPFilter'
    
    def inspect_packets(self, datapath, in_port, out_port, proto="any",
                        src_ip="any", src_port="any", dst_ip="any", 
                        dst_port="any", pps=-1, pkt_data=None):
        if PORT_SCANNING:
            if( dst_port < 10000 and self.ps_detector.port_scan_detected(proto, src_ip, dst_ip, dst_port)):
                print("\n############# PORT SCAN DETECTED ---- srcip" + str(src_ip) + " dst_ip "+ str(dst_ip)+" dst-port " + str(dst_port))
                return ["drop"]

        if SAMPLING_ENABLE:
            #print("Sampling Enabled")
            flow_meta_data = str(datapath.id) + str(in_port) + str(out_port) + str(proto) + str(src_ip) + str(src_port) + str(dst_ip) + str(dst_port)
            flow_sampler = None
            if flow_meta_data in self.flows_keeper_keys:
                flow_sampler = self.flows_keeper[flow_meta_data]
            else:
                flow_sampler = LPSampler()
                self.flows_keeper[flow_meta_data] = flow_sampler
                self.flows_keeper_keys = self.flows_keeper.keys()
            if not flow_sampler.sample():
                return self.lp_rules.impose(datapath, in_port, out_port,
                                    proto=proto, src_ip=src_ip, 
                                    src_port=src_port,
                                    dst_ip=dst_ip, dst_port=dst_port,
                                    pkt_data=pkt_data, pps=pps)
            else:
                #print("Packet sampled-out from inspection " + flow_meta_data)
                return None
	else:
            return self.lp_rules.impose(datapath, in_port, out_port,
                                    proto=proto, src_ip=src_ip, 
                                    src_port=src_port,
                                    dst_ip=dst_ip, dst_port=dst_port,
                                    pkt_data=pkt_data, pps=pps)

class LPSampler:
    def __init__(self):
        self.num_packets = 0
        self.num_sampled = 0

    def reset(self):
        self.num_packets = 0
        self.num_sampled = 0

    def check_reset(self):
        if self.num_packets > 9 and self.num_sampled == 2:
            self.reset()

    def sample(self):
        #print("LPSampler::sample #pkts" + str(self.num_packets) + " #sampled " + str(self.num_sampled))
        self.num_packets = self.num_packets + 1
        if self.num_packets == 10:
            if self.num_sampled == 2:
                self.check_reset()
                return False
        
        if self.num_packets == 9 and self.num_sampled == 0:
            self.num_sampled = self.num_sampled + 1
            self.check_reset()
            return True
        if self.num_packets == 10 and self.num_sampled == 1:
            self.num_sampled = self.num_sampled + 1 
            self.check_reset()
            return True
        if self.num_packets < 9 and self.num_sampled < 2:
            r_int = random.randint(1,2)
            if r_int % 2 == 0:
                self.num_sampled = self.num_sampled + 1
                self.check_reset()
                return True
            else:
                return False
        else:
            return False   
            
