'''
Created on Oct 16, 2014

@author: nav
'''

import random
import datetime

import simple_snort_rules
import traffic_monitor
import ids_main

#RULES_DIR
RULES_DIR = "ryu/app/AdaptiveIDS/"

#Switches for Sampling and PortScanning
PORT_SCANNING = True
SAMPLING_ENABLE = True

class PortScanDetector:
    def __init__(self, scan_window=3):
        self.packet_logs = {}
        self.packet_logs_keys = self.packet_logs.keys()
        self.scan_window = scan_window
        #print('PortScanDetector created with scan window: '+str(self.scan_window))
    
    """ Returns TRUE if a portscan from this src_ip is detected. False
    otherwise
    """
    def port_scan_detected(self, proto, src_ip, dst_ip, dst_port):
        port_scan_detected = False
        dest_ports = []
        port_scan_probe = str(proto) + str(src_ip) + str(dst_ip) + str(dst_port)
        for i in range(1, self.scan_window):
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
    def __init__(self, owner, rules='./ryu/app/AdaptiveIDS/light_probe.rules'):
        self.owner = owner
        self.lp_rules = simple_snort_rules.SnortParser(owner, rule_file=rules)
        self.ps_detector = PortScanDetector(scan_window=ids_main.IDSCfgParams.PORT_SCAN_WINDOW)
        self.flows_keeper = {}
        self.flows_keeper_keys = self.flows_keeper.keys()
        #print('lp Filter rules: ' + rules)
    
    def __name__(self):
        return 'LPFilter'

    def get_ids_main_obj(self):
        # self.owner = fsm
        # fsm.owner  = datapath
        # datapath.owner = ids_main
        return self.owner.owner
    
    """ Subject packet to the portscanner and also the light probe rules if 
    port scanner did not detect anything malicious
    """
    def inspect_packets(self, datapath, in_port, out_port, proto="any",
                        src_ip="any", src_port="any", dst_ip="any", 
                        dst_port="any", pps=-1, pkt_data=None):
        if PORT_SCANNING:
            if( dst_port < 10000 and self.ps_detector.port_scan_detected(proto,
                    src_ip, dst_ip, dst_port)):
                main_obj = self.get_ids_main_obj()
                main_obj.rogue_detected(src_ip)
                print(traffic_monitor.bcolors.FAIL+'[ '+datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+' ]' +" Port scan detected from  SRC IP: " + 
                        str(src_ip) + " DST IP: "+ str(dst_ip)+" DST PORT: " + 
                        str(dst_port) + traffic_monitor.bcolors.ENDC)
                port_scan_log = open('./ryu/app/AdaptiveIDS/portscan.report', 'a')
                port_scan_log.write('<font color="red">[ '+datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+' ]' +" Port scan detected from  SRC IP: " + 
                        str(src_ip) + " DST IP: "+ str(dst_ip)+" DST PORT: " + 
                        str(dst_port)+"</font><br>")
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
            
