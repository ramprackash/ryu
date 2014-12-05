'''
Created on Oct 16, 2014

@author: nav
'''
import simple_snort_rules 

class DPFilter:
    def __init__(self, owner, rules='./ryu/app/AdaptiveIDS/light_probe.rules'):
        self.dp_rules = simple_snort_rules.SnortParser(owner, rule_file=rules)
    

    def __name__(self):
        return 'DPFilter'
    
    def inspect_packets(self, datapath, in_port, out_port, proto="any",
                        src_ip="any", src_port="any", dst_ip="any", 
                        dst_port="any", pps=-1, pkt_data=None):
        return self.dp_rules.impose(datapath, in_port, out_port,
                                    proto=proto, src_ip=src_ip, 
                                    src_port=src_port,
                                    dst_ip=dst_ip, dst_port=dst_port,
                                    pkt_data=pkt_data, pps=pps)
