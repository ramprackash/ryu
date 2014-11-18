'''
Created on Oct 16, 2014

@author: nav
'''


import random
from ryu.ofproto import inet


class TrafficMonitor:
    def __init__(self, statemachine, owner):
        self.statemachine = statemachine
        self.owner        = owner # Back pointer to the datapath object
    
    def process_flow_stats(self, ev):
        body = ev.msg.body
        print('datapath          '
                         'in-port       ipv4-dst      '
                         'out-port packets bytes     pps (over last 10s)')
        print('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------    -------------------')
        for stat in sorted([fl for fl in body if fl.priority == 32768],
                           key=lambda fl: (fl.match['in_port'],
                           fl.match['ipv4_dst'])):
            if stat.instructions != []:
                if stat.match['ip_proto'] == 6:
                    sport = stat.match['tcp_src']
                    dport = stat.match['tcp_dst']
                    proto = "tcp"
                elif stat.match['ip_proto'] == 17:
                    sport = stat.match['udp_src']
                    dport = stat.match['udp_dst']
                    proto = "udp"
                elif stat.match['ip_proto'] == 1:
                    sport = dport = "any"
                    proto = "icmp"
                else:
                    sport = dport = proto = "any"

                flow = self.owner.flows.getflow(self.owner.datapath,
                    stat.match['ipv4_src'], stat.match['ipv4_dst'],
                    proto, sport, dport)
                if flow == None:
                    continue
                delta = stat.packet_count - flow.hitcount
                flow.hitcount = stat.packet_count

                if delta != 0:
                    avg_delta = delta / 10
                    if "ip_proto" in stat.match:
                        if int(stat.match['ip_proto']) == \
                                inet.IPPROTO_ICMP:
                            ip_proto = "icmp"
                        elif int(stat.match['ip_proto']) == \
                                inet.IPPROTO_UDP:
                            ip_proto = "udp"
                        elif int(stat.match['ip_proto']) == \
                                inet.IPPROTO_TCP:
                            ip_proto = "tcp"
                        else:
                            ip_proto="any"
                    else:
                        ip_proto = "any"

                    result = self.owner.fsm.inspect_packets(ev.msg.datapath,
                                 stat.match['in_port'], 
                                 stat.instructions[0].actions[0].port,
                                 proto=ip_proto,
                                 src_ip=stat.match['ipv4_src'],
                             dst_ip=stat.match['ipv4_dst'], pps=avg_delta)
                    if (result != None):
                        self.statemachine.enforce_deep_probing()
                
                    flow.avgpkts = avg_delta
                    print('%016x%s %8x %17s %8x %8d %8d %4d' %(
                              ev.msg.datapath.id, self.owner.fsm.get_state(),
                              stat.match['in_port'], stat.match['ipv4_dst'],
                              stat.instructions[0].actions[0].port,
                              stat.packet_count, stat.byte_count, flow.avgpkts))
