'''
Created on Oct 16, 2014

@author: nav
'''


import random

class TrafficMonitor:
    def __init__(self, statemachine):
        self.statemachine = statemachine
        self.latest_num_packets = {'12':0, '21':0, '13':0, '31':0, '23':0, '32':0}
        self.avg_outpackets = {}
    
    def process_flow_stats(self, ev):
        body = ev.msg.body
        print('datapath          '
                         'in-port       ipv4-dst      '
                         'out-port packets bytes')
        print('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 32768],
                           key=lambda flow: (flow.match['in_port'],
                           flow.match['ipv4_dst'])):
            print('%016x %8x %17s %8x %8d %8d' %(
                              ev.msg.datapath.id,
                              stat.match['in_port'], stat.match['ipv4_dst'],
                              stat.instructions[0].actions[0].port,
                              stat.packet_count, stat.byte_count))
            flow_name = str(stat.match['in_port'])+str(stat.instructions[0].actions[0].port)
            delta = stat.packet_count - self.latest_num_packets[flow_name]

            self.latest_num_packets[flow_name] = stat.packet_count
            if flow_name in self.avg_outpackets:
                if delta != 0:
                    avg_delta = delta - self.avg_outpackets[flow_name]
                    if avg_delta > 10:
                        print('!!!Spike in traffic in flow ' + str(flow_name))
                        self.statemachine.enforce_deep_probing()
                        self.statemachine.print_state()
                    self.avg_outpackets[flow_name] = (self.avg_outpackets[flow_name] + int(delta))/2
            else:
                self.avg_outpackets[flow_name] = int(stat.packet_count)
        print('\nAvg packets sent')
        print('Flow   #Packets')
        for key in self.avg_outpackets.keys():
            print(str(key) +'       ' + str(self.avg_outpackets[key]))
        print('\n')
