'''
Created on Oct 16, 2014

@author: nav
'''


import random
from ryu.ofproto import inet

#Enable logging
LOGGING = True
META = False

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

class TrafficMonitor:
    def __init__(self, statemachine, owner):
        self.statemachine = statemachine
        self.owner        = owner # Back pointer to the datapath object
    
    def process_flow_stats(self, ev):
        body = ev.msg.body
        if LOGGING:
            log_file = open("./ryu/app/AdaptiveIDS/tmlogs.txt","a")        

        print ' '
        print(bcolors.OKBLUE + 'Flows In Datapath ' + bcolors.ENDC + '%016x%s' % (ev.msg.datapath.id, self.owner.fsm.get_state()))
        if LOGGING and META:
            log_file.write(" ")
            log_file.write(bcolors.OKBLUE + '\nFlows In Datapath ' + bcolors.ENDC + '%016x%s' % (ev.msg.datapath.id, self.owner.fsm.get_state_abs()))


        print(bcolors.OKBLUE + 'in-port      ipv4-src          ipv4-dst     '
                         'out-port  packets   bytes   pps (over last 10s)')
        if LOGGING and META:
            log_file.write(bcolors.OKBLUE + '\nin-port      ipv4-src          ipv4-dst     '
                         'out-port  packets   bytes   pps (over last 10s)')

        print('-------- ----------------- ---------------- '
                         '--------  -------  -------  -------------------' 
                         + bcolors.ENDC)
        if LOGGING and META:
            log_file.write('\n-------- ----------------- ---------------- '
                         '--------  -------  -------  -------------------' 
                         + bcolors.ENDC)

        for stat in sorted([fl for fl in body if (fl.priority >= 32760 and
                                                  fl.priority != 65535)],
                           key=lambda fl: (fl.match['ipv4_src'])):
            sport = dport = proto = "any"
            try:
                if stat.match['ip_proto'] == 6:
                    #sport = stat.match['tcp_src']
                    #dport = stat.match['tcp_dst']
                    proto = "tcp"
                elif stat.match['ip_proto'] == 17:
                    #sport = stat.match['udp_src']
                    #dport = stat.match['udp_dst']
                    proto = "udp"
                elif stat.match['ip_proto'] == 1:
                    #sport = dport = "any"
                    proto = "icmp"
            except:
                proto = "any"

            try:
                dst = stat.match['ipv4_dst']
            except:
                dst = "any"

            try:
                inport = str(stat.match['in_port'])
            except:
                inport = "any"

            flow = self.owner.flows.getflow(self.owner.datapath,
                stat.match['ipv4_src'], dst,
                proto, sport, dport)
            if flow == None:
                print ("Flow not found (for %s:%s:%s:%s:%s). How??" %
                        (stat.match['ipv4_src'], stat.match['ipv4_dst'], str(proto),
                        str(sport), str(dport)))
                if LOGGING and META:
                    log_file.write("\nFlow not found (for %s:%s:%s:%s:%s). How??" %
                        (stat.match['ipv4_src'], stat.match['ipv4_dst'], str(proto),
                        str(sport), str(dport)))
                continue

            delta = stat.packet_count - flow.hitcount
            flow.hitcount = stat.packet_count

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

            if stat.instructions != [] and inport != "any":
                result = self.owner.fsm.inspect_packets(ev.msg.datapath,
                        stat.match['in_port'], 
                        stat.instructions[0].actions[0].port,
                        proto=ip_proto,
                        src_ip=stat.match['ipv4_src'],
                        dst_ip=stat.match['ipv4_dst'], pps=avg_delta)
                if (result != None):
                    self.statemachine.enforce_deep_probing()

            flow.avgpkts = avg_delta
            if stat.instructions != []:
                print('%8s %17s %17s %8s %8s %8s %4s' %(
                    '{:^8x}'.format(stat.match['in_port']), 
                    '{:^17s}'.format(stat.match['ipv4_src']), 
                    '{:^17s}'.format(stat.match['ipv4_dst']),
                    '{:^8d}'.format(stat.instructions[0].actions[0].port),
                    '{:^8d}'.format(stat.packet_count), 
                    '{:^8d}'.format(stat.byte_count), 
                    '{:^19d}'.format(flow.avgpkts)))
                if LOGGING:
                    '''
                    log_file.write('\n%3s %8s %17s %17s %8s %8s %8s %4s' %(
                    '{:^3x}'.format(ev.msg.datapath.id), 
                    '{:^8x}'.format(stat.match['in_port']), 
                    '{:^17s}'.format(stat.match['ipv4_src']), 
                    '{:^17s}'.format(stat.match['ipv4_dst']),
                    '{:^8d}'.format(stat.instructions[0].actions[0].port),
                    '{:^8d}'.format(stat.packet_count), 
                    '{:^8d}'.format(stat.byte_count), 
                    '{:^19d}'.format(flow.avgpkts)))'''
                    log_file.write('<tr><td>%3s%s</td><td>%8s</td><td>%17s</td><td>%17s</td><td>%8s</td><td> %8s</td><td>%8s</td><td>%4s</td></tr>' %(
                    '{:^3x}'.format(ev.msg.datapath.id),
                    self.owner.fsm.get_state_html(),
                    '{:^8x}'.format(stat.match['in_port']), 
                    '{:^17s}'.format(stat.match['ipv4_src']), 
                    '{:^17s}'.format(stat.match['ipv4_dst']),
                    '{:^8d}'.format(stat.instructions[0].actions[0].port),
                    '{:^8d}'.format(stat.packet_count), 
                    '{:^8d}'.format(stat.byte_count), 
                    '{:^19d}'.format(flow.avgpkts)))


            else:
                print('%8s %17s %17s %8s %8s %8s %4s' %(
                    '{:^8s}'.format(inport), 
                    '{:^17s}'.format(stat.match['ipv4_src']),
                    '{:^17s}'.format(dst),
                    bcolors.FAIL + " drop   " + bcolors.ENDC,
                    '{:^8d}'.format(stat.packet_count), 
                    '{:^8d}'.format(stat.byte_count), 
                    '{:^19d}'.format(flow.avgpkts)))
                if LOGGING:
                    '''
                    log_file.write('\n%3s %8s %17s %17s %8s %8s %8s %4s' %(
                    '{:^3x}'.format(ev.msg.datapath.id), 
                    '{:^8x}'.format(stat.match['in_port']), 
                    '{:^17s}'.format(stat.match['ipv4_src']),
                    '{:^17s}'.format(stat.match['ipv4_dst']),
                    bcolors.FAIL + " drop   " + bcolors.ENDC,
                    '{:^8d}'.format(stat.packet_count), 
                    '{:^8d}'.format(stat.byte_count), 
                    '{:^19d}'.format(flow.avgpkts)))'''
                    log_file.write('<tr><td>%3s%s</td><td>%8s</td><td>%17s</td><td>%17s</td><td>%8s</td><td> %8s</td><td>%8s</td><td>%4s</td></tr>' %(
                    '{:^3x}'.format(ev.msg.datapath.id),
                    self.owner.fsm.get_state_html(),
                    '{:^8s}'.format(inport), 
                    '{:^17s}'.format(stat.match['ipv4_src']),
                    '{:^17s}'.format(dst),
                    '<font color="red"> drop</font>',
                    '{:^8d}'.format(stat.packet_count), 
                    '{:^8d}'.format(stat.byte_count), 
                    '{:^19d}'.format(flow.avgpkts)))


            if flow.avgpkts <= flow.triggerPPS:
                print("Going back to Light Probe as spike ended %d < %d" % 
                        (flow.avgpkts, flow.triggerPPS))
                if LOGGING:
                    log_file.write("\nGoing back to Light Probe as spike ended %d < %d" % 
                        (flow.avgpkts, flow.triggerPPS))
                self.owner.flows.delflow(flow)
                self.owner.fsm.enforce_light_probing()
        log_file.close()
