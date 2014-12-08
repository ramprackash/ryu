'''
Created on Oct 16, 2014

@author: nav
'''
import dp_filter
import lp_filter
import ids_main

import threading
import time

from traffic_monitor import bcolors

class IDSTimer(threading.Thread):
    def __init__(self, statemachine, time_out=300):
        threading.Thread.__init__(self)
        self.start_time = time.time()
        self.state_machine = statemachine
        self.time_out = time_out
    
    def run(self):
        while time.time() - self.start_time < self.time_out:
            time.sleep(1)
        print('IDS Timer expired')
        self.state_machine.process_timer_expiry()
    
    def update_start_time(self):
        self.start_time = time.time()

class IDSStateMachine:
    def __init__(self, owner):
        self.lp_filter = lp_filter.LPFilter(owner, rules=ids_main.IDSCfgParams.LP_RULES_FILE)
        self.dp_filter = dp_filter.DPFilter(owner, rules=ids_main.IDSCfgParams.DP_RULES_FILE)
        self.ids_timer = None
        self.owner = owner
        self.enforce_light_probing()
    
    """ Move to DPM """
    def enforce_deep_probing(self):
        self.state = self.dp_filter
        #self.print_state()
        if self.ids_timer == None:
            self.ids_timer = IDSTimer(statemachine=self,time_out=ids_main.IDSCfgParams.FSM_TIMER)
            self.ids_timer.start()
            #print('Starting timer with time_out: ' + str(ids_main.IDSCfgParams.FSM_TIMER))
        else:
            self.ids_timer.update_start_time()
    
    """ Move to LPM """
    def enforce_light_probing(self):
        self.state = self.lp_filter
        #self.print_state()
    
    def inspect_packets(self, datapath, in_port, out_port, proto="any",
                        src_ip="any", src_port="any", dst_ip="any", 
                        dst_port="any", pps=-1, pkt_data=None):
	#print 'inspect_packets '+str(pkt_data)
        result =  self.state.inspect_packets(datapath, in_port, out_port, 
                                          proto, src_ip, src_port, dst_ip, 
                                          dst_port, pps, pkt_data)
        if result != None:
            self.enforce_deep_probing()
        return result
         
    def print_state(self):
        if self.state.__name__() == "LPFilter":
            print('Datapath %16d- Light Probe Mode' % self.owner.datapath.id)
        else:
            print('Datapath %16d- Deep Probe Mode' % self.owner.datapath.id)

    def get_state(self):
        if self.state.__name__() == "LPFilter":
            return bcolors.OKGREEN + "(L)" + bcolors.ENDC
        else:
            return bcolors.FAIL + "(D)" + bcolors.ENDC

    def get_state_abs(self):
        if self.state.__name__() == "LPFilter":
            return "(L)"
        else:
            return "(D)"

    def get_state_html(self):
        if self.state.__name__() == "LPFilter":
            return '<font color="green">(L)</font>'
        else:
            return '<font color="red">(D)</font>'
            
            
    def process_timer_expiry(self):
        if self.ids_timer != None:
            self.enforce_light_probing()
            self.owner.flows.cleanup()
            self.ids_timer = None
