'''
Created on Oct 16, 2014

@author: nav
'''
import dp_filter
import lp_filter

import threading
import time

class IDSTimer(threading.Thread):
    def __init__(self, statemachine):
        threading.Thread.__init__(self)
        self.start_time = time.time()
        self.state_machine = statemachine
    
    def run(self):
        while time.time() - self.start_time < 20:
            time.sleep(1)
        print('IDS Timer expired')
        self.state_machine.process_timer_expiry()
    
    def update_start_time(self):
        self.start_time = time.time()

class IDSStateMachine:
    def __init__(self, owner):
        self.lp_filter = lp_filter.LPFilter(owner)
        self.dp_filter = dp_filter.DPFilter(owner)
        self.ids_timer = None
        self.owner = owner
        self.enforce_light_probing()
    
    def enforce_deep_probing(self):
        self.state = self.dp_filter
        self.print_state()
        if self.ids_timer == None:
            self.ids_timer = IDSTimer(self)
            self.ids_timer.start()
        else:
            self.ids_timer.update_start_time()
    
    def enforce_light_probing(self):
        self.state = self.lp_filter
        self.print_state()
    
    def inspect_packets(self, datapath, in_port, out_port, proto="any",
                        src_ip="any", src_port="any", dst_ip="any", 
                        dst_port="any", pps=-1, pkt_data=None):
        result =  self.state.inspect_packets(datapath, in_port, out_port, 
                                          proto, src_ip, src_port, dst_ip, 
                                          dst_port, pps, pkt_data)
        if result != None:
            self.enforce_deep_probing()
        return result
         
    def print_state(self):
        if self.state.__name__() == "LPFilter":
            print('Datapath %d- Light Probe Mode' % self.owner.datapath.id)
        else:
            print('Datapath %d- Deep Probe Mode' % self.owner.datapath.id)

    def get_state(self):
        if self.state.__name__() == "LPFilter":
            return "(L)"
        else:
            return "(D)"
            
            
    def process_timer_expiry(self):
        if self.ids_timer != None:
            self.enforce_light_probing()
            self.owner.flows.cleanup()
            self.ids_timer = None
