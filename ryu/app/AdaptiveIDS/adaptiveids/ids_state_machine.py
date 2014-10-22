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
        self.state_machine.print_state()
    
    def update_start_time(self):
        self.start_time = time.time()

class IDSStateMachine:
    def __init__(self):
        self.lp_filter = lp_filter.LPFilter()
        self.dp_filter = dp_filter.DPFilter()
        self.state = self.lp_filter
        self.ids_timer = None
    
    def enforce_deep_probing(self):
        self.state = self.dp_filter
        if self.ids_timer == None:
            self.ids_timer = IDSTimer(self)
            self.ids_timer.start()
        else:
            self.ids_timer.update_start_time()
    
    def enforce_light_probing(self):
        self.state = self.lp_filter
    
    def inspect_packets(self):
        self.state.inspect_packets()
         
    def print_state(self):
        if self.state.__name__() == "LPFilter":
            print('Current state of IDS State Machine - Light Probe Mode')
        else:
            print('Current state of IDS State Machine - Deep Probe Mode')
            
    def process_timer_expiry(self):
        if self.ids_timer != None:
            self.enforce_light_probing()
            self.ids_timer = None