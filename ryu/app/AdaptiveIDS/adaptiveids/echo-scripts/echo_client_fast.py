#!/usr/bin/python
"""
A simple echo client
"""

import socket
import time
import sys

class Spiked:
    def __init__(self, start_val, fast_val):
        self.start_val = float(start_val)
        self.time_val = float(start_val)
        self.fast_val = float(fast_val)
        self.num_requests = 0
    
    def get_sleep_val(self):
        self.num_requests += 1
        if self.num_requests >= 30:
            self.num_requests = 0;
            return self.time_val
        if self.num_requests <= 20:
            return self.time_val
        if self.num_requests > 20:
            return self.fast_val

def do_echo():
    host = '10.0.0.1'
    port = 50000
    size = 1024
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host,port))
    print('Sending ' + str(time.time()))
    s.send(str(time.time()))
    #data = s.recv(size)
    s.close()
    #print 'Received:', data 

def main():
    gr = Spiked(2.0, 0.5)
    while 1:
        do_echo()
        time.sleep(gr.get_sleep_val())

main()
