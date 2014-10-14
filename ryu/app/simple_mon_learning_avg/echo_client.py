#!/usr/bin/python
"""
A simple echo client
"""

import socket
import time
import sys

class Gradual:
    def __init__(self, start_val):
        self.start_val = float(start_val)
        self.time_val = float(start_val)
        self.num_requests = 0
    
    def get_sleep_val(self):
        self.time_val = float(self.time_val - 0.05)
        if self.time_val < float(1.0):
            self.time_val = float(self.start_val)
        return self.start_val

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
    gr = Gradual(3.0)
    while 1:
        do_echo()
        time.sleep(gr.get_sleep_val())      

main()
