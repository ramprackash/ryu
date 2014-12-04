#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import RemoteController                              
from time import sleep

class SingleSwitchTopo(Topo):
        "Single switch connected to n hosts."
        def __init__(self, n=2, **opts):
            # Initialize topology and default options
            Topo.__init__(self, **opts)
            switch = self.addSwitch('s1',protocols='OpenFlow13')
            # Python's range(N) generates 0..N-1
            for h in range(n):
                host = self.addHost('h%s' % (h + 1))
                self.addLink(host, switch)

def simpleTest():
        "Create and test a simple network"
        topo = SingleSwitchTopo(n=2)
        net = Mininet(topo,controller=RemoteController,autoSetMacs = True)
        net.start()
        print "Dumping host connections"
        dumpNodeConnections(net.hosts)
        #print "Testing network connectivity"
        #net.pingAll()

	h1, h2  = net.hosts[0], net.hosts[1]
	s1 = net.switches[0]
	
	print h1.cmd('timeout 11 bwm-ng -o html -t 10000 > h1_bandwith.html &')
	print h2.cmd('timeout 11 bwm-ng -o html -t 10000 > h2_bandwith.html &')
	print h1.cmd('ping -c 1000 -i .01 %s' % h2.IP())
	

	print "Stopping mininet"
        net.stop()

if __name__ == '__main__':
        # Tell mininet to print useful information
        setLogLevel('info')
        simpleTest()
