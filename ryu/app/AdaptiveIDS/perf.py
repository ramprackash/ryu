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
        topo = SingleSwitchTopo(n=3)
        net = Mininet(topo,controller=RemoteController,autoSetMacs = True)
        net.start()
        print "Dumping host connections"
        dumpNodeConnections(net.hosts)
        #print "Testing network connectivity"
        #net.pingAll()

	h1, h2, h3  = net.hosts[0], net.hosts[1], net.hosts[2]
	s1 = net.switches[0]
	
	print h1.cmd('timeout 11 bwm-ng -o plain -t 10000 -c 0 > h1_lp_bandwidth &')
	print h3.cmd('timeout 11 bwm-ng -o plain -t 10000 -c 0 > h2_lp_bandwidth &')
	print h1.cmd('ping -q -c 1000 -i .01 %s > lp_latency' % h3.IP())

	print h1.cmd('timeout 11 bwm-ng -o plain -t 10000 -c 0 > h1_dp_bandwidth &')
	print h3.cmd('timeout 11 bwm-ng -o plain -t 10000 -c 0 > h2_dp_bandwidth &')
	print h1.cmd('ping -q -c 1000 -i .01 %s > dp_latency' % h3.IP())
	
	print "Stopping mininet"
        net.stop()

if __name__ == '__main__':
        # Tell mininet to print useful information
        setLogLevel('info')
        simpleTest()
