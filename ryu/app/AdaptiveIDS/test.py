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
	print "Running light probe tests"
	print h1.cmd('ping -c 1 -i .1 %s' % h3.IP())
	print "Running deep probe tests"
	print h2.cmd('nc -l 80 &')
	print h1.cmd('echo diablo | nc %s 80' % h2.IP())
	print "====== Flow dump =========="
	s1.cmdPrint('ovs-ofctl -O OpenFlow13 dump-flows s1')
	print "Stopping mininet"
        net.stop()

if __name__ == '__main__':
        # Tell mininet to print useful information
        setLogLevel('info')
        simpleTest()
