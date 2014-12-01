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
        topo = SingleSwitchTopo(n=4)
        net = Mininet(topo,controller=RemoteController,autoSetMacs = True)
        net.start()
        print "Dumping host connections"
        dumpNodeConnections(net.hosts)
        #print "Testing network connectivity"
        #net.pingAll()

	h1, h2, h3, h4  = net.hosts[0], net.hosts[1], net.hosts[2], net.hosts[3]
	s1 = net.switches[0]

	print "Running light probe tests"
	print "Testing : alert any 10.0.0.1 any -> 10.0.0.3 any (msg:\"This is h1->h3\";)"
	print h1.cmd('ping -c 1 -i .1 %s' % h3.IP())

	print "Running deep probe tests"

	print "Testing : alert tcp 10.0.0.1 any -> 10.0.0.2 80 (msg:\"Malicious tcp data\"; content:\"diablo\";)"
	print h2.cmd('nc -l 80 &')
	print h1.cmd('echo \'diablo \n\' | nc %s 80 &' % h2.IP())
        print h1.cmd('sleep 3')

	print "Testing : alert udp 10.0.0.3 any -> 10.0.0.4 80 (msg:\"Malicious udp data\"; content:\"diablo\";)"
	print h4.cmd('nc -ul 80 &')
	print h3.cmd('echo diablo | nc -u %s 80 &' % h4.IP())
	print h3.cmd('sleep 3')

        print "Testing : drop icmp 10.0.0.2 any -> 10.0.0.3 any (msg:\"This is h2->h3\";reinstate:\"true\";)"
	print h2.cmd('ping -c 1 -i .1 %s' % h3.IP())
	
        print "Testing : alert any any any -> any any (msg:\"I see a lot of traffic\"; pps:100;) "
	print h2.cmd('ping -c 100 -i .01 %s' % h3.IP())

	print "====== Flow dump =========="
	s1.cmdPrint('ovs-ofctl -O OpenFlow13 dump-flows s1 > flow_dump')
	print "Stopping mininet"
        net.stop()

if __name__ == '__main__':
        # Tell mininet to print useful information
        setLogLevel('info')
        simpleTest()
