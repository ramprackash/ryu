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

def verifyAlerts(alerts):
	#./alert_output
        with open('alert_output') as fp:
           match={}
           for rule in alerts:
               match[rule]=False
           for line in fp:	
               for rule in alerts:
                  if line.rstrip('\n') == alerts[rule]:
                       match[rule]=True
                       break
           for rule in alerts:
               if match[rule] == False:
                     print "ERROR!!!! Match not found for "+rule
               #else:
                #     print "Match found for " + rule   

#def verifyFlows(flows):
	#./flow_dump

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

	alerts={}
	flows={}

	print "Running light probe tests"

	rule="alert any 10.0.0.1 any -> 10.0.0.3 any (msg:\"This is h1->h3\";)"
	print rule
	print h1.cmd('ping -c 1 -i .1 %s' % h3.IP())
	alerts[rule]="\"This is h1->h3\""
	flows[rule]=["10.0.0.1","10.0.0.3","output"]

	print "Running deep probe tests"
 
	rule="alert tcp 10.0.0.1 any -> 10.0.0.2 80 (msg:\"Malicious tcp data\"; content:\"diablo\";)"
	print rule
	print h2.cmd('nc -l 80 &')
	print h1.cmd('echo \'diablo \n\' | nc %s 80 &' % h2.IP())
        print h1.cmd('sleep 3')
	alerts[rule]="\"Malicious tcp data\""
	flows[rule]=["10.0.0.1","10.0.0.2","output"]

	rule=" alert udp 10.0.0.3 any -> 10.0.0.4 80 (msg:\"Malicious udp data\"; content:\"diablo\";)"
        print rule
	print h4.cmd('nc -ul 80 &')
	print h3.cmd('echo diablo | nc -u %s 80 &' % h4.IP())
	print h3.cmd('sleep 3')
	alerts[rule]="\"Malicious udp data\""
	flows[rule]=["10.0.0.3","10.0.0.4","output"]

        rule = "drop icmp 10.0.0.2 any -> 10.0.0.3 any (reinstate:\"true\";)"
        print rule
	print h2.cmd('ping -c 1 -i .1 %s' % h3.IP())
	flows[rule]=["10.0.0.2","10.0.0.3","drop"]
	
        rule = "alert any any any -> any any (msg:\"I see a lot of traffic\"; pps:80;) "
        print rule
	print h2.cmd('ping -c 100 -i .01 %s' % h4.IP())
	alerts[rule]="\"I see a lot of traffic\""
	flows[rule]=["10.0.0.2","10.0.0.4","output"]

	#verify alerts
	verifyAlerts(alerts)

	#verify flow
	#verifyFlows(flows)

	print "====== Flow dump =========="
	s1.cmdPrint('ovs-ofctl -O OpenFlow13 dump-flows s1 > flow_dump')
	print "Stopping mininet"
        net.stop()

if __name__ == '__main__':
        # Tell mininet to print useful information
        setLogLevel('info')
        simpleTest()
