#!/usr/bin/python
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import irange,dumpNodeConnections
from mininet.log import setLogLevel

class CustomTopo(Topo):
   """ 
      Creates the topology given below. Notice that there is not controller 
      here. The controller is a remotely running POX. The mininet command to 
      launch this topology is:

           sudo mn --custom ~/pox/mininet_topologies/custom_topo.py \
                   --topo mytopo --controller=remote,ip=10.0.1.10

      Also note that the topology contains a couple of loops. POX does not 
      support loops by default. The spanning tree component needs to be enabled:

           ./pox.py forwarding.l2_learning openflow.of_01 --address=10.0.1.10 \
                   openflow.discovery openflow.spanning_tree

                /------------------------\
      h1.1 --\ /    /--h2.1     /--h3.1   \  /--h4.1
              s1 -- s2 ------- s3 -------- s4-----------\
      h1.2 --/      \--h2.2    | \--h3.2     \--h4.2    R1
                                \------------------------/
   """

   def __init__(self, k=4, **opts):
       """Init.
           k: number of switches (and hosts)
           hconf: host configuration options
           lconf: link configuration options"""

       super(CustomTopo, self).__init__(**opts)

       self.k = k

       lastSwitch = None
       firstSwitch = None
       for i in irange(1, k):
	   j = 1;
           host1 = self.addHost('h%s_%s' % (i,j))
           j = j + 1;
           host2 = self.addHost('h%s_%s' % (i,j))
           switch = self.addSwitch('s%s' % i)
           if (i == 1):
               firstSwitch = switch
           self.addLink( host1, switch)
           self.addLink( host2, switch)
           if lastSwitch:
               self.addLink( switch, lastSwitch)
           if (i == k):
               router = self.addSwitch('r1')
               self.addLink(switch, router)
               self.addLink(lastSwitch, router)
           lastSwitch = switch

       self.addLink(switch, firstSwitch)

def simpleTest():
   "Create and test a simple network"
   topo = CustomTopo(k=4)
   net = Mininet(topo)
   net.start()
   print "Dumping host connections"
   dumpNodeConnections(net.hosts)
   print "Testing network connectivity"
   net.pingAll()
   net.stop()

if __name__ == '__main__':
   # Tell mininet to print useful information
   setLogLevel('info')
   simpleTest()

topos = { 'mytopo': ( lambda: CustomTopo() ) }

