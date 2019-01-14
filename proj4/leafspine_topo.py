#!/usr/bin/env python

from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.topo import Topo
from mininet.log import setLogLevel
#from pox import POX

class AssignmentNetworks(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)

        #Start to build the tree here.

        #Add Hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')

        #Add Leaf switches
        l1 = self.addSwitch('l1')
        l2 = self.addSwitch('l2')
        l3 = self.addSwitch('l3')

        #Add Spine switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        #Link Hosts to Link switches
        self.addLink(h1, l1)
        self.addLink(h2, l1)
        self.addLink(h3, l2)
        self.addLink(h4, l2)
        self.addLink(h5, l3)
        self.addLink(h6, l3)

        #Link Link switches to Spine switches
        self.addLink(l1, s1)
        self.addLink(l2, s1)
        self.addLink(l3, s1)
	self.addLink(l1, s2)
	self.addLink(l2, s2)
	self.addLink(l3, s2) 
        
if __name__ == '__main__':
    setLogLevel( 'info' )

    topo = AssignmentNetworks()
    net = Mininet(controller=RemoteController, topo=topo, link=TCLink, autoSetMacs=True,
           autoStaticArp=True)

    # Run network
    net.start()
    CLI( net )
    net.stop()


