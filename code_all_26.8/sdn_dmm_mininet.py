#!/usr/bin/python

"""
Simple example of Mobility with Mininet
(aka enough rope to hang yourself.)

We move a host from s1 to s2, s2 to s3, and then back to s1.

Gotchas:

The reference controller doesn't support mobility, so we need to
manually flush the switch flow tables!

Good luck!

to-do:

- think about wifi/hub behavior
- think about clearing last hop - why doesn't that work?
"""
import time
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.topo import LinearTopo, Topo
from mininet.util import quietRun
from mininet.log import output, warn
from mininet.link import TCLink
from mininet.node import CPULimitedHost
from mininet.node import RemoteController, Controller

from mininet.cli import CLI

from random import randint
from re import findall


class MobilitySwitch( OVSSwitch ):
    #def __init__(self):
    def version(self): 	
	super(MobilitySwitch, self).protocols='OpenFlow13'
        print 'test'
    #OVSSwitch.protocols='OpenFlow13'	
    #"Switch that can reattach and rename interfaces"	
    def delIntf( self, intf ):
        "Remove (and detach) an interface"
        port = self.ports[ intf ]
        del self.ports[ intf ]
        del self.intfs[ port ]
        del self.nameToIntf[ intf.name ]

    def addIntf( self, intf, rename=False, **kwargs ):
        "Add (and reparent) an interface"
        OVSSwitch.addIntf( self, intf, **kwargs )
        intf.node = self
        if rename:
            self.renameIntf( intf )

    def attach( self, intf ):
        "Attach an interface and set its port"
        port = self.ports[ intf ]
        if port:
            if self.isOldOVS():
                print 'Attach:', self.cmd( 'ovs-vsctl add-port', self, intf )
            else:
                print 'Attach:', self.cmd( 'ovs-vsctl add-port', self, intf,
                          '-- set Interface', intf,
                          'ofport_request=%s' % port )
            self.validatePort( intf )
	self.cmd( 'ovs-ofctl --version', self)	

    def validatePort( self, intf ):
        "Validate intf's OF port number"
        ofport = int( self.cmd( 'ovs-vsctl get Interface', intf,
                              'ofport' ) )
        if ofport != self.ports[ intf ]:
            warn( 'WARNING: ofport for', intf, 'is actually', ofport,
                  '\n' )
	    print 'WARNING: ofport for:', 

    def renameIntf( self, intf, newname='' ):
        "Rename an interface (to its canonical name)"
        intf.ifconfig( 'down' )
        if not newname:
            newname = '%s-eth%d' % ( self.name, self.ports[ intf ] )
        intf.cmd( 'ip link set', intf, 'name', newname )
        del self.nameToIntf[ intf.name ]
	print 'Old Interface:', intf.name
        intf.name = newname
        self.nameToIntf[ intf.name ] = intf
        intf.ifconfig( 'up' )
	print 'New Interface:', newname

    def moveIntf( self, intf, switch, port=None, rename=True ):
        "Move one of our interfaces to another switch"
        self.detach( intf )
        self.delIntf( intf )
        switch.addIntf( intf, port=port, rename=rename )
        switch.attach( intf )


class MyTopo( Topo ):
    "Simple topology example."

    def build( self, **_opts ):
        "Create custom topo."

        # Add hosts and switches
        #host10 = self.addHost('h10')
        host1 = self.addHost('h1')
        #host30 = self.addHost('h30')
        host3 = self.addHost('h3')
        #host40 = self.addHost('h40')
        host5 = self.addHost('h5')
        
        switch1 = self.addSwitch( 's1' )
        switch2 = self.addSwitch( 's2' )
        switch3 = self.addSwitch( 's3' )
        switch4 = self.addSwitch( 's4' )
        switch5 = self.addSwitch( 's5' )

        self.addLink( host1, switch1, bw=10, delay = '0ms' )
        #self.addLink( host11, switch1 )

        #self.addLink( host30, switch3 )
        self.addLink( host3, switch3, bw=10, delay = '0ms' )

        #self.addLink( host40, switch4 )
        self.addLink( host5, switch5, bw=10, delay = '0ms' )

        # Add links
        self.addLink( switch1, switch2, bw=10, delay = '0ms')
        self.addLink( switch2, switch3, bw=10, delay = '0ms' )
        self.addLink( switch2, switch4, bw=10, delay = '0ms' )
        self.addLink( switch3, switch4, bw=10, delay = '0ms' )
        self.addLink( switch4, switch5 , bw=10, delay = '0ms')


def printConnections( switches ):
    "Compactly print connected nodes to each switch"
    for sw in switches:
        output( '%s: ' % sw )
        for intf in sw.intfList():
            link = intf.link
            if link:
                intf1, intf2 = link.intf1, link.intf2
                remote = intf1 if intf1.node != sw else intf2
                output( '%s(%s) ' % ( remote.node, sw.ports[ intf ] ) )
        output( '\n' )


def moveHost( host, oldSwitch, newSwitch, newPort=None ):
    "Move a host from old switch to new switch"
    hintf, sintf = host.connectionsTo( oldSwitch )[ 0 ]
    oldSwitch.moveIntf( sintf, newSwitch, port=newPort )
    return hintf, sintf


def mobilityTest():


    topo = MyTopo()
    c2 = RemoteController( 'c2', ip='127.0.0.1' )
    net = Mininet(topo=topo, link=TCLink, controller=c2, switch=MobilitySwitch)
    for s in net.switches:	
        s.protocols = 'OpenFlow13'
        #print 'protocol:', s.protocols

    old = net.get( 's3')
    s1, s2, s3, s4, s5 = net.get('s1','s2','s3', 's4', 's5')
    h1, h3, h5 = net.get('h1','h3', 'h5')

    
    net.start()
    print '', s1.cmd('ovs-vsctl set bridge s1 protocols=OpenFlow13')
    s2.cmd('ovs-vsctl set bridge s2 protocols=OpenFlow13')
    s3.cmd('ovs-vsctl set bridge s3 protocols=OpenFlow13')
    s4.cmd('ovs-vsctl set bridge s4 protocols=OpenFlow13')
    s5.cmd('ovs-vsctl set bridge s5 protocols=OpenFlow13')
    h1.cmd('/sbin/route -A inet6 add default gw 2001::1')
    h3.cmd('/sbin/route -A inet6 add default gw 2003::1')
    h5.cmd('/sbin/route -A inet6 add default gw 2005::1')
    #print 'protocol:', s1.protocols
    print ''
    print ''       
    print '*********************************'
    print 'Network Topology: '
    printConnections( net.switches )
    print '*********************************'
    CLI(net)
    i =3
    new = net[ 's%d' % 1 ]

#    while i>0:	
#        print '************************'
#        port = randint( 3, 9 )
#        hintf, sintf = moveHost( h3, old, new, newPort=port )
#        print '*', hintf, 'is now connected to', sintf
#        printConnections( net.switches )
#        print 'Send RS', h3.cmd( './send_rs.py')
#        h3.cmd('/sbin/route -A inet6 add default gw 2001::1')
#        tmp = old
#        old = new
#        new = tmp
#        i= i-1
#        print '************************'
#        CLI(net)


    print '***************Move from S3 to S1******************'
    port = 3
    hintf, sintf = moveHost( h3, s3, s1, newPort=port )
    print '*', hintf, 'is now connected to', sintf
    printConnections( net.switches )
    print '***************************************************'
    h3.cmd( './send_rs.py')
    h3.cmd('/sbin/route -A inet6 add default gw 2003::1')

    CLI(net)

    print '*************Move back from S1 to S3****************'
    port = 1
    hintf, sintf = moveHost( h3, s1, s3, newPort=port )
    print '*', hintf, 'is now connected to', sintf
    printConnections( net.switches )
    print '***************************************************'
    h3.cmd( './send_rs.py')
    h3.cmd('/sbin/route -A inet6 add default gw 2003::1')

    CLI(net)

    CLI(net)
    net.stop()
    

if __name__ == '__main__':
    mobilityTest()
