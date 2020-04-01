#!/usr/bin/python

"""
linuxrouter.py: Example network with Linux IP router
This example converts a Node into a router using IP forwarding
already built into Linux.
The example topology creates a router and three IP subnets:
    - 192.168.1.0/24 (r0-eth1, IP: 192.168.1.1)
    - 172.16.0.0/12 (r0-eth2, IP: 172.16.0.1)
    - 10.0.0.0/8 (r0-eth3, IP: 10.0.0.1)
Each subnet consists of a single host connected to
a single switch:
    r0-eth1 - s1-eth1 - h1-eth0 (IP: 192.168.1.100)
    r0-eth2 - s2-eth1 - h2-eth0 (IP: 172.16.0.100)
    r0-eth3 - s3-eth1 - h3-eth0 (IP: 10.0.0.100)
The example relies on default routing entries that are
automatically created for each router interface, as well
as 'defaultRoute' parameters for the host interfaces.
Additional routes may be added to the router or hosts by
executing 'ip route' or 'route' commands on the router or hosts.
"""


from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI



class LinuxRouter( Node ):
    "A Node with IP forwarding enabled."

    def config( self, **params ):
        super( LinuxRouter, self).config( **params )
        # Enable forwarding on the router
        self.cmd( 'sysctl net.ipv4.ip_forward=1' )

    def terminate( self ):
        self.cmd( 'sysctl net.ipv4.ip_forward=0' )
        super( LinuxRouter, self ).terminate()


class NetworkTopo( Topo ):
    "A LinuxRouter connecting three IP subnets"

    def build( self, **_opts ):

        defaultIP = '192.168.1.1/24'  # IP address for r0-eth1
        router = self.addNode( 'r0', cls=LinuxRouter, ip=defaultIP )

        s1, s2, s3 = [ self.addSwitch( s ) for s in ( 's1', 's2', 's3' ) ]

        self.addLink( s1, router, intfName2='r0-eth1',
                      params2={ 'ip' : defaultIP } )  # for clarity
        self.addLink( s2, router, intfName2='r0-eth2',
                      params2={ 'ip' : '172.16.0.1/12' } )
        self.addLink( s3, router, intfName2='r0-eth3',
                      params2={ 'ip' : '10.0.0.1/8' } )

        h1x1 = self.addHost( 'h1x1', ip='192.168.1.101/24', mac='00:00:00:00:00:11',
                           defaultRoute='via 192.168.1.1' )
        h1x2 = self.addHost( 'h1x2', ip='192.168.1.102/24', mac='00:00:00:00:00:12',
                           defaultRoute='via 192.168.1.1' )
        h2x1 = self.addHost( 'h2x1', ip='172.16.0.101/12', mac='00:00:00:00:00:21',
                           defaultRoute='via 172.16.0.1' )
        h2x2 = self.addHost( 'h2x2', ip='172.16.0.102/12', mac='00:00:00:00:00:22',
                           defaultRoute='via 172.16.0.1' )
        h3x1 = self.addHost( 'h3x1', ip='10.0.0.101/8', mac='00:00:00:00:00:31',
                           defaultRoute='via 10.0.0.1' )
        h3x2 = self.addHost( 'h3x2', ip='10.0.0.102/8', mac='00:00:00:00:00:32',
                           defaultRoute='via 10.0.0.1' )

        for h, s in [ (h1x1, s1), (h1x2, s1), (h2x1, s2), (h2x2, s2), (h3x1, s3), (h3x2, s3) ]:
            self.addLink( h, s )


def run():
    "Test linux router"
    topo = NetworkTopo()
    net = Mininet( topo=topo )  # controller is used by s1-s3
    net.start()
    info( '*** Routing Table on Router:\n' )
    info( net[ 'r0' ].cmd( 'route' ) )
    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    run()
