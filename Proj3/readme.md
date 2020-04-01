IP packet sender/receiver usage instructions:  

1. Compile the source file:  
gcc -o iparp ip_arp.c

2. Run Mininet and build a network:  
sudo mn -c  
python router.py  

Send a packet using mininet:  
h1x1 ./iparp Send <interfaceName> <destIP> <routerIP> <message>  
h1x1 ./iparp Send h1x1-eth0 10.0.0.1 192.168.1.100 'This is a test'  

Receive a packet (immediately after sending the packet from another host):  
h3x2 ./iparp Recv <interfaceName>  
h3x2 ./iparp Recv h3x2-eth0  
