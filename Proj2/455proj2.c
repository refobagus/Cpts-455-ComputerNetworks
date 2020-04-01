#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <unistd.h>

#define BUF_SIZE 60


struct arp_hdr {
    uint16_t ar_hrd;
    uint16_t ar_pro;
    unsigned char ar_hln;
    unsigned char ar_pln;
    uint16_t ar_op;
    unsigned char ar_sha[6];
    unsigned char ar_sip[4];
    unsigned char ar_tha[6];
    unsigned char ar_tip[4];
};

int get_ip_saddr(int fd, const char *ifname, uint32_t *ip) 
{
    struct ifreq if_idx;
    memset(&if_idx, 0, sizeof(struct ifreq));
    strcpy(if_idx.ifr_name, ifname);
    if (ioctl(fd, SIOCGIFADDR, &if_idx) < 0) 
    {
        perror("SIOCGIFADDR");
        return -1;
    }

    struct sockaddr *addr = &if_idx.ifr_addr;

    if (addr->sa_family == AF_INET)
    {
        struct sockaddr_in *i = (struct sockaddr_in *) addr;
        *ip = i->sin_addr.s_addr;
        return 0;
    }

    return -1;
}

int send_arp(int fd, int ifindex, const unsigned char *src_mac, uint32_t src_ip, uint32_t dst_ip)
{
    unsigned char buf[BUF_SIZE];
    memset(buf, 0, sizeof(buf));
    struct ethhdr *ehead = (struct ethhdr *) buf;
    struct arp_hdr *arp = (struct arp_hdr *) (buf + 14);
    int index;
    struct sockaddr_ll sockaddr;


    sockaddr.sll_ifindex = ifindex;
    sockaddr.sll_halen = ETH_ALEN;
    memcpy(sockaddr.sll_addr, src_mac, 6);
    sockaddr.sll_addr[6] = 0x00;
    sockaddr.sll_addr[7] = 0x00;

    memset(ehead->h_dest, 0xff, 6);
    memcpy(ehead->h_source, src_mac, 6);
    ehead->h_proto = htons(ETH_P_ARP);

    arp->ar_hrd = htons(1);
    arp->ar_pro = htons(ETH_P_IP);
    arp->ar_hln = 6;
    arp->ar_pln = 4;
    arp->ar_op = htons(0x01);
    memset(arp->ar_tha, 0x00, 6);
    memcpy(arp->ar_sha, src_mac, 6);

    // ip to arp
    memcpy(arp->ar_sip, &src_ip, sizeof(uint32_t));
    memcpy(arp->ar_tip, &dst_ip, sizeof(uint32_t));

    sendto(fd, buf, 42, 0, (struct sockaddr *) &sockaddr, sizeof(sockaddr));
    return 0;
}


int get_ip(const char *ifname, uint32_t *ip, char *mac, int *ifindex)
{
    struct ifreq if_idx;
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd <= 0) 
    {
        close(sockfd);
        return -1;
    }

    strcpy(if_idx.ifr_name, ifname);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) //assign socket to device
	{
    	perror("SIOCGIFINDEX");
        close(sockfd);
        return -1;
    }   

    *ifindex = if_idx.ifr_ifindex;
    if (ioctl(sockfd, SIOCGIFHWADDR, &if_idx) < 0) 
    {
        perror("SIOCGIFINDEX");
        close(sockfd);
        return -1;
    }

    memcpy(mac, if_idx.ifr_hwaddr.sa_data, 6);

    if (get_ip_saddr(sockfd, ifname, ip)) 
    {
        close(sockfd);
        return -1;
    }

    return 0;
}

int bind_proc(int ifindex, int *fd)
{
    struct sockaddr_ll sll;
    *fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (*fd < 1) 
    {
        close(*fd);
        return -1;
    }
    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    if (bind(*fd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0) 
    {
        close(*fd);
        return -1;
    }

    return 0;
    
}

int recv_arp(int fd)
{
    unsigned char buf[BUF_SIZE];
    ssize_t length = recvfrom(fd, buf, BUF_SIZE, 0, NULL, NULL);
    int index;
    struct ethhdr *ehead = (struct ethhdr *) buf;
    struct arp_hdr *arp = (struct arp_hdr *) (buf + 14);
    struct in_addr recv_ip;
    if (ntohs(ehead->h_proto) != ETH_P_ARP) 
    {
        printf("Not an ARP packet\n");
        return -1;
    }
    if (ntohs(arp->ar_op) != 0x02) 
    {
        printf("Not an ARP reply");
        return -1;
    }
    memset(&recv_ip, 0, sizeof(struct in_addr));
    memcpy(&recv_ip.s_addr, arp->ar_sip, sizeof(uint32_t));
    printf("Destination IP: %s\n", inet_ntoa(recv_ip));

    printf("Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
          arp->ar_sha[0],
          arp->ar_sha[1],
          arp->ar_sha[2],
          arp->ar_sha[3],
          arp->ar_sha[4],
          arp->ar_sha[5]);

    return 0;
}

int arp_proc(const char *ifname, const char *ip) 
{
    int arp, src, ifindex;

    char mac[6];
    uint32_t dst = inet_addr(ip);
    if (get_ip(ifname, &src, mac, &ifindex)) 
    {
        printf("Mission Failed\n");
        return -1;
    }
    if (bind_proc(ifindex, &arp)) 
    {
        close(arp);
        return -1;
    }
    if (send_arp(arp, ifindex, mac, src, dst)) 
    {
        close(arp);
        return -1;
    }
    int reply = recv_arp(arp);
    return 0;
}

int main(int argc, const char **argv)
{
    if (argc != 3) 
    {
        printf("Usage: ./a.out <Interfacename> <DestIP>\n");
        return -1;
    }
    const char *ifname = argv[1];
    const char *ip = argv[2];
    return arp_proc(ifname, ip); 
}