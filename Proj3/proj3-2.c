#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>

#define BUF_SIZ	65536
#define SEND 0
#define RECV 1

void recv_message(char * ifname);
void recv_arp(char* ifname, unsigned char* result);

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

int16_t ip_checksum(void* vdata,size_t length) {
	char* data=(char*)vdata;
	uint32_t acc=0xffff;
	for (size_t i=0;i+1<length;i+=2) 
	{
		uint16_t word;
		memcpy(&word,data+i,2);
		acc+=ntohs(word);
		if (acc>0xffff) 
		{
			acc-=0xffff;
		}
	}
	if (length&1) 
	{
		uint16_t word=0;
		memcpy(&word,data+length-1,1);
		acc+=ntohs(word);
		if (acc>0xffff) 
		{
			acc-=0xffff;
		}
	}
	return htons(~acc);
}

void recv_arp(char* ifname, unsigned char* result)
{
	printf("Inside ARP Recv\n");
	int sockfd, recvLen;
	char buf[BUF_SIZ];
	u_int8_t broadcast[6];
	char* broadcast_addr = "ff:ff:ff:ff:ff:ff";
	sscanf(broadcast_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &broadcast[0], &broadcast[1], &broadcast[2], &broadcast[3], &broadcast[4], &broadcast[5]);
	struct ifreq if_mac;
	struct ifreq if_idx;
	struct sockaddr_ll sk_addr;
	int sk_addr_size = sizeof(struct sockaddr_ll);
	struct ether_header *ehead = (struct ether_header *) buf;
	struct arp_hdr *arp = (struct arp_hdr *) (buf + sizeof(struct ether_header));

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		printf("Socket() failed");

	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifname, IFNAMSIZ -1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0){
		perror("SIOCGIFINDEX");
	}
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifname, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0){
		perror("SIOCGIFHWADDR");
	}
	while(1)
	{
		int invalid = 1;
		while(invalid)
		{
			invalid = 0;
			memset(&sk_addr, 0, sk_addr_size);
			recvLen = recvfrom(sockfd, buf, BUF_SIZ, 0, (struct sockaddr*)&sk_addr, &sk_addr_size);
			printf("recvLen = %d\n", recvLen);
			printf("Broadcast addr = %x:%x:%x:%x:%x:%x\n", broadcast[0], broadcast[1], broadcast[2], 
				broadcast[3], broadcast[4], broadcast[5]);
			if((ehead->ether_dhost[0] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0] || ehead->ether_dhost[1] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1] ||
				ehead->ether_dhost[2] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2] || ehead->ether_dhost[3] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3] ||
				ehead->ether_dhost[4] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4] || ehead->ether_dhost[5] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5]) &&
				(ehead->ether_dhost[0] != broadcast[0] || ehead->ether_dhost[1] != broadcast[1] ||
				ehead->ether_dhost[2] != broadcast[2] || ehead->ether_dhost[3] != broadcast[3] ||
				ehead->ether_dhost[4] != broadcast[4] || ehead->ether_dhost[5] != broadcast[5]))
			{
				invalid = 1;
			}
		}
		char sip1[16]; 
		unsigned char sip2[4];
		strcpy(sip1, inet_ntoa(get_ip_saddr(ifname, sockfd)));
		sscanf(sip1, "%hhd.%hhd.%hhd.%hhd", &sip2[0], &sip2[1], &sip2[2], &sip2[3]);
		if(arp->ar_op == htons((short)1))
		{
			printf("ARP Request Received!\n");
			if(arp->ar_tip[0] == sip2[0] && arp->ar_tip[1] == sip2[1] && arp->ar_tip[2] == sip2[2] && arp->ar_tip[3] == sip2[3])
			{
				unsigned char res[6];
				send_arp(arp->ar_sha, ifname, arp->ar_sip, 2, res);
				printf("ARP Reply Sent!\n");
			}
		}
		if(arp->ar_op == htons((short)2))
		{
			printf("ARP Reply Received!\n");
			if(arp->ar_tip[0] == sip2[0] && arp->ar_tip[1] == sip2[1] && arp->ar_tip[2] == sip2[2] && arp->ar_tip[3] == sip2[3])
			{
				for(int i = 0; i < 6; i++)
				{
					result[i] = arp->ar_sha[i];
				}
				return;
			}
		}
	}
}

void recv_message(char * ifname)
{
	printf("Receiving...\n");
	int sockfd, recvLen;
	char buf[BUF_SIZ];
	struct ifreq if_mac;
	struct ifreq if_idx;
	struct sockaddr_ll sk_addr;
	int sk_addr_size = sizeof(struct sockaddr_ll);
	struct ether_header *ehead = (struct ether_header *) buf;

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		printf("Socket() failed");

	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifname, IFNAMSIZ -1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0){
		perror("SIOCGIFINDEX");
	}
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifname, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0){
		perror("SIOCGIFHWADDR");
	}
	while(1)
	{
		memset(&sk_addr, 0, sk_addr_size);
		recvLen = recvfrom(sockfd, buf, BUF_SIZ, 0, (struct sockaddr*)&sk_addr, &sk_addr_size);
		printf("recvLen = %d\n", recvLen);
		printf("ether_type = %x\n", htons(ehead->ether_type));
		
		if(ehead->ether_type == htons(ETH_P_ARP))
		{
			struct arp_hdr *arp = (struct arp_hdr *) (buf + sizeof(struct ether_header));
			u_int8_t broadcast[6];
			char* broadcast_addr = "ff:ff:ff:ff:ff:ff";
			sscanf(broadcast_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &broadcast[0], &broadcast[1], &broadcast[2], &broadcast[3], &broadcast[4], &broadcast[5]);
			
			printf("ARP Received\n");
			if((ehead->ether_dhost[0] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0] || ehead->ether_dhost[1] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1] ||
				ehead->ether_dhost[2] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2] || ehead->ether_dhost[3] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3] ||
				ehead->ether_dhost[4] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4] || ehead->ether_dhost[5] != ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5]) &&
				(ehead->ether_dhost[0] != broadcast[0] || ehead->ether_dhost[1] != broadcast[1] ||
				ehead->ether_dhost[2] != broadcast[2] || ehead->ether_dhost[3] != broadcast[3] ||
				ehead->ether_dhost[4] != broadcast[4] || ehead->ether_dhost[5] != broadcast[5]))
			{
				printf("Ignoring...\n");
				continue;
			}
			char sip1[16]; 
			unsigned char sip2[4];
			strcpy(sip1, inet_ntoa(get_ip_saddr(ifname, sockfd)));
			sscanf(sip1, "%hhd.%hhd.%hhd.%hhd", &sip2[0], &sip2[1], &sip2[2], &sip2[3]);
			if(arp->ar_op == htons((short)1))
			{
				printf("ARP Request Received....\n");
				if(arp->ar_tip[0] == sip2[0] && arp->ar_tip[1] == sip2[1] && arp->ar_tip[2] == sip2[2] && arp->ar_tip[3] == sip2[3])
				{
					printf("Sender MAC Address = %x:%x:%x:%x:%x:%x\n", arp->ar_sha[0], arp->ar_sha[1], arp->ar_sha[2], 
						arp->ar_sha[3], arp->ar_sha[4], arp->ar_sha[5]);
					printf("Sender IP = %d.%d.%d.%d\n", arp->ar_sip[0], arp->ar_sip[1], arp->ar_sip[2], arp->ar_sip[3]);
					unsigned char res[6];
					send_arp(arp->ar_sha, ifname, arp->ar_sip, 2, res);
					printf("ARP Reply Sent....\n\n");
				}
			}
			if(arp->ar_op == htons((short)2))
			{
				printf("ARP Reply Received....\n");
				if(arp->ar_tip[0] == sip2[0] && arp->ar_tip[1] == sip2[1] && arp->ar_tip[2] == sip2[2] && arp->ar_tip[3] == sip2[3])
				{
					printf("Sender MAC Address = %x:%x:%x:%x:%x:%x\n", arp->ar_sha[0], arp->ar_sha[1], arp->ar_sha[2], 
						arp->ar_sha[3], arp->ar_sha[4], arp->ar_sha[5]);
					printf("Sender IP = %d.%d.%d.%d\n", arp->ar_sip[0], arp->ar_sip[1], arp->ar_sip[2], arp->ar_sip[3]);
				}
			}
		}
		
		else if(ehead->ether_type == htons(ETH_P_IP))
		{
			printf("Source = %x:%x:%x:%x:%x:%x\n", ehead->ether_shost[0], ehead->ether_shost[1], ehead->ether_shost[2], 
				ehead->ether_shost[3], ehead->ether_shost[4], ehead->ether_shost[5]);
			printf("Payload = ");
			for(int i = sizeof(struct ether_header) + sizeof(struct iphdr); i < recvLen; i++)
			{
				printf("%c", buf[i]);
			}
			printf("\n");
		}
	}
}

struct in_addr get_ip_saddr(char *if_name, int sockfd){
	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, if_name, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFADDR, &if_idx) < 0){
		perror("SIOCGIFADDR");
	}
	return ((struct sockaddr_in *)&if_idx.ifr_addr)->sin_addr;
}

struct in_addr get_netmask(char *if_name, int sockfd){
	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, if_name, IFNAMSIZ-1);
	if((ioctl(sockfd, SIOCGIFNETMASK, &if_idx)) == -1){
		perror("ioctl():");
	}
	return ((struct sockaddr_in *)&if_idx.ifr_netmask)->sin_addr;
}

void send_arp(char* addr1, char* ifname, char* destIp, short type, unsigned char* result)
{
	printf("Inside ARP Send\n");
	int sockfd, i, byteSent, tlen = 0;
	struct ifreq if_mac;
	struct ifreq if_idx;
	struct sockaddr_ll sk_addr;
	char sendbuf[BUF_SIZ];
	int sk_addr_size = sizeof(struct sockaddr_ll);
	struct in_addr addr;
	struct ether_header *ehead = (struct ether_header *) sendbuf;
	struct arp_hdr *arp = (struct arp_hdr *) (sendbuf + sizeof(struct ether_header));

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		printf("Socket() failed");

	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifname, IFNAMSIZ -1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0){
		perror("SIOCGIFINDEX");
	}
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifname, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0){
		perror("SIOCGIFHWADDR");
	}
	
	char sip1[16]; 
	unsigned char sip2[4];
	strcpy(sip1, inet_ntoa(get_ip_saddr(ifname, sockfd)));
	sscanf(sip1, "%hhd.%hhd.%hhd.%hhd", &sip2[0], &sip2[1], &sip2[2], &sip2[3]);
	
	sk_addr.sll_ifindex = if_idx.ifr_ifindex;
	sk_addr.sll_halen = ETH_ALEN;
	memcpy(sk_addr.sll_addr, addr1, 6);
	
	memset(sendbuf, 0, BUF_SIZ);
    memcpy(ehead->ether_shost, ((uint8_t *)&if_mac.ifr_hwaddr.sa_data), 6);
    memcpy(ehead->ether_dhost, addr1, 6);
	ehead->ether_type = htons(ETH_P_ARP);
	tlen += sizeof(struct ether_header);

	arp->ar_hrd = htons(1);
	arp->ar_pro = htons(ETH_P_IP);
	arp->ar_hln = 6;
	arp->ar_pln = 4;
	arp->ar_op = htons(type);
    memcpy(arp->ar_sha, ((uint8_t *)&if_mac.ifr_hwaddr.sa_data), 6);
	memcpy(arp->ar_tha, addr1, 6);
	memcpy(arp->ar_tip, destIp, 4);
	memcpy(arp->ar_sip, sip2, 4);
	tlen += sizeof(struct arp_hdr);

	byteSent = sendto(sockfd, sendbuf, tlen, 0,
		(struct sockaddr*)&sk_addr, sk_addr_size);
	printf("byteSent = %d\n", byteSent);
	if(type == 1)
	{
		printf("Listening For Reply!\n");
		recv_arp(ifname, result);
	}
}

void send_message(char* ifname, unsigned char* destIPRaw, unsigned char* routerIP, char* message)
{
	printf("Inside Send\n");
	int sockfd, i, byteSent, tlen = 0;
	struct ifreq if_mac;
	struct ifreq if_idx;
	struct sockaddr_ll sk_addr;
	char sendbuf[BUF_SIZ];
	unsigned char addr1[6];
	char hw_addr[6];
	struct ether_header *ehead = (struct ether_header *) sendbuf;
	struct iphdr *ip_hdr = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
	int sk_addr_size = sizeof(struct sockaddr_ll);
	unsigned char destIP[4];
	sscanf(destIPRaw, "%hhd.%hhd.%hhd.%hhd", &destIP[0], &destIP[1], &destIP[2], &destIP[3]);

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		printf("Socket() failed");

	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifname, IFNAMSIZ -1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0){
		perror("SIOCGIFINDEX");
	}
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifname, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0){
		perror("SIOCGIFHWADDR");
	}

	char sip1[16], nmask1[16]; 
	unsigned char sip2[4], nmask2[4], subnet1[4], subnet_dest[4];
	strcpy(nmask1, inet_ntoa(get_netmask(ifname, sockfd)));
	sscanf(nmask1, "%hhd.%hhd.%hhd.%hhd", &nmask2[0], &nmask2[1], &nmask2[2], &nmask2[3]);
	
	strcpy(sip1, inet_ntoa(get_ip_saddr(ifname, sockfd)));
	sscanf(sip1, "%hhd.%hhd.%hhd.%hhd", &sip2[0], &sip2[1], &sip2[2], &sip2[3]);
	for(int i = 0; i < 4; i++)
	{
		subnet1[i] = nmask2[i]&sip2[i];
	}
	for(int i = 0; i < 4; i++)
	{
		subnet_dest[i] = nmask2[i]&destIP[i];
	}
	char* broadcast_addr = "ff:ff:ff:ff:ff:ff";
	sscanf(broadcast_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &hw_addr[0], &hw_addr[1], &hw_addr[2], &hw_addr[3], &hw_addr[4], &hw_addr[5]);
	if(subnet_dest[0] == subnet1[0] && subnet_dest[1] == subnet1[1] && subnet_dest[2] == subnet1[2] && subnet_dest[3] == subnet1[3])
	{
		send_arp(hw_addr, ifname, destIP, 1, addr1);
		printf("Dest MAC Address = %x:%x:%x:%x:%x:%x\n", addr1[0], addr1[1], addr1[2], 
						addr1[3], addr1[4], addr1[5]);
	}
	else
	{
		send_arp(hw_addr, ifname, routerIP, 1, addr1);
		printf("Router MAC Address = %x:%x:%x:%x:%x:%x\n", addr1[0], addr1[1], addr1[2], 
						addr1[3], addr1[4], addr1[5]);
	}
	
	sk_addr.sll_ifindex = if_idx.ifr_ifindex;
	sk_addr.sll_halen = ETH_ALEN;
	memcpy(sk_addr.sll_addr, addr1, 6);

	memset(sendbuf, 0, BUF_SIZ);
    memcpy(ehead->ether_shost, ((uint8_t *)&if_mac.ifr_hwaddr.sa_data), 6);
    memcpy(ehead->ether_dhost, addr1, 6);
	ehead->ether_type = htons(ETH_P_IP);
	tlen += sizeof(struct ether_header);
	
	ip_hdr->version = 4;
	ip_hdr->ihl = 5;
	ip_hdr->check = 0;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + strlen(message));
	ip_hdr->ttl = 0xFF;
	ip_hdr->protocol = IPPROTO_TCP;
	ip_hdr->saddr = get_ip_saddr(ifname, sockfd).s_addr;
	ip_hdr->daddr = inet_addr(destIPRaw);
	tlen += sizeof(struct iphdr);
	
	for(i = 0; i < strlen(message); i++)
	{
		sendbuf[tlen+i] = message[i];
	}
	tlen += i;
	
	ip_hdr->check = ip_checksum(ip_hdr, 20);
	byteSent = sendto(sockfd, sendbuf, tlen, 0,
		(struct sockaddr*)&sk_addr, sk_addr_size);
	printf("byteSent = %d\n", byteSent);
	printf("message = %s\n", message);

}

int main(int argc, char *argv[])
{
	int mode;
	char hw_addr[6];
	unsigned char dest_ip[16];
	unsigned char router_ip[4];
	char interfaceName[IFNAMSIZ];
	char buf[BUF_SIZ];
	memset(buf, 0, BUF_SIZ);
	unsigned char res[6];
	
	int correct=0;
	if (argc > 1){
		if(strncmp(argv[1],"Send", 4)==0)
		{
			if (argc == 6)
			{
				mode=SEND; 
				strcpy(dest_ip, argv[3]);
				sscanf(argv[4], "%hhd.%hhd.%hhd.%hhd", &router_ip[0], &router_ip[1], &router_ip[2], &router_ip[3]);
				strncpy(buf, argv[5], BUF_SIZ);
				correct=1;
				printf("  buf: %s\n", buf);
			}
		}
		else if(strncmp(argv[1],"Recv", 4)==0)
		{
			if (argc == 3)
			{
				mode=RECV;
				correct=1;
			}
		}
	 }
	if(!correct)
	{
		fprintf(stderr, "./455_proj2 Send <InterfaceName> <DestIP> <RouterIP> <Message>\n");
		fprintf(stderr, "./455_proj2 Recv <InterfaceName>\n");
		exit(1);
	}

	strncpy(interfaceName, argv[2], IFNAMSIZ);

	if(mode == SEND)
	{
		send_message(interfaceName, dest_ip, router_ip, buf);
	}
	else if (mode == RECV)
	{
		recv_message(interfaceName);
	}
	return 0;
}