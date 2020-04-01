#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>

#define BUF_SIZ		65536

struct arp_hdr {
	uint16_t 	ar_hrd;
	uint16_t 	ar_pro;
	uint8_t 	ar_hln;
	uint8_t 	ar_pln;
	uint16_t 	ar_op;
	uint8_t		ar_sha[6];
	uint8_t 	ar_sip[4];
	uint8_t 	ar_tha[6];
	uint8_t 	ar_tip[4];
};

int is_broadcast(struct ether_header *eth_hdr){
	if (eth_hdr->ether_dhost[0] == 0xff &&
		eth_hdr->ether_dhost[1] == 0xff &&
 		eth_hdr->ether_dhost[2] == 0xff &&
 		eth_hdr->ether_dhost[3] == 0xff &&
		eth_hdr->ether_dhost[4] == 0xff &&
		eth_hdr->ether_dhost[5] == 0xff)
		return 1;
	else
		return 0;
}

uint32_t get_ip_saddr(int8_t *if_name, int32_t sockfd){ 
	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(struct ifreq)); 
	strncpy(if_idx.ifr_name, if_name, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFADDR, &if_idx) < 0) 
		perror("SIOCGIFADDR");
	return ((struct sockaddr_in *)&if_idx.ifr_addr)->sin_addr.s_addr; 
}

void get_hw_saddr(int8_t *hw_addr, int8_t *if_name, int32_t sockfd){
	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, if_name, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_idx) < 0)
	    perror("SIOCGIFHWADDR");
	memcpy(hw_addr, if_idx.ifr_hwaddr.sa_data, 6);
}

void send_ether(int32_t sockfd, int8_t *if_name, struct arp_hdr *ah, uint32_t pyld_len){
	uint32_t tot_len = pyld_len + sizeof(struct ether_header);
	int8_t buf[tot_len];
	memset(buf, 0, tot_len);
	
	struct sockaddr_ll socket_address;
	uint32_t socket_address_size = sizeof(struct sockaddr_ll);
	memset(&socket_address, 0, socket_address_size);

	struct ifreq if_idx;
	strncpy(if_idx.ifr_name, if_name, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;

	struct ether_header *eth_hdr = (struct ether_header *) buf;
	memset(eth_hdr->ether_dhost, 0xff, 6); 
    	get_hw_saddr(eth_hdr->ether_shost, if_name, sockfd);
	eth_hdr->ether_type = htons(ETH_P_ARP);
	memcpy(buf+sizeof(struct ether_header), ah, sizeof(struct arp_hdr));
	
	if(sendto(sockfd, buf, tot_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0){
	    printf("Send failed\n");
	    return; 
	}
}

void send_arp_rqst(int32_t sockfd, int8_t *interfaceName, int8_t *dst_IP){
	struct arp_hdr ah; 
	uint32_t len =  sizeof(struct arp_hdr);
	ah.ar_hrd = htons(1);
	ah.ar_pro = htons(ETH_P_IP);
	ah.ar_hln = 6;
	ah.ar_pln = 4;
	ah.ar_op = htons(1); 
	get_hw_saddr((int8_t *)&ah.ar_sha, interfaceName, sockfd);
	*((int32_t*) ah.ar_sip) = get_ip_saddr(interfaceName, sockfd);
	memset(ah.ar_tha, 0, 6);
	memcpy(ah.ar_tip, dst_IP, 4); 
	send_ether(sockfd, interfaceName, &ah, len);
}


void *recv_eth(int32_t sockfd, int8_t *hw_addr, int8_t *buf, uint16_t type, uint32_t *pyld_len){
	struct ether_header *eth_hdr;
	struct arp_hdr *ah; 
	struct sockaddr_ll socket_address;
	uint32_t socket_address_size = sizeof(struct sockaddr_ll);
	memset(&socket_address, 0, socket_address_size);

	uint32_t recvLen; 
	while(1){
		recvLen = recvfrom(sockfd, buf, BUF_SIZ, 0, (struct sockaddr*)&socket_address, &socket_address_size );
		if (recvLen < 0){
		    printf("Recv failed\n");
			continue;
		}
	   	eth_hdr = (struct ether_header *) buf;
		if (memcmp(hw_addr, eth_hdr->ether_dhost, 6)!=0 || is_broadcast(eth_hdr)){
		    	printf("Wrong HW addr\n");
				continue;
	    	}
		if(ntohs(eth_hdr->ether_type)!=type){
			printf("Not type %x\n", type);
			continue;
		}
		*((uint32_t*)pyld_len) = recvLen + sizeof(struct ether_header);
		return buf + sizeof(struct ether_header);
	}
}

void recv_arp(uint32_t sockfd, int8_t *interfaceName, int8_t *dst_ip){
	int8_t buf[BUF_SIZ];
	uint32_t pyld_len;
	uint16_t type = ETH_P_ARP;
	int8_t shw_addr[6]; 
	get_hw_saddr((int8_t *)&shw_addr, interfaceName, sockfd);
	struct arp_hdr *ah;

	while(1){
		memset(buf, 0, BUF_SIZ);
		ah = (struct arp_hdr *) recv_eth(sockfd, (int8_t *)&shw_addr, (int8_t *) &buf, type, (uint32_t *)&pyld_len);
		if(memcmp(shw_addr, ah->ar_tha, 6) == 0 ||
		   memcmp(dst_ip, ah->ar_sip, 4)){
			printf(" Dst HW Addr: %0x:%0x:%0x:%0x:%0x:%0x\n",
				(uint8_t)ah->ar_sha[0], (uint8_t)ah->ar_sha[1], (uint8_t)ah->ar_sha[2],
        		(uint8_t)ah->ar_sha[3], (uint8_t)ah->ar_sha[4], (uint8_t)ah->ar_sha[5]);
			return;
		}
	}
}

int32_t main(int argc, int8_t *argv[])
{
	int32_t sockfd;
	int32_t mode;
	int8_t interfaceName[IFNAMSIZ];
	struct in_addr addr;
	
	if (argc > 1){
		strncpy(interfaceName, argv[1], IFNAMSIZ);
		inet_aton(argv[2], &addr); 
	 }
	 else{
		fprintf(stderr, "./455_proj2 <InterfaceName> <IPAddr>\n");
		exit(1);
	 }

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
	    perror("socket");
	}

	send_arp_rqst(sockfd, interfaceName, (int8_t *) &addr.s_addr);
	recv_arp(sockfd, interfaceName, (int8_t *) &addr.s_addr);
	return 0;
}



