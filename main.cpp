#include <pcap.h>
#include <libnet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define PACKET_SIZE 42

struct tmp_ip{
	uint8_t sender_mac[6];
	uint8_t sender_ip[4];
	uint8_t target_mac[6];
	uint8_t target_ip[4];
};

void usage(void){
	printf("./main <victim's ip>\n");
}

void print_mac(char * mac);
void get_victim_mac(char * mydev, 
	char * victim_ip,char * victim_mac,
	char * my_ip, char * my_mac);

int main(int argc, char * argv[]){

	char * mydev = 0;
	char victim_mac[6] = {};

	if (argc != 2) {
		usage();
		exit(1);
	}

	char victim_ip[20];
	strncpy(victim_ip,argv[1],18);

	printf("Victim's IP : %s\n", victim_ip);

	mydev = pcap_lookupdev(NULL);
	if (mydev==NULL){
		puts("pcap_lookupdev ERROR!");
		exit(1);
	}
	printf("My Dev : %s\n", mydev);

	pcap_if_t * alldevs;

	if (pcap_findalldevs(
			&alldevs,
			NULL) != 0
		)
	{
		puts("pcap_findalldevs ERROR!");
		exit(1);
	}

	char my_ip[20];
	char my_mac[6];
	int tmp=0;

	for(pcap_if_t * i = alldevs; i != NULL; i=i->next){
		if(strcmp(i->name,mydev)!=0)continue;

		for(pcap_addr_t * j=i->addresses; j!=NULL; j=j->next){
			if ( (j->addr->sa_family != AF_INET) && (j->addr->sa_family != AF_LINK))
				continue;

			if (j->addr->sa_family == AF_INET){
				strncpy(
					my_ip,
					inet_ntoa(((struct sockaddr_in*)j->addr)->sin_addr),
					18);
				tmp++;
			}else{
				char * mac_addr = (char *)j->addr->sa_data;
				mac_addr += 9;
				memcpy(my_mac, mac_addr, 6);
				tmp++;
			}
			if (tmp==2)break;
		}
		break;
	}

	pcap_freealldevs(alldevs);

	printf("My IP : %s\n",my_ip);
	printf("My Mac : ");
	print_mac(my_mac);

	
	get_victim_mac(
		mydev,
		victim_ip,
		victim_mac,
		my_ip,
		my_mac);

	
	

}
void get_victim_mac(char * mydev, 
	char * victim_ip,char * victim_mac,
	char * my_ip, char * my_mac){

	struct libnet_ethernet_hdr * eth_hdr = 0;
	pcap_t * handler;
	char packet_s[PACKET_SIZE+1]={};
	const unsigned char * packet_r=0;
	struct libnet_arp_hdr * arp_hdr;


	putchar(10);
	puts("-----------------------");
	puts("Getting Victim's Mac address...");

	if((handler = pcap_open_live(mydev,1000,1,1000,NULL))==NULL){
		puts("pcap_open_live ERROR!");
		exit(1);
	}

	eth_hdr = (struct libnet_ethernet_hdr *)packet_s;

	memset(eth_hdr->ether_dhost,'\xff',6);
	memcpy(eth_hdr->ether_shost,my_mac,6);
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);

	arp_hdr = (libnet_arp_hdr *)((char *)eth_hdr + 
		sizeof(struct libnet_ethernet_hdr));

	arp_hdr->ar_hrd = htons(ARPHRD_ETHER);
	arp_hdr->ar_pro = htons(0x0800); //ipv4
	arp_hdr->ar_hln = 6;
	arp_hdr->ar_pln = 4;
	arp_hdr->ar_op = htons(ARPOP_REQUEST);

	struct tmp_ip *ip_info = (struct tmp_ip *)((char *)arp_hdr + 
		sizeof(struct libnet_arp_hdr));

	memcpy(ip_info->sender_mac,my_mac,6);
	inet_pton(AF_INET, my_ip, &ip_info->sender_ip);
	memcpy(ip_info->target_mac,victim_mac,6);
	inet_pton(AF_INET, victim_ip,&ip_info->target_ip);

	if(pcap_sendpacket(handler,(const u_char *)packet_s,42)==-1){
		puts("pcap_sendpacket Error!");
		exit(1);
	}

	struct pcap_pkthdr pkthdr;
	while(1){
		packet_r = pcap_next(handler,&pkthdr);
		if(packet_r==NULL){
			puts("pcap_next Error!");
			exit(1);
		}
		eth_hdr = (struct libnet_ethernet_hdr *)packet_r;
		arp_hdr = (libnet_arp_hdr *)((char *)eth_hdr + 
			sizeof(struct libnet_ethernet_hdr));
		if((eth_hdr->ether_type == htons(ETHERTYPE_ARP)) &&
			(arp_hdr->ar_op == htons(ARPOP_REPLY))) 
			break;
	}

	
	ip_info = (struct tmp_ip *)((char *)arp_hdr + 
		sizeof(struct libnet_arp_hdr));

	puts("Got Victim's Mac address!!");
	puts("-----------------------");
	putchar(10);

	printf("Victim's Mac : ");
	print_mac((char *)ip_info->sender_mac);

	memcpy(victim_mac,ip_info->sender_mac,6);

}
void print_mac(char * mac){
	printf("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
		mac[0],mac[1],mac[2],
		mac[3],mac[4],mac[5]);
}