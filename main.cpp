#include <pcap.h>
#include <libnet.h>
#include <stdio.h>
#include <string.h>

#define PACKET_SIZE 42

void usage(void){
	printf("./main <victim's ip>\n");
}

void print_mac(char * mac);

int main(int argc, char * argv[]){

	char * mydev = 0;
	char victim_mac[6] = {};
	struct libnet_arp_hdr * packet_s = 0;
	struct libnet_arp_hdr * packet_r = 0;

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

	/*
	get_victim_mac(
		victim_ip,
		victim_mac
		my_ip
		my_mac);
	*/

}

void print_mac(char * mac){
	printf("%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
		mac[0],mac[1],mac[2],
		mac[3],mac[4],mac[5]);
}