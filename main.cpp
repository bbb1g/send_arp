#include <pcap.h>
#include <libnet.h>
#include <stdio.h>
#include <string.h>

#define PACKET_SIZE 42

void usage(void){
	printf("./main <victim's ip>\n");
}


int main(int argc, char * argv[]){

	char * mydev = 0;
	char my_mac[6] = {0x4c,0x32,0x75,0x95,0x95,0xed};
	char victim_mac[6] = {};
	struct libnet_arp_hdr * packet_s = 0;
	struct libnet_arp_hdr * packet_r = 0;
	struct in_addr adr;

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

	for(pcap_if_t * i = alldevs; i != NULL; i=i->next){
		if(strcmp(i->name,mydev)!=0)continue;

		for(pcap_addr_t * j=i->addresses; j!=NULL; j=j->next){
			if(j->addr->sa_family != AF_INET)continue;
			strncpy(
			my_ip,
			inet_ntoa(((struct sockaddr_in*)j->addr)->sin_addr),
			18
			);
			break;
		}
		break;
	}

	printf("My IP : %s\n",my_ip);
	//get_victim_mac(victim_ip, victim_mac);

}