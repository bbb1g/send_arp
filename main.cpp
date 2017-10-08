#include <pcap.h>
#include <libnet.h>

#define PACKET_SIZE 42

void usage(void){
	printf("./main <victim's ip>\n");
}

int main(int argc, char * argv[]){

	char * mydev = 0;
	char my_mac[6] = {0x4c,0x32,0x75,0x95,0x95,0xed};

	if (argc != 2) {
		usage();
		exit(1);
	}

	char * victim_ip = argv[1];

	printf("Victim's IP : %s\n", victim_ip);

	mydev = pcap_lookupdev(NULL);
	if (mydev==NULL){
		puts("pcap_lookupdev ERROR!");
		exit(1);
	}
	printf("My Dev : %s\n", mydev);
}