#include <pcap.h>
#include <libnet.h>

int main(int argc, char * argv[]){
	char * mydev = 0;

	mydev = pcap_lookupdev(NULL);

	printf("My Dev : %s\n", mydev);
}