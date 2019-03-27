#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#pragma pack(1)

typedef struct iphdr ipHeader;
typedef struct udphdr udpHeader;


typedef struct
{
    u_int32_t saddr;
    u_int32_t daddr;
    u_int8_t filler;
    u_int8_t protocol;
    u_int16_t len;
}psHeader;

typedef struct
{
	unsigned short id;
	unsigned short flags;
	unsigned short qusCount;
	unsigned short ansCount;
	unsigned short authCount;
	unsigned short addRecordCount;
}dnsHeader;

typedef struct
{
	unsigned short type;
	unsigned short qclass;
}query;

typedef struct
{
	unsigned char name;
	unsigned short type;
	unsigned short udpPayloadSize;
	unsigned char higherBits;
	unsigned char eDnsVersion;
	unsigned short z;
	unsigned short dataLength;
} eDnsHeader;

