#pragma pack(1)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>

// Typedef the iphdr and udphdr from the netinet libs to prevent 
// an infestation of "struct" in all the checksum and size calculations
typedef struct iphdr iph;
typedef struct udphdr udph;


// Pseudoheader struct
typedef struct
{
    u_int32_t saddr;
    u_int32_t daddr;
    u_int8_t filler;
    u_int8_t protocol;
    u_int16_t len;
}psHeader;

// DNS header struct
typedef struct
{
	unsigned short id; 		// ID
	unsigned short flags;	// DNS Flags
	unsigned short qcount;	// Question Count
	unsigned short ans;		// Answer Count
	unsigned short auth;	// Authority RR
	unsigned short add;		// Additional RR
}dnsHeader;

// Question types
typedef struct
{
	unsigned short qtype;
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
