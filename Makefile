all: dns.c dns.h
	gcc -o DnsAmplificationAttack dns.c
clean:
	rm DnsAmplificationAttack
