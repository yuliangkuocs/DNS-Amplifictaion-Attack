all: dnsAmplificationAttack.c dnsAmplificationAttack.h
	gcc dnsAmplificationAttack.c -o DnsAttack
clean:
	rm DnsAttack
