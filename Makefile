all: main.c dns.c dns.h
	gcc dns.c
clean:
	rm a.out
