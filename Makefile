all: main.c dns.c dns.h
	gcc main.c dns.c
clean:
	rm a.out
