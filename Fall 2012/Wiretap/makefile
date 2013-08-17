CC = gcc
all: wiretap

wiretap: wiretap.c
	$(CC) -o wiretap wiretap.c -lpcap

clean:
	rm -f *.o
	rm -f wiretap
