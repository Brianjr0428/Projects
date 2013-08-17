CC = gcc
all: portScanner
portScanner: portScanner.o scanner.o
	$(CC) -o portScanner portScanner.o scanner.o -lpthread -lm
portScanner.o: portScanner.c scanner.h scanner.c portScanner.h
	$(CC) -c portScanner.c
scanner.o: portScanner.c scanner.h scanner.c portScanner.h
	$(CC) -c scanner.c

clean:
	rm -f *.o
	rm -f portScanner

