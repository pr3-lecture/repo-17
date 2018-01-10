.PHONY: all clean runtest
all: crypto
clean:
	rm -f crypto.o cryptoTest.o Main.o decrypt encrypt test
crypto.o: crypto.c
	gcc -Wall -c crypto.c
cryptoTest.o: cryptoTest.c
	gcc -Wall -c cryptoTest.c
Main.o: Main.c
	gcc -Wall -c Main.c
crypto: crypto.o Main.o
	gcc -o encrypt crypto.o Main.o
	gcc -o decrypt crypto.o Main.o
runtest: crypto.o cryptoTest.o
	gcc -o test cryptoTest.o crypto.o
	./test