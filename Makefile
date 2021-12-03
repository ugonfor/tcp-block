CC=g++
LDLIBS+=-lpcap

all: tcp-block

tcp-block: main.o tcp-block.o

tcp-block.o:
	g++ -c -o tcp-block.o tcp-block.cpp -std=c++17

clean:
	rm -f *.o tcp-block