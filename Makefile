dnsseed: dns.o bitcoin.cpp netbase.cpp protocol.cpp db.cpp main.cpp bitcoin.h netbase.h protocol.h db.h serialize.h uint256.h util.h
	g++ -pthread -lssl -O3 -ggdb3 -march=nocona -Wno-invalid-offsetof -o dnsseed bitcoin.cpp netbase.cpp protocol.cpp db.cpp main.cpp dns.o

dns.o: dns.c
	gcc -std=c99 -O3 -g0 -march=nocona dns.c -c -o dns.o

