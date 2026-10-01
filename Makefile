CXXFLAGS = -O3 -g0
LDFLAGS = $(CXXFLAGS)

dnsseed: dns.o bitcoin.o bitcoin_core/netbase.o bitcoin_core/protocol.o db.o main.o bitcoin_core/util.o bitcoin_core/util/serfloat.o
	g++ -pthread $(LDFLAGS) -o dnsseed dns.o bitcoin.o bitcoin_core/netbase.o bitcoin_core/protocol.o db.o main.o bitcoin_core/util.o bitcoin_core/util/serfloat.o -lcrypto

%.o: %.cpp *.h bitcoin_core/*.h bitcoin_core/*/*.h
	g++ -std=c++20 -pthread -Ibitcoin_core $(CXXFLAGS) -Wall -Wno-unused -Wno-sign-compare -Wno-reorder -Wno-comment -c -o $@ $<
