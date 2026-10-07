CXXFLAGS = -O3 -g0
LDFLAGS = $(CXXFLAGS)

dnsseed: dns.o bitcoin.o bitcoin_core/netbase.o bitcoin_core/protocol.o db.o main.o bitcoin_core/util.o http_filter.o tcp_probe.o
	g++ -pthread $(LDFLAGS) -o dnsseed dns.o bitcoin.o bitcoin_core/netbase.o bitcoin_core/protocol.o db.o main.o bitcoin_core/util.o http_filter.o tcp_probe.o -lcrypto

test-http-probe: tests/http_probe.cpp tcp_probe.cpp tcp_probe.h
	g++ -std=c++20 -pthread -I. -Ibitcoin_core -o $@ tests/http_probe.cpp tcp_probe.cpp
	./$@

test-http-filter: tests/http_filter_db.cpp db.o bitcoin_core/netbase.o bitcoin_core/protocol.o bitcoin_core/util.o
	g++ -std=c++20 -pthread -I. -Ibitcoin_core -o $@ tests/http_filter_db.cpp db.o bitcoin_core/netbase.o bitcoin_core/protocol.o bitcoin_core/util.o -lcrypto
	./$@

test-http-proxy-route: tests/http_proxy_route.cpp http_filter.o tcp_probe.o bitcoin_core/netbase.o bitcoin_core/protocol.o bitcoin_core/util.o
	g++ -std=c++20 -pthread -I. -Ibitcoin_core -o $@ tests/http_proxy_route.cpp http_filter.o tcp_probe.o bitcoin_core/netbase.o bitcoin_core/protocol.o bitcoin_core/util.o -lcrypto
	./$@

%.o: %.cpp *.h bitcoin_core/*.h bitcoin_core/*/*.h
	g++ -std=c++20 -pthread -Ibitcoin_core $(CXXFLAGS) -Wall -Wno-unused -Wno-sign-compare -Wno-reorder -Wno-comment -c -o $@ $<
