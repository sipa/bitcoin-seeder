CXXFLAGS = -O3 -g0
CFLAGS = -O2 -g0
LDFLAGS = $(CXXFLAGS)

OBJS = dns.o bitcoin.o netbase.o protocol.o db.o main.o util.o crypto/sha256.o

# libsecp256k1 (in the secp256k1/ subtree), built with the ElligatorSwift module (needed for BIP324),
# and its default table sizes.
SECP256K1_OBJS = secp256k1/src/secp256k1.o secp256k1/src/precomputed_ecmult.o secp256k1/src/precomputed_ecmult_gen.o
SECP256K1_CFLAGS = -Isecp256k1/include -DENABLE_MODULE_ELLSWIFT=1 -DECMULT_WINDOW_SIZE=15 -DCOMB_BLOCKS=43 -DCOMB_TEETH=6

dnsseed: $(OBJS) $(SECP256K1_OBJS)
	g++ -pthread $(LDFLAGS) -o dnsseed $(OBJS) $(SECP256K1_OBJS)

%.o: %.cpp *.h compat/*.h crypto/*.h
	g++ -std=c++20 -pthread -I. -Isecp256k1/include $(CXXFLAGS) -Wall -Wno-unused -Wno-sign-compare -Wno-reorder -Wno-comment -c -o $@ $<

secp256k1/src/%.o: secp256k1/src/%.c
	gcc $(CFLAGS) $(SECP256K1_CFLAGS) -c -o $@ $<

clean:
	rm -f dnsseed $(OBJS) $(SECP256K1_OBJS)

.PHONY: clean
