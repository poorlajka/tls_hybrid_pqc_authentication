LDLIBS=-lcrypto
CC = /usr/bin/gcc
CFLAGS = -Wall -Wextra -Wpedantic -O3 -std=c99 -march=native -fomit-frame-pointer -flto

THASH = simple

SOURCES =          hash_sha256.c hash_sha256x8.c thash_sha256_$(THASH).c thash_sha256_$(THASH)x8.c sha256.c sha256x8.c sha256avx.c address.c rng.c wots.c utils.c utilsx8.c fors.c sign.c
HEADERS = params.h hash.h        hashx8.h        thash.h                 thashx8.h               sha256.h sha256x8.h sha256avx.h address.h rng.h wots.h utils.h utilsx8.h fors.h api.h

DET_SOURCES = $(SOURCES:rng.%=rng.%)
DET_HEADERS = $(HEADERS:rng.%=rng.%)

TESTS = test/wots \
		test/fors \
		test/spx \
		test/thashx8 \

BENCHMARK = test/benchmark

#.PHONY: clean test benchmark

default: PQCgenKAT_sign

all: PQCgenKAT_sign tests benchmarks

tests: $(TESTS)

test: $(TESTS:=.exec)

benchmarks: $(BENCHMARK)

benchmark: $(BENCHMARK:=.exec)

PQCgenKAT_sign: PQCgenKAT_sign.c $(DET_SOURCES) $(DET_HEADERS)
	$(CC) $(CFLAGS) -c $(DET_SOURCES) $< -lcrypto

test/%: test/%.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

test/%.exec: test/%
	@$<

clean:
	-$(RM) $(TESTS)
	-$(RM) $(BENCHMARK)
	-$(RM) *.o
	-$(RM) PQCsignKAT_*.rsp
	-$(RM) PQCsignKAT_*.req
