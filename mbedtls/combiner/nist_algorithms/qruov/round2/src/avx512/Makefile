PLATFORM=avx512
CC=gcc
CFLAGS=-march=native -mtune=native -O3 -fomit-frame-pointer -fwrapv -fPIC -fPIE -fopenmp -Wno-deprecated-declarations -Wno-unused-result # -ggdb3 # -DQRUOV_PRG_SHAKE
LDFLAGS=-lcrypto -Wl,-Bstatic -lcrypto -Wl,-Bdynamic -lm
# CFLAGS=-march=native -mtune=native -O3 -fwrapv -fPIC -fPIE -fopenmp -Wno-deprecated-declarations -Wno-unused-result -pg -g # -ggdb3
# LDFLAGS=-lcrypto -Wl,-Bstatic -lcrypto -Wl,-Bdynamic -lm -pg -g
OBJS=Fql.o PQCgenKAT_sign.o qruov.o rng.o sign.o matrix.o mgf.o

.SUFFIXES:
.SUFFIXES: .rsp .req .diff .c .o .h

.PHONY: all clean

all: qruov_config.h api.h PQCgenKAT_sign
	bash -c "time ./PQCgenKAT_sign"

PQCgenKAT_sign: Makefile ${OBJS}
	${CC} ${OBJS} ${CFLAGS} ${LDFLAGS} -o $@

qruov_config.h: qruov_config_h_gen.c
	${CC} @qruov_config.txt -DQRUOV_PLATFORM=${PLATFORM} -DQRUOV_CONFIG_H_GEN ${CFLAGS} ${LDFLAGS} qruov_config_h_gen.c
	./a.out > qruov_config.h
	rm a.out

api.h: api_h_gen.c
	${CC} -DAPI_H_GEN ${CFLAGS} ${LDFLAGS} api_h_gen.c
	./a.out > api.h
	rm a.out

clean:
	rm -f PQCgenKAT_sign PQCsignKAT_*.req PQCsignKAT_*.rsp ${OBJS}
