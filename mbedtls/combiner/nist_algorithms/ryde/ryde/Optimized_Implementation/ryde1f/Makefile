
SCRIPT_VERSION=v2.0
SCRIPT_AUTHOR=RYDE team

CC=gcc
C_FLAGS:=-O3 -flto -Wall -Wextra -Wno-unused-function -mpclmul -msse2 -mavx -mavx2 -maes -DOPT_AVX
C_FLAGS_VERBOSE:=-O3 -flto -Wall -Wextra -Wno-unused-function -mpclmul -msse2 -mavx -mavx2 -maes -DOPT_AVX -DVERBOSE

RANDOMBYTES_SRC:=lib/randombytes/randombytes.c
RANDOMBYTES_INCLUDE:=-I lib/randombytes -lcrypto

XKCP_SRC:=lib/XKCP
XKCP_SRC_SIMPLE:=$(XKCP_SRC)/SimpleFIPS202.c
XKCP_INCLUDE:=-I$(XKCP_SRC) -I$(XKCP_SRC)/avx2
XKCP_INCLUDE_SIMPLE:=-I $(XKCP_SRC)
XKCP_LINKER:=-L$(XKCP_SRC) -lshake

WRAPPER_SRC:=src/wrapper
WRAPPER_INCLUDE:=-I $(WRAPPER_SRC)

RBC_SRC:=src/rbc-53
RBC_INCLUDE:=-I $(RBC_SRC)

SRC:=src
INCLUDE:=-I src $(RBC_INCLUDE) $(WRAPPER_INCLUDE) $(XKCP_INCLUDE) $(RANDOMBYTES_INCLUDE)

MAIN_RYDE:=src/main.c
BENCH_RYDE:=src/bench.c
KAT_RYDE:=src/PQCgenKAT_sign.c

RYDE_OBJS:=rbc_53_elt.o rbc_53_vec.o rbc_53_vspace.o rbc_53_mat.o rbc_53_mat_fq.o keypair.o signature.o verification.o parsing.o ggm_tree.o sign.o
RYDE_OBJS_VERBOSE:=rbc_53_elt.o rbc_53_vec.o rbc_53_vspace.o rbc_53_mat.o rbc_53_mat_fq.o keypair-verbose.o signature-verbose.o verification-verbose.o parsing.o ggm_tree.o sign.o
LIB_OBJS:=SimpleFIPS202.o randombytes.o

BUILD:=bin/build
BIN:=bin



folders:
	@echo -e "\n### Creating build folders\n"
	mkdir -p $(BUILD)

randombytes.o: folders
	@echo -e "\n### Compiling $@\n"
	$(CC) $(C_FLAGS) -c $(RANDOMBYTES_SRC) $(RANDOMBYTES_INCLUDE) -o $(BUILD)/$@

SimpleFIPS202.o: folders
	@echo -e "\n### Compiling $@\n"
	$(CC) $(C_FLAGS) -c $(XKCP_SRC_SIMPLE) $(XKCP_INCLUDE_SIMPLE) $(XKCP_INCLUDE) $(XKCP_LINKER) -o $(BUILD)/SimpleFIPS202.o

xkcp: folders
	@echo -e "\n### Compiling XKCP\n"
	make -C $(XKCP_SRC)



rbc_%.o: $(RBC_SRC)/rbc_%.c | folders
	@echo -e "\n### Compiling $@\n"
	$(CC) $(C_FLAGS) -c $< $(RBC_INCLUDE) $(WRAPPER_INCLUDE) $(XKCP_INCLUDE) -o $(BUILD)/$@

%.o: $(SRC)/%.c | folders
	@echo -e "\n### Compiling $@\n"
	$(CC) $(C_FLAGS) -c $< $(INCLUDE) -o $(BUILD)/$@

 %-verbose.o: $(SRC)/%.c | folders
	@echo -e "\n### Compiling $@ (verbose mode)\n"
	$(CC) $(C_FLAGS_VERBOSE) -c $< $(INCLUDE) -o $(BUILD)/$@


tcith-rijndael.o: $(SRC)/tcith.c | folders
	@echo -e "\n### Compiling $@\n"
	$(CC) $(C_FLAGS) -c $< $(INCLUDE) -o $(BUILD)/$@

tcith-sha3.o: $(SRC)/tcith.c | folders
	@echo -e "\n### Compiling $@\n"
	$(CC) $(C_FLAGS) -D_RYDE_SHA3_ -c $< $(INCLUDE) -o $(BUILD)/$@



all: ryde1f-rijndael-main ryde1f-rijndael-bench ryde1f-rijndael-kat ryde1f-rijndael-verbose ryde1f-sha3-main ryde1f-sha3-bench ryde1f-sha3-kat ryde1f-sha3-verbose ##@Build Build all the project

.PHONY: ryde1f-rijndael-main
ryde1f-rijndael-main: $(RYDE_OBJS) tcith-rijndael.o $(LIB_OBJS) | xkcp folders ##@Build A single example using Rijndael-based commits
	@echo -e "\n### Compiling RYDE-1F (main) using Rijndael-based commits\n"
	$(CC) $(C_FLAGS) $(MAIN_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: ryde1f-sha3-main
ryde1f-sha3-main: $(RYDE_OBJS) tcith-sha3.o $(LIB_OBJS) | xkcp folders ##@Build A single example using SHA3-based commits
	@echo -e "\n### Compiling RYDE-1F (main) using SHA3-based commits\n"
	$(CC) $(C_FLAGS) -D_RYDE_SHA3_ $(MAIN_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: ryde1f-rijndael-bench
ryde1f-rijndael-bench: $(RYDE_OBJS) tcith-rijndael.o $(LIB_OBJS) | xkcp folders ##@Build Benchmarks using Rijndael-based commits
	@echo -e "\n### Compiling RYDE-1F (benchmark) using Rijndael-based commits\n"
	$(CC) $(C_FLAGS) $(BENCH_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: ryde1f-sha3-bench
ryde1f-sha3-bench: $(RYDE_OBJS) tcith-sha3.o $(LIB_OBJS) | xkcp folders ##@Build Benchmarks using SHA3-based commits
	@echo -e "\n### Compiling RYDE-1F (benchmark) using SHA3-based commits\n"
	$(CC) $(C_FLAGS) -D_RYDE_SHA3_ $(BENCH_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: ryde1f-rijndael-kat
ryde1f-rijndael-kat: $(RYDE_OBJS) tcith-rijndael.o $(LIB_OBJS) | xkcp folders ##@Build Generate KAT files using Rijndael-based commits: PQCsignKAT_XX.req and PQCsignKAT_XX.rsp
	@echo -e "\n### Compiling RYDE-1F (KATs) using Rijndael-based commits\n"
	$(CC) $(C_FLAGS) $(KAT_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: ryde1f-sha3-kat
ryde1f-sha3-kat: $(RYDE_OBJS) tcith-sha3.o $(LIB_OBJS) | xkcp folders ##@Build Generate KAT files using SHA3-based commits: PQCsignKAT_XX.req and PQCsignKAT_XX.rsp
	@echo -e "\n### Compiling RYDE-1F (KATs) using SHA3-based commits\n"
	$(CC) $(C_FLAGS) -D_RYDE_SHA3_ $(KAT_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: ryde1f-rijndael-verbose
ryde1f-rijndael-verbose: $(RYDE_OBJS_VERBOSE) tcith-rijndael.o $(LIB_OBJS) | xkcp folders ##@Build Generate intermediate values of a single example using Rijndael-based commits
	@echo -e "\n### Compiling RYDE-1F (verbose mode) using Rijndael-based commits\n"
	$(CC) $(C_FLAGS_VERBOSE) $(MAIN_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: ryde1f-sha3-verbose
ryde1f-sha3-verbose: $(RYDE_OBJS_VERBOSE) tcith-sha3.o $(LIB_OBJS) | xkcp folders ##@Build Generate intermediate values of a single example using SHA3-based commits
	@echo -e "\n### Compiling RYDE-1F (verbose mode) using SHA3-based commits\n"
	$(CC) $(C_FLAGS_VERBOSE) -D_RYDE_SHA3_ $(MAIN_RYDE) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(XKCP_LINKER) -o $(BIN)/$@

.PHONY: clean
clean: ##@Miscellaneous Clean data
	make -C $(XKCP_SRC) clean
	rm -f PQCsignKAT_*
	rm -f vgcore.*
	rm -rf ./bin



.PHONY: help
HELP_FUN = \
    %help; while(<>){push@{$$help{$$2//'options'}},[$$1,$$3] \
    if/^([\w-_]+)\s*:.*\#\#(?:@(\w+))?\s(.*)$$/}; \
    print"$$_:\n", map"  \033[37m$$_->[0]\033[0m".(" "x(25-length($$_->[0])))."$$_->[1]\n",\
    @{$$help{$$_}},"\n" for keys %help; \

help: ##@Miscellaneous Show this help
	@echo -e "Usage: make [target] ..."
	@perl -e '$(HELP_FUN)' $(MAKEFILE_LIST)
	@echo -e "Written by \033[36m$(SCRIPT_AUTHOR)\033[0m, version \033[37m$(SCRIPT_VERSION)\033[0m"
	@echo -e "Please report any bug or error to the authors."
