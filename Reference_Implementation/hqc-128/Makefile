
CC:=gcc
RNG_FLAGS:=-Wno-unused-but-set-variable -Wno-unused-parameter -Wno-sign-compare
CFLAGS:=-O3 -std=c99 -mavx -mavx2 -pedantic ${RNG_FLAGS} 

HASH_SRC:=lib/hash/hash.c
HASH_INCLUDE:=-I lib/hash -lcrypto

RNG_SRC:=lib/rng/rng.c
RNG_INCLUDE:=-I lib/rng
 
SRC:=src/
INCLUDE:=-I src/
LIB:=$(HASH_INCLUDE) $(RNG_INCLUDE)

#MAIN_HQC:=src/main_hqc.c
MAIN_KAT:=src/main_kat.c
MAIN_SERVER:=src/server.c
MAIN_CLIENT:=src/client.c
MAIN_TEST:=src/test.c
MAIN_SERVER2:=src/server2.c
MAIN_CLIENT2:=src/client2.c
MAIN_BENCH1:=src/benchmark.c
MAIN_BENCH2:=src/benchmark2.c

HQC_OBJS:=vector.o repetition.o bch.o gf2x_avx2.o tensor.o parsing.o hqc.o kem.o
HQC_OBJS_VERBOSE:=vector.o repetition.o bch-verbose.o gf2x_avx2.o tensor-verbose.o parsing.o hqc-verbose.o kem-verbose.o 
LIB_OBJS:= hash.o rng.o

BIN:=bin
BUILD:=bin/build


folders:
	@echo -e "\n### Creating folders\n"
	mkdir -p $(BUILD)

hash.o: folders
	@echo -e "\n### Compiling $@ (wrapper around openssl SHA512 implementation)\n"	
	$(CC) $(CFLAGS) -c $(HASH_SRC) $(HASH_INCLUDE) -o $(BUILD)/$@

rng.o: folders
	@echo -e "\n### Compiling NIST rng.o\n"	
	$(CC) -O3 -c $(RNG_SRC) $(RNG_INCLUDE) -o $(BUILD)/$@



%.o: $(SRC)/%.c | folders
	@echo -e "\n### Compiling $@\n"
	$(CC) $(CFLAGS) -c $< $(INCLUDE) $(LIB) -o $(BUILD)/$@ 

%-verbose.o: $(SRC)/%.c | folders
	@echo -e "\n### Compiling $@ (verbose mode)\n"
	$(CC) $(CFLAGS) -c $< $(INCLUDE) $(LIB) -D VERBOSE -o $(BUILD)/$@



hqc-128-1: $(HQC_OBJS) $(LIB_OBJS)
	@echo -e "\n### Compiling HQC-128-1\n"	
	$(CC) $(CFLAGS) $(MAIN_SERVER) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -o $(BIN)/$@ 

hqc-128-1-client: $(HQC_OBJS) $(LIB_OBJS)
	@echo -e "\n### Compiling HQC-128-1\n"	
	$(CC) $(CFLAGS) $(MAIN_CLIENT) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -o $(BIN)/$@ 

hqc-128-1-test: $(HQC_OBJS) $(LIB_OBJS)
	@echo -e "\n### Compiling HQC-128-1\n"	
	$(CC) $(CFLAGS) $(MAIN_TEST) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -o $(BIN)/$@ 

hqc-128-1-server2: $(HQC_OBJS) $(LIB_OBJS)
	@echo -e "\n### Compiling HQC-128-1\n"	
	$(CC) $(CFLAGS) $(MAIN_SERVER2) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -o $(BIN)/$@ 

hqc-128-1-client2: $(HQC_OBJS) $(LIB_OBJS)
	@echo -e "\n### Compiling HQC-128-1\n"	
	$(CC) $(CFLAGS) $(MAIN_CLIENT2) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -o $(BIN)/$@

hqc-128-1-benchmark1: $(HQC_OBJS) $(LIB_OBJS)
	@echo -e "\n### Compiling HQC-128-1\n"	
	$(CC) $(CFLAGS) $(MAIN_BENCH1) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -o $(BIN)/$@

hqc-128-1-benchmark2: $(HQC_OBJS) $(LIB_OBJS)
	@echo -e "\n### Compiling HQC-128-1\n"	
	$(CC) $(CFLAGS) $(MAIN_BENCH2) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -o $(BIN)/$@

hqc-128-1-kat: $(HQC_OBJS) $(LIB_OBJS)
	@echo -e "\n### Compiling HQC-128-1 KAT\n"	
	$(CC) $(CFLAGS) $(MAIN_KAT) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -o $(BIN)/$@

hqc-128-1-verbose: $(HQC_OBJS_VERBOSE) $(LIB_OBJS)
	@echo -e "\n### Compiling HQC-128-1 (verbose mode)\n"	
	$(CC) $(CFLAGS) $(MAIN_HQC) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -D VERBOSE -o $(BIN)/$@ 



clean:
	rm -f PQCkemKAT_*
	rm -f vgcore.*
	rm -rf ./bin
