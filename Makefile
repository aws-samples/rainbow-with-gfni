ROOT = $(realpath .)
OBJ_DIR = ${ROOT}/obj
SRC_DIR = ${ROOT}/src
CTR_DRBG_DIR = ${SRC_DIR}/ctr_drbg
TEST_DIR = ${ROOT}/tests
KAT_TEST_DIR = ${TEST_DIR}/kats_test/
SA_TEST_DIR = ${TEST_DIR}/stand_alone/


CC := clang-9
INC := -I${SRC_DIR} -I${CTR_DRBG_DIR} 

BIN_DIR = ./bin/
TARGET := $(BIN_DIR)/main

SRC_CSRC  = ${SRC_DIR}/gfni.c ${SRC_DIR}/keypair.c ${SRC_DIR}/keypair_computation.c 
SRC_CSRC += ${SRC_DIR}/utils_hash.c ${SRC_DIR}/verify.c ${SRC_DIR}/sign.c 
SRC_CSRC += ${CTR_DRBG_DIR}/aes.c ${CTR_DRBG_DIR}/ctr_drbg.c

CSRC = ${SRC_CSRC}

SSRC  = ${CTR_DRBG_DIR}/vaes256_key_expansion.S

OBJ_FILES += $(patsubst ${SRC_DIR}/%.c, $(OBJ_DIR)/%.o, $(CSRC))
OBJ_FILES += $(patsubst ${CTR_DRBG_DIR}/%.c, $(OBJ_DIR)/%.o, $(CSRC))
OBJ_FILES += $(patsubst ${CTR_DRBG_DIR}/%.S, $(OBJ_DIR)/%.o, $(SSRC))

CFLAGS += $(INC) -ggdb -O3 -march=native -std=c99 -mno-red-zone
CFLAGS += -fvisibility=hidden -funsigned-char -Wall -Wextra -Werror -Wpedantic 
CFLAGS += -Wunused -Wcomment -Wchar-subscripts -Wuninitialized -Wshadow
CFLAGS += -Wwrite-strings -Wno-deprecated-declarations -Wno-unknown-pragmas -Wformat-security
CFLAGS += -Wcast-qual -Wunused-result -fPIC 
CFLAGS += -Wcast-align 

ifdef USE_ORIG_TEST
  CSRC += ${KAT_TEST_DIR}/PQCgenKAT_sign.c ${KAT_TEST_DIR}/rng.c
  INC  += -I${KAT_TEST_DIR}
  OBJ_FILES += $(patsubst ${KAT_TEST_DIR}/%.c, $(OBJ_DIR)/%.o, $(CSRC))
  ifdef USE_ORIG_RNG
    CFLAGS += -DUSE_ORIG_RNG
  endif
else
  SRC_CSRC += ${SA_TEST_DIR}/main.c
  CSRC += ${SA_TEST_DIR}/main.c
  INC  += -I${SA_TEST_DIR}
  OBJ_FILES += $(patsubst ${SA_TEST_DIR}/%.c, $(OBJ_DIR)/%.o, $(CSRC))
endif

OBJS = $(OBJ_DIR)/*.o
CFLAGS += $(INC)

#Avoiding GCC 4.8 bug
CFLAGS += -Wno-missing-braces -Wno-missing-field-initializers

ifndef NO_VAES
  CFLAGS += -DVAES
endif

ifdef USE_AES_FIELD
  CFLAGS += -DUSE_AES_FIELD
endif

ifdef SPECIAL_PIPELINING
  CFLAGS += -DSPECIAL_PIPELINING
endif

ifdef UNROLL_LOOPS
    #FOr GCC use CFLAGS += -funroll-all-loops
    CFLAGS += -funroll-loops
endif

ifdef MSAN
    CFLAGS += -fsanitize=memory -fsanitize-memory-track-origins -fno-omit-frame-pointer -DMSAN
endif

ifdef ASAN
    CFLAGS += -fsanitize=address -fsanitize-address-use-after-scope -fno-omit-frame-pointer
endif

ifdef TSAN
    CFLAGS += -fsanitize=thread
endif

ifdef UBSAN
    CFLAGS += -fsanitize=undefined
endif

ifdef RDTSC
    CFLAGS += -DRDTSC
endif

EXTERNAL_LIBS = -lcrypto

all: $(BIN_DIR) $(OBJ_DIR) $(OBJ_FILES) $(SUB_DIRS)
	$(CC) $(OBJS) $(CFLAGS) $(EXTERNAL_LIBS) -o $(TARGET)

$(SUB_DIRS):
	make -C $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)
	mkdir -p $(OBJ_DIR)/ctr_drbg
	mkdir -p $(OBJ_DIR)/kats_test
	mkdir -p $(OBJ_DIR)/stand_alone

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(OBJ_DIR)/%.o: ${SRC_DIR}/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/%.o: ${CTR_DRBG_DIR}/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/%.o: ${CTR_DRBG_DIR}/%.S
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/%.o: ${KAT_TEST_DIR}/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/%.o: ${SA_TEST_DIR}/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(OBJ_DIR)
	rm -rf $(BIN_DIR)

pretty:
	find ${ROOT} -name '*.c' -o -name '*.h' | xargs clang-format-9 -style=file -i

tidy:
	clang-tidy-9 ${SRC_CSRC} -p $(ROOT) --fix-errors --format-style=file -- ${CFLAGS}

pre-commit-test:
	make pretty
	make tidy
	make tidy USE_AES_FIELD=1 SPECIAL_PIPELINING=1 
	make clean; make -j4 USE_ORIG_TEST=1
	make clean; make USE_ORIG_TEST=1 USE_AES_FIELD=1 SPECIAL_PIPELINING=1 -j4; ${TARGET}
	make clean; make USE_ORIG_TEST=1 ASAN=1  -j4; ${TARGET}
	make clean; make USE_ORIG_TEST=1 MSAN=1  -j4; ${TARGET}
	make clean; make USE_ORIG_TEST=1 UBSAN=1 -j4; ${TARGET}
	make clean; make USE_ORIG_TEST=1 TSAN=1  -j4; ${TARGET}
