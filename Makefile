BIN_FILE = fpp

SRC_FILES += main.c
SRC_FILES += encrypt_file.c
SRC_FILES += aes128.c
SRC_FILES += aes256.c
SRC_FILES += blowfish.c
SRC_FILES += cast5.c
SRC_FILES += camellia128.c
SRC_FILES += camellia256.c
SRC_FILES += pbkdf2.c
SRC_FILES += getpass.c
SRC_FILES += random.c
SRC_FILES += memory.c
SRC_FILES += errcodes.c
SRC_FILES += log.c

CC = gcc
INSTALL_DIR = /usr/local/bin

override CFLAGS += -Iinclude
override CFLAGS += -Wall -Wextra -Wuninitialized -pipe
build: override CFLAGS += -g0 -s -O3 -DNDEBUG
debug: override CFLAGS += -g3 -ggdb3 -O0 -DDEBUG

override LDFLAGS += -lssl -lcrypto

ifeq ($(CC), gcc)
	GCC_VER = $(shell $(CC) -v 2>&1 | grep 'gcc version' 2>&1 \
		| sed -e 's/^.* version \(.*\)/\1/')
	override CFLAGS += -DFPP_COMPILER="\"gcc $(GCC_VER)\""
endif

ifeq ($(CC), clang)
	CLANG_VER = $(shell $(CC) -v 2>&1 | grep 'version' 2>&1 \
		| sed -n -e 's/^.*clang version \(.*\)/\1/p' \
		-e 's/^.*LLVM version \(.*\)/\1/p')
	override CFLAGS += -DFPP_COMPILER="\"clang $(CLANG_VER)\""
endif

ifeq ($(CC), x86_64-w64-mingw32-gcc)
	MINGW_VER = $(shell $(CC) -v 2>&1 | grep 'gcc version' 2>&1 \
		| sed -e 's/^.* version \(.*\)/\1/')
	override CFLAGS += -DFPP_COMPILER="\"mingw $(MINGW_VER)\""
	CFLAGS += -D__USE_MINGW_ANSI_STDIO
	LDFLAGS += -static -lws2_32
endif

ifeq ($(CC), i686-w64-mingw32-gcc)
	MINGW_VER = $(shell $(CC) -v 2>&1 | grep 'gcc version' 2>&1 \
		| sed -e 's/^.* version \(.*\)/\1/')
	override CFLAGS += -DFPP_COMPILER="\"mingw $(MINGW_VER)\""
	CFLAGS += -D__USE_MINGW_ANSI_STDIO
	LDFLAGS += -static -lws2_32
endif

OBJ_FILES := $(patsubst %.c,obj/%.o,$(SRC_FILES))
QUIET_CC = @echo '   ' CC $(notdir $@);

VPATH += src
VPATH += src/core
VPATH += src/cli

#.ONESHELL:
.PHONY: build debug test docs

all: build
build: mkdirs _build
debug: mkdirs _debug

_build: $(OBJ_FILES)
	$(CC) $^ -o bin/$(BIN_FILE) $(LDFLAGS)

_debug: $(OBJ_FILES)
	$(CC) $^ -o bin/$(BIN_FILE) $(LDFLAGS)

test:
	$(warning Tests now is not available!)

docs:
	doxygen docs/Doxyfile

obj/%.o: %.c
	$(QUIET_CC) $(CC) -c $< -o $@ $(CFLAGS)

install: mkdirs build
	install bin/$(BIN_FILE) $(INSTALL_DIR)

uninstall:
	rm -f $(INSTALL_DIR)/$(BIN_FILE)

clean:
	rm -f obj/*
	rm -f bin/*

mkdirs: 
	@if [ ! -d bin ]; then \
		mkdir bin; \
	fi

	@if [ ! -d obj ]; then \
		mkdir obj; \
	fi
