CC ?= gcc
CFLAGS ?= -O2 -ggdb -Wall -Wextra -I../../include \
          -DAFL_PATH=\"/usr/local/lib/afl\" \
          -DBIN_PATH=\"/usr/local/bin\" \
          -DDOC_PATH=\"/usr/local/share/doc/afl\"
LDFLAGS ?= -ldl

TARGET := qdmsan-diff
SRC := qdmsan_diff.c ../../src/afl-common.c ../../src/afl-forkserver.c \
       ../../src/afl-performance.c ../../src/afl-sharedmem.c

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SRC) qdmsan_diff.h
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: all
	install -m 755 $(TARGET) /usr/local/bin/
