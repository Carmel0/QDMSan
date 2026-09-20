#
# american fuzzy lop++ - libqdmsan
# --------------------------------
#

PREFIX      ?= /usr/local
HELPER_PATH  = $(PREFIX)/lib/afl
DOC_PATH    ?= $(PREFIX)/share/doc/afl

CFLAGS      += -I ../qemuafl/qemuafl/
CFLAGS      += -Wno-int-to-void-pointer-cast -ggdb
LDFLAGS     += -ldl -pthread

SRC := libqdmsan.c
HDR :=

all: libqdmsan.so

libqdmsan.so: $(HDR) $(SRC)
	$(CC) $(CFLAGS) -fPIC -shared $(SRC) -o ../../$@ $(LDFLAGS)

.NOTPARALLEL: clean

clean:
	rm -f *.o *.so *~ a.out core core.[1-9][0-9]*
	rm -f ../../libqdmsan.so

install: all
	install -m 755 ../../libqdmsan.so $${DESTDIR}$(HELPER_PATH)
	install -m 644 -T README.md $${DESTDIR}$(DOC_PATH)/README.qdmsan.md
