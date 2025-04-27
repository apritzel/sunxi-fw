SH=/bin/sh
CC=${CROSS_COMPILE}gcc
CFLAGS=-Wall -g -O
LDFLAGS=-lfdt
PKG_CONFIG?=pkg-config
LIBCRYPTO_PKGCONFIG:=$(shell $(PKG_CONFIG) --exists libcrypto && echo $$?)
ifeq ($(LIBCRYPTO_PKGCONFIG),0)
	LIBCRYPTO_CFLAGS=$(shell $(PKG_CONFIG) --cflags libcrypto)
	LIBCRYPTO_LDFLAGS=$(shell $(PKG_CONFIG) --libs libcrypto)
endif
WITH_OPENSSL?=1
ifeq ($(WITH_OPENSSL),1)
	CFLAGS+=$(LIBCRYPTO_CFLAGS) -DWITH_OPENSSL=1
	LDFLAGS+=$(LIBCRYPTO_LDFLAGS)
endif
PREFIX?=/usr/local

all: sunxi-fw

sunxi-fw: sunxi-img.o sunxi-mbr.o sunxi-uboot.o sunxi-fit.o sunxi-spl.o sunxi-fw.o sunxi-toc0.o sunxi-boot0.o sunxi-wty.o
	${CC} -o $@ $^ ${LDFLAGS}

sunxi-%.o: sunxi-%.c
	${CC} -c ${CFLAGS} -o $@ $^

.PHONY: clean

clean:
	rm -f *.o sunxi-fw

install: sunxi-fw
	install -D -m755 -s sunxi-fw $(PREFIX)/bin/sunxi-fw

uninstall:
	rm -f $(PREFIX)/bin/sunxi-fw

.PHONY: clean install uninstall
