SH=/bin/sh
CC=${CROSS_COMPILE}gcc
CFLAGS=-Wall -g -O
PREFIX ?=/usr/local

all: sunxi-fw

sunxi-fw: sunxi-img.o sunxi-mbr.o sunxi-uboot.o sunxi-fit.o sunxi-spl.o sunxi-fw.o sunxi-toc0.o sunxi-boot0.o sunxi-wty.o
	${CC} -o $@ $^ -lfdt

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
