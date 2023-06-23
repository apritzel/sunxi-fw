SH=/bin/sh
CC=${CROSS_COMPILE}gcc
CFLAGS=-Wall -g -O

all: sunxi-fw

sunxi-fw: sunxi-img.o sunxi-mbr.o sunxi-uboot.o sunxi-fit.o sunxi-spl.o sunxi-fw.o
	${CC} -o $@ $^ -lfdt

sunxi-%.o: sunxi-%.c
	${CC} -c ${CFLAGS} -o $@ $^

.PHONY: clean

clean:
	rm -f *.o sunxi-fw
