// SPDX-License-Identifier: GPL-2.0
/*
 * (C) Copyright 2018, Andre Przywara
 *
 * sunxi-toc0: dump very basic information about an Allwinner TOC0 image
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "sunxi-fw.h"

#define CHECKSUM_SEED	0x5f0a6c39

struct toc0_header {
	uint8_t		magic[8];
	uint32_t	magic2;
	uint32_t	check_sum;
	uint32_t	serial_num;
	uint32_t	status;
	uint32_t	num_items;
	uint32_t	length;
	uint32_t	boot_media;
	uint8_t		reserved[8];
	char		end_marker[4];
};

void output_toc0_info(void *sector, FILE *inf, FILE *stream, bool verbose)
{
	struct toc0_header *toc0head = sector;

	if (verbose) {
		fprintf(stream, "\t%d item%s\n", toc0head->num_items,
			toc0head->num_items > 1 ? "s" : "");
		fprintf(stream, "\tsize: %d bytes\n", toc0head->length);
	}

	if (toc0head->length > 32768)
		pseek(inf, toc0head->length - 512);
	else
		pseek(inf, 32768 - 512);
}
