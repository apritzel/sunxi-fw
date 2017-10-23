// SPDX-License-Identifier: GPL-2.0
/*
 * (C) Copyright 2018, Andre Przywara
 *
 * sunxi-mbr: parse an MS-DOS style Master Boot Record (MBR) to dump the
 *            partition table (not chasing extended partitions)
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "sunxi-fw.h"

void output_mbr_info(void *sector, FILE *stream, bool verbose)
{
	unsigned char *parts = sector + 0x1be;
	int i;
	uint32_t psize, poffset;
	unsigned char ptype;
	uint32_t first_part = ~0;

	for (i = 0; i < 4; i++) {
		ptype = parts[i * 16 + 4];
		if (ptype == 0)			/* empty entry, skip */
			continue;

		memcpy(&poffset, &parts[i * 16 + 8], sizeof(poffset));
		memcpy(&psize, &parts[i * 16 + 12], sizeof(psize));

		if (poffset < first_part)
			first_part = poffset;

		switch (ptype) {
			break;
		case 0xee:
			fprintf(stream, "\tprotective MBR, GPT used\n");
			continue;
		case 0xef:
			fprintf(stream, "\tpart %d is EFI system partition\n",
				i + 1);
			break;
		}

		if (!verbose || ptype == 0xee)
			continue;

		fprintf(stream, "\tpart %d: type: %02X, offset: %8d sectors, size: %8d sectors\n",
			i + 1, ptype, poffset, psize);
	}
	if (first_part == ~0) {
		fprintf(stream, "\tno partitions defined\n");
		return;
	}
	fprintf(stream, "\tfirst partition starts at %d KB\n", first_part / 2);
}
