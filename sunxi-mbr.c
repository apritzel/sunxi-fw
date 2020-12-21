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
#include <inttypes.h>
#include <string.h>

#include "sunxi-fw.h"

static int output_gpt_info(FILE *inf, FILE *stream, bool verbose)
{
	uint32_t sector[512 / 4];
	uint64_t *arr64 = (void *)sector;
	int ret, nr_entries, entry_size, sectors;

	ret = fread(sector, 512, 1, inf);
	if (ret == 0 && feof(inf))
		return -1;

	fprintf(stream, "\tGPT version %08x\n", sector[2]);
	fprintf(stream, "\tusable disk size: %"PRId64" MB\n",
		(arr64[6] - arr64[5]) / 2048);
	nr_entries = sector[20];
	entry_size = sector[21];
	sectors = ((nr_entries * entry_size) + 511) / 512;
	fprintf(stream, "\tnumber of partition entries: %d\n", sector[20]);

	if (!verbose) {
		pseek(inf, sectors * 512);
		return 1 + sectors;
	}

	pseek(inf, sectors * 512);
	return 1 + sectors;
}

int output_mbr_info(void *sector, FILE *inf, FILE *stream, bool verbose)
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
			return output_gpt_info(inf, stream, verbose);
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
		return 0;
	}
	fprintf(stream, "\tfirst partition starts at %d KB\n", first_part / 2);

	return 0;
}
