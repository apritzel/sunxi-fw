// SPDX-License-Identifier: GPL-2.0
/*
 * (C) Copyright 2020, Andre Przywara
 *
 * sunxi-boot0: dump basic information about an Allwinner eGON image
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "sunxi-fw.h"

#define CHECKSUM_SEED	0x5f0a6c39

#define BOOT0_CHECKSUM	3
#define BOOT0_LENGTH	4
#define BOOT0_DRAM_OFS	14

#define EGON_DRAM_PARAM_COUNT 32

static void
dram_param_raw_print(FILE *stream, void *raw)
{
	uint32_t *param = raw;
	int i;

	fprintf(stream, "; Unknown structure\n");
	for (i = 0; i < EGON_DRAM_PARAM_COUNT; i++)
		fprintf(stream, "dram_%02d\t= 0x%08X\n", i, param[i]);
}

int output_boot0_info(void *sector, FILE *inf, FILE *stream, bool verbose)
{
	const uint32_t *boot0 = sector;
	uint32_t *buffer, i, chksum = CHECKSUM_SEED;
	void *dram_param;
	size_t ret;

	if (!verbose) {
		pseek(inf, boot0[BOOT0_LENGTH] - 512);
		return (boot0[BOOT0_LENGTH] / 512) - 1;
	}

	fprintf(stream, "\tsize: %d bytes\n", boot0[BOOT0_LENGTH]);

	buffer = malloc(boot0[BOOT0_LENGTH]);
	if (!buffer)
		return 0;
	ret = fread(buffer + (512 / 4), 1, boot0[BOOT0_LENGTH] - 512, inf);
	if (ret < boot0[BOOT0_LENGTH] - 512) {
		fprintf(stream, "\tERROR: image file too small\n");
		free(buffer);

		return ret / 512;
	}
	memcpy(buffer, sector, 512);

	for (i = 0; i < boot0[BOOT0_LENGTH] / 4; i++)
		if (i != 3)
			chksum += buffer[i];
	if (chksum == boot0[BOOT0_CHECKSUM])
		fprintf(stream, "\teGON checksum matches: 0x%08x\n", chksum);
	else
		fprintf(stream, "\teGON checksum: 0x%08x, programmed: 0x%08x\n",
			chksum, boot0[BOOT0_CHECKSUM]);
	free(buffer);

	dram_param = (void *) &boot0[BOOT0_DRAM_OFS];

	dram_param_raw_print(stream, dram_param);

	return ret / 512;
}
