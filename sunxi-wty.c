// SPDX-License-Identifier: GPL-2.0
/*
 * (C) Copyright 2023, Andre Przywara
 *
 * sunxi-wty: dump information about an Allwinner PhoenixSuite image
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "sunxi-fw.h"

#define ENTRY_SIZE	0x400

int output_wty_info(void *sector, FILE *inf, FILE *stream, bool verbose)
{
	const uint32_t *wty = sector;
	int nr_images, i;
	uint32_t *buffer;
	size_t ret;
	uint32_t boot0_ofs = 0;
	bool found_boot0 = false;

	nr_images = wty[15];
	fprintf(stream, "\theader v%d.%d, %d images, %d MB\n",
		(wty[2] & 0xff00) >> 8, wty[2] & 0xff, nr_images, wty[6] >> 20);
	if (!verbose) {
		pseek(inf, wty[6] - 512);
		return (wty[6] / 512) - 1;
	}

	pseek(inf, ENTRY_SIZE - 512);	// fast-forward to the first image entry

	buffer = malloc(nr_images * ENTRY_SIZE);
	if (!buffer)
		return 0;
	ret = fread(buffer, 1, nr_images * ENTRY_SIZE, inf);
	if (ret < nr_images * ENTRY_SIZE) {
		fprintf(stream, "\tERROR: image file too small\n");
		free(buffer);

		return ret / 512;
	}

	for (i = 0; i < nr_images; i++) {
		unsigned int ofs = i * ENTRY_SIZE / 4;
		char *name = (char *)&buffer[ofs + 9];

		fprintf(stream, "\t\twty:%-20s: %10d bytes @ +0x%08x\n", name,
			buffer[ofs + 75], buffer[ofs + 77]);

		if (found_boot0)
			continue;
		if (!strncmp(name, "boot0_", 6))
			boot0_ofs = ofs;
		found_boot0 = !strcmp(name, "boot0_sdcard.fex");
	}
	if (boot0_ofs) {
		fprintf(stream, "@%4d: boot0: Allwinner boot0\n",
			buffer[boot0_ofs + 77] / 512);
		pseek(inf,
		      buffer[boot0_ofs + 77] - nr_images * ENTRY_SIZE - 1024);
		ret = fread(buffer, 1, 512, inf);
		output_boot0_info(buffer, inf, stream, verbose);
	} else
		pseek(inf, wty[6] - 512 - nr_images * ENTRY_SIZE);

	free(buffer);
	return (wty[6] / 512) - 1;
}

void extract_wty_image(void *sector, FILE *inf, FILE *outf, const char *imgname)
{
	const uint32_t *wty = sector;
	uint32_t buffer[ENTRY_SIZE / sizeof(uint32_t)];
	int nr_images = wty[15], i, ret;

	pseek(inf, ENTRY_SIZE - 512);	// fast-forward to the first image entry

	for (i = 0; i < nr_images; i++) {
		char *name;

		ret = fread(buffer, 1, ENTRY_SIZE, inf);
		if (ret != ENTRY_SIZE) {
			fprintf(stderr, "ERROR: image file too small\n");
			return;
		}
		name = (char *)&buffer[9];
		if (!strcmp(name, imgname + 4)) {
			pseek(inf, buffer[77] - (i + 2) * ENTRY_SIZE);
			copy_file(inf, outf, buffer[75]);
			return;
		}
	}
	fprintf(stderr, "ERROR: image file \"%s\" not found\n", imgname);
}
