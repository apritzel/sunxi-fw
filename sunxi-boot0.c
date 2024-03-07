// SPDX-License-Identifier: GPL-2.0
/*
 * (C) Copyright 2020, Andre Przywara
 * Copyright (c) 2024 Luc Verhaegen <libv@skynet.be>
 *
 * sunxi-boot0: dump basic information about an Allwinner eGON image
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "sunxi-fw.h"

#define __maybe_unused  __attribute__((unused))

struct egon_header {
	uint32_t jump;
#define EGON_MAGIC_0 "eGON.BT0"
#define EGON_MAGIC_1 "eGON.BT1"
	char magic[8];
#define EGON_CHECKSUM_SEED 0x5f0a6c39
	uint32_t checksum;
#define EGON_FILESIZE_ALIGN 4096
	uint32_t filesize;
	uint32_t header_size;
	char header_version[4];
	uint32_t return_address;
	uint32_t run_address;
	char eGON_version[4];
	char platform_info[8];
};

static void __maybe_unused
egon_header_print(FILE *stream, struct egon_header *header)
{
	fprintf(stream, "struct egon_header header[1] = {\n");

	fprintf(stream, "\t.jump = 0x%08X,\n", header->jump);
	fprintf(stream, "\t.magic = \"%c%c%c%c%c%c%c%c\",\n",
		header->magic[0], header->magic[1],
		header->magic[2], header->magic[3],
		header->magic[4], header->magic[5],
		header->magic[6], header->magic[7]);
	fprintf(stream, "\t.checksum = 0x%08X,\n", header->checksum);
	fprintf(stream, "\t.filesize = 0x%08X, /* %dbytes */\n",
		header->filesize, header->filesize);
	fprintf(stream, "\t.header_size = 0x%08X,\n", header->header_size);
	fprintf(stream, "\t.header_version = \"%c%c%c%c\",\n",
		header->header_version[0], header->header_version[1],
		header->header_version[2], header->header_version[3]);
	fprintf(stream, "\t.return_address = 0x%08X,\n",
		header->return_address);
	fprintf(stream, "\t.run_address = 0x%08X,\n", header->run_address);
	fprintf(stream, "\t.eGON_version = \"%c%c%c%c\",\n",
		header->eGON_version[0], header->eGON_version[1],
		header->eGON_version[2], header->eGON_version[3]);
	fprintf(stream, "\t.platform_info = \"%c%c%c%c%c%c%c%c\",\n",
		header->platform_info[0], header->platform_info[1],
		header->platform_info[2], header->platform_info[3],
		header->platform_info[4], header->platform_info[5],
		header->platform_info[6], header->platform_info[7]);

	fprintf(stream, "};\n\n");
}

struct egon_header_secondary {
	uint32_t header_size;
	char header_version[4];
#define EGON_DRAM_PARAM_COUNT 32
	uint32_t dram_param[EGON_DRAM_PARAM_COUNT];
	/* ignore the rest of this struct for now. */
};

static void __maybe_unused
egon_header_secondary_print(FILE *stream,
			    struct egon_header_secondary *header)
{
	int i;

	fprintf(stream, "struct egon_header header[1] = {\n");

	fprintf(stream, "\t.header_size = 0x%08X,\n", header->header_size);
	fprintf(stream, "\t.header_version = \"%c%c%c%c\",\n",
	       header->header_version[0],
	       header->header_version[1],
	       header->header_version[2],
	       header->header_version[3]);

	for (i = 0; i < EGON_DRAM_PARAM_COUNT; i++)
		fprintf(stream, "\t.dram_param[0x%02X] = 0x%08X,\n",
		       i, header->dram_param[i]);

	fprintf(stream, "\t/* ... */\n");

	fprintf(stream, "};\n\n");
}

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
	struct egon_header *header = sector;
	struct egon_header_secondary *secondary;
	uint32_t *buffer, i, chksum = EGON_CHECKSUM_SEED;
	void *dram_param;
	size_t ret;

	if (!verbose) {
		pseek(inf, header->filesize - 512);
		return (header->filesize / 512) - 1;
	}

	fprintf(stream, "\tsize: %d bytes\n", header->filesize);

	buffer = malloc(header->filesize);
	if (!buffer)
		return 0;
	ret = fread(buffer + (512 / 4), 1, header->filesize - 512, inf);
	if (ret < header->filesize - 512) {
		fprintf(stream, "\tERROR: image file too small\n");
		free(buffer);

		return ret / 512;
	}
	memcpy(buffer, sector, 512);

	for (i = 0; i < header->filesize / 4; i++)
		if (i != 3)
			chksum += buffer[i];
	if (chksum == header->checksum)
		fprintf(stream, "\teGON checksum matches: 0x%08x\n", chksum);
	else
		fprintf(stream, "\teGON checksum: 0x%08x, programmed: 0x%08x\n",
			chksum, header->checksum);
	free(buffer);

	secondary = (void *) header + header->header_size;
	dram_param = secondary->dram_param;

	dram_param_raw_print(stream, dram_param);

	return ret / 512;
}
