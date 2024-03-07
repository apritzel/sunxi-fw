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
#include <errno.h>
#include <stddef.h>

#include "sunxi-fw.h"

#define __maybe_unused  __attribute__((unused))

#define SECTOR_SIZE 512

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

static int
egon_checksum_verify(FILE *stream, struct egon_header *header,
		     uint32_t *sector0, FILE *inf)
{
#define BUFFER_COUNT (SECTOR_SIZE / sizeof(uint32_t))
	uint32_t buffer[BUFFER_COUNT];
	uint32_t checksum = EGON_CHECKSUM_SEED;
	off_t checksum_offset =
		offsetof(struct egon_header, checksum) / sizeof(uint32_t);
	off_t offset;
	int i;

	/* handle the already read sector separately */
	for (i = 0; i < BUFFER_COUNT; i++) {
		if (i == checksum_offset)
			continue;
		checksum += sector0[i];
	}
	offset = SECTOR_SIZE;

	for (; offset < header->filesize; offset += SECTOR_SIZE) {
		int ret;

		ret = fread(buffer, sizeof(uint32_t), BUFFER_COUNT, inf);
		if (ret != BUFFER_COUNT) {
			fprintf(stream,	"Error: %s(): fread failed: %s (%d)\n",
				__func__, strerror(errno), ret);
			return ret;
		}

		for (i = 0; i < BUFFER_COUNT; i++)
			checksum += buffer[i];
	}

	if (checksum != header->checksum)
		fprintf(stream, "eGON checksum mismatch: 0x%08X vs 0x%08X\n",
			checksum, header->checksum);
	else
		fprintf(stream, "eGON checksum matches.\n");

	return 0;
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
	size_t ret;

	/*
	 * This might be superfluous as the upper level already checks for
	 * this, but we are doing a thorough header check here.
	 */
	if (memcmp(header->magic, EGON_MAGIC_0, 8) > 0) {
		fprintf(stream,
			"\tERROR: wrong header magic: %c%c%c%c%c%c%c%c\n",
			header->magic[0], header->magic[1],
			header->magic[2], header->magic[3],
			header->magic[4], header->magic[5],
			header->magic[6], header->magic[7]);
		return 0;
	}

	if (header->header_size != sizeof(struct egon_header)) {
		fprintf(stream, "\tERROR: egon header size mismatch: %d\n",
			header->header_size);
		return 0;
	}

	if (header->filesize & (EGON_FILESIZE_ALIGN - 1)) {
		fprintf(stream, "\tERROR: boot0 file size not a multiple of "
			"%d: %d bytes (0x%04X).\n", EGON_FILESIZE_ALIGN,
			header->filesize, header->filesize);
		return 0;
	}

	if (!header->filesize) {
		fprintf(stream, "\tERROR: boot0 file is supposedly empty: "
			"0x%04X.\n", header->filesize);
		return 0;
	}

	if (verbose) {
		struct egon_header_secondary *secondary =
			(void *) header + header->header_size;
		void *dram_param = secondary->dram_param;

		fprintf(stream, "Found eGON header.\n");
		fprintf(stream, "Boot0 Filesize is %dkB.\n",
			header->filesize >> 10);

		ret = egon_checksum_verify(stream, header, sector, inf);
		if (ret)
			return 0;

		dram_param_raw_print(stream, dram_param);
	} else {
		ret = pseek(inf, header->filesize - SECTOR_SIZE);
		if (ret)
			return 0;
	}

	return (header->filesize / SECTOR_SIZE) - 1;
}
