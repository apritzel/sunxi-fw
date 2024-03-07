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

/*
 * should work for A10, A10s, A13 and A20.
 */
#define DRAM_PARAM_A10_MATCHES "A10/A10s/A13/A20"

struct dram_param_a10 {
	uint32_t baseaddr;
	uint32_t clk;
	uint32_t type;
	uint32_t rank_num;
	uint32_t chip_density;
	uint32_t io_width;
	uint32_t bus_width;
	uint32_t cas;
	uint32_t zq;
	uint32_t odt_en;
	uint32_t size;
	uint32_t tpr0;
	uint32_t tpr1;
	uint32_t tpr2;
	uint32_t tpr3;
	uint32_t tpr4;
	uint32_t tpr5;
	uint32_t emr1;
	uint32_t emr2;
	uint32_t emr3;
};

static int
dram_param_a10_validate(FILE *stream, void *raw)
{
	struct dram_param_a10 *param = raw;
	char *message = "Invalid structure for " DRAM_PARAM_A10_MATCHES;

	/* This is a base address, should be 0x40000000 */
	if (param->baseaddr & 0x0FFFFFFF) {
		fprintf(stream, "%s: wrong baseaddr: 0x%08X\n", message,
		       param->baseaddr);
		return -1;
	}

	/* MHz */
	if ((param->clk < 100) || (param->clk > 1000)) {
		fprintf(stream, "%s: wrong clk: 0x%08X\n", message,
		       param->clk);
		return -1;
	}

	/* 2: DDR2, 3: DDR3 */
	if ((param->type != 2) && (param->type != 3)) {
		fprintf(stream, "%s: wrong type: 0x%08X\n", message,
		       param->type);
		return -1;
	}

	if ((param->odt_en != 0) && (param->odt_en != 1)) {
		fprintf(stream, "%s: wrong odt_en: 0x%08X\n", message,
		       param->odt_en);
		return -1;
	}

	fprintf(stream, "Parameters seem valid for %s.\n",
		DRAM_PARAM_A10_MATCHES);
	return 0;
}

static void
dram_param_a10_print(FILE *stream, void *raw)
{
	struct dram_param_a10 *param = raw;

	fprintf(stream, "\n; %s\n", DRAM_PARAM_A10_MATCHES);
	fprintf(stream, "[dram para]\n\n");
	fprintf(stream, "dram_baseaddr\t   = 0x%x\n", param->baseaddr);
	fprintf(stream, "dram_clk\t   = %d\n", param->clk);
	fprintf(stream, "dram_type\t   = %d\n", param->type);
	fprintf(stream, "dram_rank_num\t   = 0x%x\n", param->rank_num);
	fprintf(stream, "dram_chip_density  = 0x%x\n", param->chip_density);
	fprintf(stream, "dram_io_width\t   = 0x%x\n", param->io_width);
	fprintf(stream, "dram_bus_width\t   = 0x%x\n", param->bus_width);
	fprintf(stream, "dram_cas\t   = 0x%x\n", param->cas);
	fprintf(stream, "dram_zq\t\t   = 0x%x\n", param->zq);
	fprintf(stream, "dram_odt_en\t   = %d\n", param->odt_en);
	fprintf(stream, "dram_size\t   = 0x%x\n", param->size);
	fprintf(stream, "dram_tpr0\t   = 0x%x\n", param->tpr0);
	fprintf(stream, "dram_tpr1\t   = 0x%x\n", param->tpr1);
	fprintf(stream, "dram_tpr2\t   = 0x%x\n", param->tpr2);
	fprintf(stream, "dram_tpr3\t   = 0x%x\n", param->tpr3);
	fprintf(stream, "dram_tpr4\t   = 0x%x\n", param->tpr4);
	fprintf(stream, "dram_tpr5\t   = 0x%x\n", param->tpr5);
	fprintf(stream, "dram_emr1\t   = 0x%x\n", param->emr1);
	fprintf(stream, "dram_emr2\t   = 0x%x\n", param->emr2);
	fprintf(stream, "dram_emr3\t   = 0x%x\n", param->emr3);
	fprintf(stream, "\n");
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

		fprintf(stream,
			"\nLooking for a valid dram parameter structure...\n");
		if (!dram_param_a10_validate(stream, dram_param))
			dram_param_a10_print(stream, dram_param);
		else
			dram_param_raw_print(stream, dram_param);
	} else {
		ret = pseek(inf, header->filesize - SECTOR_SIZE);
		if (ret)
			return 0;
	}

	return (header->filesize / SECTOR_SIZE) - 1;
}
