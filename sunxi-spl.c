// SPDX-License-Identifier: GPL-2.0
/*
 * (C) Copyright 2018, Andre Przywara
 *
 * sunxi-spl: dump information about a mainline U-Boot SPL, wrapped into
 *            an Allwinner eGON header
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "sunxi-fw.h"

#define CHECKSUM_SEED	0x5f0a6c39

struct spl_boot_file_head {
	uint32_t  jump_instruction;
	uint8_t	  magic[8];
	uint32_t  check_sum;
	uint32_t  length;
	uint8_t	  spl_signature[4];
	uint32_t  fel_script_address;
	uint32_t  fel_uEnv_length;
	uint32_t  offset_dt_name;
	uint32_t  reserved1;
	uint32_t  boot_media;
	uint32_t  string_pool[13];
};

/* Like strstr(), but does not stop at \0. */
static const char *memstr(const char *haystack, const char *needle, size_t size)
{
	size_t i;

	for (i = 0; i <= size - strlen(needle); i++) {
		if (haystack[i] != needle[0])
			continue;
		if (!memcmp(haystack + i, needle, strlen(needle)))
			return haystack + i;
	}

	return NULL;
}

void output_spl_info(void *sector, FILE *inf, FILE *stream, bool verbose)
{
	struct spl_boot_file_head *splhead = sector;
	uint32_t *buffer, i, chksum = CHECKSUM_SEED;
	const char *spl_banner;
	size_t ret;

	if (splhead->spl_signature[3] >= 2 &&
	    splhead->offset_dt_name != 0 &&
	    splhead->offset_dt_name < 512)
		fprintf(stream, "\tDT: %s\n",
			(char *)splhead + splhead->offset_dt_name);

	if (!verbose) {
		pseek(inf, 32768 - 512);
		return;
	}

	fprintf(stream, "\tsize: %d bytes\n", splhead->length);

	if (splhead->length > MAX_SPL_SIZE)
		fprintf(stream, "\tWARNING: SPL size bigger than 32KB!\n");
	buffer = malloc(MAX_SPL_SIZE);
	if (!buffer)
		return;
	ret = fread(buffer + (512 / 4), 1, MAX_SPL_SIZE - 512, inf);
	if (ret < splhead->length - 512) {
		fprintf(stream, "\tERROR: image file too small\n");
		free(buffer);

		return;
	}
	memcpy(buffer, sector, 512);

	for (i = 0; i < splhead->length / 4; i++)
		if (i != 3)
			chksum += buffer[i];
	if (chksum == splhead->check_sum)
		fprintf(stream, "\teGON checksum matches: 0x%08x\n", chksum);
	else
		fprintf(stream, "\teGON checksum: 0x%08x, programmed: 0x%08x\n",
			chksum, splhead->check_sum);

	spl_banner = memstr((char *)buffer, "U-Boot SPL ", MAX_SPL_SIZE);
	if (spl_banner)
		fprintf(stream, "\t%s\n", spl_banner);

	free(buffer);
}

int handle_dt_name(FILE *inf, const char *dt_name, FILE *outf)
{
	struct spl_boot_file_head *splhead;
	char sector[512];
	size_t ret;
	enum image_type type;

	ret = fread(sector, 1, 512, inf);
	if (ret < 512) {
		fprintf(stderr, "Cannot read from input file\n");
		return -3;
	}

	type = identify_image(sector);
	if (type == IMAGE_MBR) {
		pseek(inf, 8192 - 512);

		ret = fread(sector, 1, 512, inf);
		if (ret < 512) {
			fprintf(stderr, "Cannot read from input file\n");
			return -3;
		}
		type = identify_image(sector);
	}

	if (type != IMAGE_SPL2) {
		fprintf(stderr, "expecting U-Boot SPLv2\n");
		return -4;
	}

	splhead = (void *)sector;
	if (splhead->spl_signature[3] < 2 ||
	    splhead->offset_dt_name == 0 ||
	    splhead->offset_dt_name >= 512) {
		fprintf(stderr, "no DT name found.\n");
		return -5;
	}

	fprintf(outf, "%s\n", sector + splhead->offset_dt_name);

	return 0;
}
