// SPDX-License-Identifier: GPL-2.0
/*
 * (C) Copyright 2018, Andre Przywara
 *
 * sunxi-uboot: dump information about a legacy U-Boot image
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>			/* for ntohl() */

#include "sunxi-fw.h"
#define UBOOT_LEGACY_NEED_NAMES
#include "uboot_legacy.h"

void output_uboot_info(void *sector, FILE *inf, FILE *stream, bool verbose)
{
	struct legacy_image_header *header = sector;

	fprintf(stream, "\t\tsize: %d bytes\n", ntohl(header->ih_size));
	if (verbose) {
		fprintf(stream, "\t\tOS: %s\n",
			uboot_legacy_os_type[header->ih_os]);
		fprintf(stream, "\t\tarch: %s\n",
			uboot_legacy_arch_name[header->ih_arch]);
		fprintf(stream, "\t\ttype: %s\n",
				uboot_legacy_image_type[header->ih_type]);
		fprintf(stream, "\t\tcomp: %d\n", header->ih_comp);
	}
	fprintf(stream, "\tu-boot:\tname: %.32s\n", header->ih_name);
}

void dump_uboot_legacy(void *sector, FILE *inf, FILE *outf, bool payload)
{
	struct legacy_image_header *header = sector;

	if (payload)
		fwrite(sector + 64, 1, 512 - 64, outf);
	else
		fwrite(sector, 1, 512, outf);

	copy_file(inf, outf, ntohl(header->ih_size) - 512 + sizeof(*header));
}
