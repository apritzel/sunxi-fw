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
#define OFS(x) ((x) + BOOT0_DRAM_OFS)

enum dram_para {
	DRAM_PARAM_NOT_USED = 0,
	DRAM_CLK,
	DRAM_TYPE,
	DRAM_ZQ,
	DRAM_ODT_EN,
	DRAM_DX_ODT,
	DRAM_DX_DRI,
	DRAM_CA_DRI,
	DRAM_PARA1, DRAM_PARA2,
	DRAM_MR0, DRAM_MR1, DRAM_MR2, DRAM_MR3,
	DRAM_MR4, DRAM_MR5, DRAM_MR6, DRAM_MR7,
	DRAM_MR8, DRAM_MR9, DRAM_MR10, DRAM_MR11,
	DRAM_MR12, DRAM_MR13, DRAM_MR14, DRAM_MR15,
	DRAM_MR16, DRAM_MR17, DRAM_MR18, DRAM_MR19,
	DRAM_MR20, DRAM_MR21, DRAM_MR22,
	DRAM_TPR0, DRAM_TPR1, DRAM_TPR2, DRAM_TPR3,
	DRAM_TPR4, DRAM_TPR5, DRAM_TPR6, DRAM_TPR7,
	DRAM_TPR8, DRAM_TPR9, DRAM_TPR10, DRAM_TPR11,
	DRAM_TPR12, DRAM_TPR13,
	NR_DRAM_PARAMS
};

static const char *param_name[] = {
	[DRAM_PARAM_NOT_USED] = "unused",
	[DRAM_CLK] = "DRAM clock",
	[DRAM_TYPE] = "DRAM type",
	[DRAM_ZQ] = "ZQ value",
	[DRAM_ODT_EN] = "ODT enabled",
	[DRAM_DX_ODT] = "DX ODT",
	[DRAM_DX_DRI] = "DX DRI",
	[DRAM_CA_DRI] = "CA DRI",
	[DRAM_PARA1] = "PARA1",
	[DRAM_PARA2] = "PARA2",
	[DRAM_MR0] = "MR0",
	[DRAM_MR1] = "MR1",
	[DRAM_MR2] = "MR2",
	[DRAM_MR3] = "MR3",
	[DRAM_MR4] = "MR4",
	[DRAM_MR5] = "MR5",
	[DRAM_MR6] = "MR6",
	[DRAM_MR7] = "MR7",
	[DRAM_MR8] = "MR8",
	[DRAM_MR9] = "MR9",
	[DRAM_MR10] = "MR10",
	[DRAM_MR11] = "MR11",
	[DRAM_MR12] = "MR12",
	[DRAM_MR13] = "MR13",
	[DRAM_MR14] = "MR14",
	[DRAM_MR15] = "MR15",
	[DRAM_MR16] = "MR16",
	[DRAM_MR17] = "MR17",
	[DRAM_MR18] = "MR18",
	[DRAM_MR19] = "MR19",
	[DRAM_MR20] = "MR20",
	[DRAM_MR21] = "MR21",
	[DRAM_MR22] = "MR22",
	[DRAM_TPR0] = "TPR0",
	[DRAM_TPR1] = "TPR1",
	[DRAM_TPR2] = "TPR2",
	[DRAM_TPR3] = "TPR3",
	[DRAM_TPR4] = "TPR4",
	[DRAM_TPR5] = "TPR5",
	[DRAM_TPR6] = "TPR6",
	[DRAM_TPR7] = "TPR7",
	[DRAM_TPR8] = "TPR8",
	[DRAM_TPR9] = "TPR9",
	[DRAM_TPR10] = "TRP10",
	[DRAM_TPR11] = "TRP11",
	[DRAM_TPR12] = "TRP12",
	[DRAM_TPR13] = "TRP13",
};

enum soc_types {
	SOC_A64 = 0,
	SOC_H616,
	SOC_H6,
	NR_SOC_TYPES
};

static int8_t register_mappings[NR_SOC_TYPES][NR_DRAM_PARAMS] = {
	[SOC_A64] = {
		[DRAM_CLK] = OFS(0),
		[DRAM_TYPE] = OFS(1),
		[DRAM_ZQ] = OFS(2),
		[DRAM_ODT_EN] = OFS(3),
		[DRAM_PARA1] = OFS(4),
		[DRAM_PARA2] = OFS(5),
		[DRAM_MR0] = OFS(6),
		[DRAM_MR1] = OFS(7),
		[DRAM_MR2] = OFS(8),
		[DRAM_MR3] = OFS(9),
		[DRAM_TPR0] = OFS(10),
		[DRAM_TPR1] = OFS(11),
		[DRAM_TPR2] = OFS(12),
		[DRAM_TPR3] = OFS(13),
		[DRAM_TPR4] = OFS(14),
		[DRAM_TPR5] = OFS(15),
		[DRAM_TPR6] = OFS(16),
		[DRAM_TPR7] = OFS(17),
		[DRAM_TPR8] = OFS(18),
		[DRAM_TPR9] = OFS(19),
		[DRAM_TPR10] = OFS(20),
		[DRAM_TPR11] = OFS(21),
		[DRAM_TPR12] = OFS(22),
		[DRAM_TPR13] = OFS(23),
	},
	[SOC_H616] = {
		[DRAM_CLK] = OFS(0),
		[DRAM_TYPE] = OFS(1),
		[DRAM_DX_ODT] = OFS(2),
		[DRAM_DX_DRI] = OFS(3),
		[DRAM_CA_DRI] = OFS(4),
		[DRAM_ODT_EN] = OFS(5),
		[DRAM_PARA1] = OFS(6),
		[DRAM_PARA2] = OFS(7),
		[DRAM_MR0] = OFS(8),
		[DRAM_MR1] = OFS(9),
		[DRAM_MR2] = OFS(10),
		[DRAM_MR3] = OFS(11),
		[DRAM_MR4] = OFS(12),
		[DRAM_MR5] = OFS(13),
		[DRAM_MR6] = OFS(14),
		[DRAM_MR11] = OFS(15),
		[DRAM_MR12] = OFS(16),
		[DRAM_MR13] = OFS(17),
		[DRAM_MR14] = OFS(18),
		[DRAM_MR16] = OFS(19),
		[DRAM_MR17] = OFS(20),
		[DRAM_MR22] = OFS(21),
		[DRAM_TPR0] = OFS(22),
		[DRAM_TPR1] = OFS(23),
		[DRAM_TPR2] = OFS(24),
		[DRAM_TPR3] = OFS(25),
		[DRAM_TPR6] = OFS(26),
		[DRAM_TPR10] = OFS(27),
		[DRAM_TPR11] = OFS(28),
		[DRAM_TPR12] = OFS(29),
		[DRAM_TPR13] = OFS(30),
	},
};

int output_boot0_info(void *sector, FILE *inf, FILE *stream, bool verbose)
{
	const uint32_t *boot0 = sector;
	uint32_t *buffer, i, chksum = CHECKSUM_SEED;
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

	fprintf(stream, "\tDRAM parameters:\tA64\t\tH616\n");

	for (i = 0; i < NR_DRAM_PARAMS; i++) {
		int ver;

		for (ver = 0; ver < NR_SOC_TYPES; ver++)
			if (register_mappings[ver][i] &&
			    boot0[register_mappings[ver][i]])
				break;
		/* if this parameter is unused, skip the output */
		if (ver == NR_SOC_TYPES)
			continue;


		fprintf(stream, "\t\t%-12s:", param_name[i]);

		for (ver = 0; ver < NR_SOC_TYPES; ver++) {
			if (register_mappings[ver][i] == 0)
				fprintf(stream, "           -");
			else
				fprintf(stream, "  %#10x",
					boot0[register_mappings[ver][i]]);
		}
		fprintf(stream, "\n");
	}

	return ret / 512;
}
