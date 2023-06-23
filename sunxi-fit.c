// SPDX-License-Identifier: GPL-2.0
/*
 * (C) Copyright 2018, Andre Przywara
 *
 * sunxi-fit: dump information about a U-Boot FIT image
 */

#include <stdio.h>
#include <libfdt.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <errno.h>
#include "sunxi-fw.h"

static ssize_t read_dt(void *sector, FILE *stream, void **fdt)
{
	uint32_t head;
	void *blob;
	ssize_t size;

	memcpy(&head, sector + 4, 4);
	size = ntohl(head);
	if (size < 4)
		return -size;

	blob = malloc(size);
	if (blob == NULL)
		return -8;

	memcpy(blob, sector, size < 512 ? size : 512);
	if (size > 512) {
		if (fread(blob + 512, 1, size - 512, stream) < size - 512) {
			free(blob);
			return -size;
		}
	}

	*fdt = blob;
	return size;
}

static void dump_property(void *fdt, int node, const char *propname, FILE *outf)
{
	const struct fdt_property *prop;

	prop = fdt_get_property(fdt, node, propname, NULL);
	if (prop)
		fprintf(outf, "\t\t%s: %s\n", propname, prop->data);
}

static void dump_image_info(void *fdt, int node, FILE *outf, bool verbose)
{
	const char *nodename = fdt_get_name(fdt, node, NULL);
	const struct fdt_property *prop;
	uint32_t reg32;
	int length;

	prop = fdt_get_property(fdt, node, "description", NULL);
	fprintf(outf, "%s: \"%s\"\n", nodename,
		prop ? prop->data : "<no description>");

	if (!verbose)
		return;

	dump_property(fdt, node, "type", outf);
	dump_property(fdt, node, "arch", outf);
	dump_property(fdt, node, "compression", outf);

	prop = fdt_get_property(fdt, node, "data-size", NULL);
	if (prop) {
		reg32 = ntohl(*(uint32_t *)prop->data);
		fprintf(outf, "\t\tsize: %u bytes\n", reg32);
	} else {
		prop = fdt_get_property(fdt, node, "data", &length);
		if (prop) {
			fprintf(outf, "\t\tembedded data size: %u bytes\n",
				length);
		}
	}
	prop = fdt_get_property(fdt, node, "load", NULL);
	if (prop) {
		reg32 = ntohl(*(uint32_t *)prop->data);
		fprintf(outf, "\t\tload address: 0x%08x\n", reg32);
	}
}

static void dump_config_info(void *fdt, int node, FILE *outf, bool verbose)
{
	const struct fdt_property *prop;

	prop = fdt_get_property(fdt, node, "description", NULL);
	fprintf(outf, "%s\n", prop->data);

	if (!verbose)
		return;

	dump_property(fdt, node, "firmware", outf);
	dump_property(fdt, node, "loadables", outf);
	dump_property(fdt, node, "fdt", outf);
}

void dump_dt_info(void *sector, FILE *inf, FILE *outf, bool verbose)
{
	void *fdt = NULL;
	ssize_t size;
	int node, subnode;
	const char *nodename;
	bool is_config;

	size = read_dt(sector, inf, &fdt);
	if (size < 0) {
		fprintf(stderr, "invalid FIT image\n");
		return;
	}

	for (node = fdt_first_subnode(fdt, 0);
	     node != -FDT_ERR_NOTFOUND;
	     node = fdt_next_subnode(fdt, node)) {
		nodename = fdt_get_name(fdt, node, NULL);
		is_config = !strcmp(nodename, "configurations");
		for (subnode = fdt_first_subnode(fdt, node);
		     subnode != -FDT_ERR_NOTFOUND;
		     subnode = fdt_next_subnode(fdt, subnode)) {
			if (is_config) {
				fprintf(outf, "\tconfiguration: ");
				dump_config_info(fdt, subnode, outf, verbose);
			} else {
				fprintf(outf, "\tfit:");
				dump_image_info(fdt, subnode, outf, verbose);
			}
		}
	}

	if (fdt)
		free(fdt);
}

void extract_fit_image(void *sector, FILE *inf, FILE *outf, const char *imgname)
{
	void *fdt = NULL;
	ssize_t size;
	int node, length;
	const char *nodename;
	const struct fdt_property *prop;
	uint32_t offset, imgsize;

	size = read_dt(sector, inf, &fdt);
	if (size < 0 || !fdt) {
		fprintf(stderr, "invalid FIT image\n");
		if (fdt)
			free(fdt);
		return;
	}

	if (!strcmp(imgname, "fit")) {
		fwrite(fdt, size, 1, outf);
		free(fdt);
		return;
	}

	if (strncmp(imgname, "fit:", 4))
		return;

	for (node = fdt_first_subnode(fdt, 0);
	     node != -FDT_ERR_NOTFOUND;
	     node = fdt_next_subnode(fdt, node)) {
		nodename = fdt_get_name(fdt, node, NULL);
		if (!strcmp(nodename, "images"))
			break;
	}
	if (node == -FDT_ERR_NOTFOUND) {
		free(fdt);
		return;
	}

	for (node = fdt_first_subnode(fdt, node);
	     node != -FDT_ERR_NOTFOUND;
	     node = fdt_next_subnode(fdt, node)) {
		nodename = fdt_get_name(fdt, node, NULL);
		if (!strcmp(nodename, imgname + 4))
			break;
	}
	if (node == -FDT_ERR_NOTFOUND) {
		free(fdt);
		return;
	}

	prop = fdt_get_property(fdt, node, "data", &length);
	if (prop) {
		fwrite(prop->data, 1, length, outf);
		return;
	}

	prop = fdt_get_property(fdt, node, "data-offset", NULL);
	if (!prop)
		return;
	offset = ntohl(*(uint32_t *)prop->data);

	prop = fdt_get_property(fdt, node, "data-size", NULL);
	if (!prop)
		return;
	imgsize = ntohl(*(uint32_t *)prop->data);
	pseek(inf, offset);
	copy_file(inf, outf, imgsize);

	free(fdt);
}
