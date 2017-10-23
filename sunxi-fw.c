// SPDX-License-Identifier: GPL-2.0
/*
 * (C) Copyright 2018, Andre Przywara
 *
 * sunxi-fw:
 * dump information about firmware images for Allwinner CPU based systems
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "sunxi-fw.h"

/*
 * pseek() - forward-only seek, that works on pipes as well
 * @stream: file to seek in
 * @offset: number of bytes to skip
 *
 * pseek() works like fseek(), with @whence fixed to SEEK_CUR. But it also
 * support pipes (or other non-seekable file descriptors), by dummy-reading
 * the respective number of bytes if fseek() does not work.
 *
 * Return: 0 if successful, negative error value otherwise
 */
#define BUFSIZE 1024
int pseek(FILE *stream, long offset)
{
	static char buffer[BUFSIZE] = {};
	int chunk, ret;

	ret = fseek(stream, offset, SEEK_CUR);
	if (!ret)
		return ret;

	if (ret < 0 && errno != ESPIPE)
		return -errno;

	while (offset) {
		chunk = (offset > BUFSIZE ? BUFSIZE : offset);
		ret = fread(buffer, 1, chunk, stream);
		if (ret < chunk)
			return -errno;

		offset -= ret;
	}

	return 0;
}

/*
 * copy_file(): copy content of one FILE to another
 * @inf: input file pointer
 * @outf: output file pointer
 * @length: length to copy, or -1 for "the rest of @inf"
 *
 * Copies the content of @inf from the current position to @outf.
 * Copies @length bytes, unless @length is -1, in this case copies till EOF.
 *
 * Return: number of bytes copied, could be 0.
 */
#define BLOCKSIZE 4096
off_t copy_file(FILE *inf, FILE *outf, off_t length)
{
	void *buffer;
	off_t counter = 0;
	size_t ret;

	buffer = malloc(BLOCKSIZE);
	if (!buffer)
		return 0;

	while (length > 0 || length == -1) {
		size_t toread;

		if (length == -1)
			toread = BLOCKSIZE;
		else
			toread = length > BLOCKSIZE ? BLOCKSIZE : length;

		ret = fread(buffer, 1, toread, inf);
		if (ret <= 0)
			break;
		ret = fwrite(buffer, 1, ret, outf);
		if (ret <= 0)
			break;

		if (length > 0)
			length -= ret;
		counter += ret;
	}

	free(buffer);

	return counter;
}

/* open a file for writing, returning NULL and "-" as "stdout" */
static FILE *open_output_file(const char *outfn, const char *action)
{
	FILE *outf;

	if (!outfn || !strcmp(outfn, "-"))
		return stdout;

	outf = fopen(outfn, "r+b");
	if (!outf && errno == ENOENT)
		outf = fopen(outfn, "wb");

	if (!outf)
		perror(outfn);

	return outf;
}

static void usage(FILE *stream, const char *progname)
{
	fprintf(stream, "usage: %s <action> [-vh] [-n name] [-o outputfile] [inputfile]\n",
		progname);
	fprintf(stream, "\tinfo: print information about the image\n");
	fprintf(stream, "\textract -n <id>: extract part of image\n");
	fprintf(stream, "\t-o filename: output file name for extract\n");
	fprintf(stream, "\t-v: more verbose output\n");
	fprintf(stream, "\t-h: this help screen\n");
}

int main(int argc, char **argv)
{
	FILE *inf, *outf = NULL;
	int option;
	char *action, *outfn = NULL;
	char *name = NULL;
	bool verbose = false;

	while ((option = getopt(argc, argv, "n:o:hv")) != -1) {
		switch (option) {
		case 'o':
			outfn = optarg;
			break;
		case 'h':
			usage(stdout, argv[0]);
			return 0;
		case 'n':
			name = optarg;
			break;
		case 'v':
			verbose = true;
			break;
		case '?':
			break;
		}
	}

	/* The first non-option argument is the action verb. */
	if (optind >= argc) {
		usage(stderr, argv[0]);
		return 1;
	}
	action = argv[optind];

	/* The second non-option argument is the (optional) input file. */
	if (optind + 1 < argc) {
		inf = fopen(argv[optind + 1], "rb");
		if (!inf) {
			perror(argv[optind + 1]);
			return 2;
		}
	} else {
		inf = stdin;
	}

	if (!strcmp(action, "info")) {
		output_image_info(inf, stdout, verbose);
	} else if (!strcmp(action, "extract")) {
		if (!name) {
			fprintf(stderr, "%s requires -n <name>\n", action);
			return 2;
		}
		outf = open_output_file(outfn, action);
		if (!outf)
			return 2;

		extract_image(inf, outf, name);
	} else {
		fprintf(stderr, "unknown action verb \"%s\"\n", action);
		usage(stderr, argv[0]);
		return 1;
	}

	if (inf)
		fclose(inf);
	if (outf)
		fclose(outf);

	return 0;
}
