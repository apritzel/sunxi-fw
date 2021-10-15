#ifndef __SUNXI_FW_H__
#define __SUNXI_FW_H__

#include <stdint.h>
#include <stdbool.h>

enum image_type {
	IMAGE_ERROR,
	IMAGE_SHORT,
	IMAGE_UNKNOWN,
	IMAGE_BOOT0,
	IMAGE_SPL1,
	IMAGE_SPL2,
	IMAGE_SPLx,
	IMAGE_TOC0,
	IMAGE_UBOOT,
	IMAGE_FIT,
	IMAGE_MBR,
	IMAGE_GPT,
	IMAGE_ROCKCHIP,
	IMAGE_AML,
};

/* Like lseek(), but works on pipes as well. Implies SEEK_CUR. */
int pseek(FILE *stream, long offset);

/*
 * Copy the content of <inf> from the current position to <outf>.
 * Copy <length> bytes, unless <length> is -1, in this case copy till EOF.
 */
off_t copy_file(FILE *inf, FILE *outf, off_t length);

/* sunxi-img.c */
enum image_type identify_image(const void *buffer);
int find_firmware_image(FILE *inf, enum image_type img, void *sector,
			FILE *outf);
int extract_image(FILE *inf, FILE *outf, const char *extract);
void output_image_info(FILE *inf, FILE *outf, bool verbose, bool scan_all);

/**
 * output_*_info(): output information about image type
 * sector: pointer to buffer containing the first sector (512 bytes)
 * inf: input stream, for reading further data
 * stream: output stream, for dumping information
 * verbose: whether to output more elaborate information
 */

/* sunxi-mbr.c */
int output_mbr_info(void *sector, FILE *inf, FILE *stream, bool verbose);

/* sunxi-spl.c */
int output_spl_info(void *sector, FILE *inf, FILE *stream, bool verbose);
int spl_set_dtname(void *sector, FILE *inf, const char *dts, FILE *outf);
int handle_dt_name(FILE *inf, const char *dt_name, FILE *outf);

/* sunxi-boot0.c */
int output_boot0_info(void *sector, FILE *inf, FILE *stream, bool verbose);

/* sunxi-toc0.c */
void output_toc0_info(void *sector, FILE *inf, FILE *stream, bool verbose);

/* sunxi-uboot.c */
void output_uboot_info(void *sector, FILE *inf, FILE *stream, bool verbose);
void dump_uboot_legacy(void *sector, FILE *inf, FILE *outf, bool payload);

/* sunxi-fit.c */
void extract_fit_image(void *sector, FILE *inf, FILE *outf, const char *imgname);
int dump_dt_info(void *sector, FILE *inf, FILE *outf, bool verbose);
int dump_dt_names(FILE *inf, FILE *outf);

#endif
