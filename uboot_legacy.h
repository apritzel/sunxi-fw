#ifndef __UBOOT_LEGACY_H__
#define __UBOOT_LEGACY_H__

#define IH_MAGIC        0x27051956      /* Image Magic Number           */
#define IH_NMLEN                32      /* Image Name Length            */

struct legacy_image_header {
	uint32_t	ih_magic;       /* Image Header Magic Number    */
	uint32_t	ih_hcrc;        /* Image Header CRC Checksum    */
	uint32_t	ih_time;        /* Image Creation Timestamp     */
	uint32_t	ih_size;        /* Image Data Size              */
	uint32_t	ih_load;        /* Data  Load  Address          */
	uint32_t	ih_ep;          /* Entry Point Address          */
	uint32_t	ih_dcrc;        /* Image Data CRC Checksum      */
	uint8_t		ih_os;          /* Operating System             */
	uint8_t		ih_arch;        /* CPU architecture             */
	uint8_t		ih_type;        /* Image Type                   */
	uint8_t		ih_comp;        /* Compression Type             */
	uint8_t		ih_name[IH_NMLEN];      /* Image Name           */
};

#ifdef UBOOT_LEGACY_NEED_NAMES

const char *uboot_legacy_os_type[] = {
	"Invalid OS", "OpenBSD", "NetBSD", "FreeBSD",
	"4.4BSD", "Linux", "SVR4", "Esix",
	"Solaris", "Irix", "SCO", "Dell",
	"NCR", "LynxOS", "VxWorks", "pSOS",
	"QNX", "U-Boot", "RTEMS", "ARTOS",
	"Unity OS", "INTEGRITY", "OSE", "Plan 9",
	"OpenRTOS",
};

const char *uboot_legacy_arch_name[] = {
	"invalid", "Alpha", "ARM", "x86",
	"IA64", "MIPS", "MIPS64", "PowerPC",
	"IBM_S390", "SuperH", "Sparc", "Sparc64",
	"M68K", "Nios-32", "MicroBlaze", "Nios-II",
	"Blackfin", "AVR32", "ST200", "Sandbox",
	"NDS32", "OpenRISC1K", "ARM64", "ARC",
	"x86_64", "Xtensa",
};

const char *uboot_legacy_image_type[] = {
	"invalid", "Standalone Program",
	"OS Kernel", "RAMDisk",
	"Multi-File", "Firmware",
	"Script file", "Filesystem",
	"Binary Flat Device Tree Blob", "Kirkwood Boot",
	"Freescale IMXBoot", "Davinci UBL",
	"TI OMAP Config Header", "TI Davinci AIS Image",
	"relocateable OS kernel", "Freescale PBL Boot",
	"Freescale MXSBoot", "TI Keystone GPHeader",
	"ATMEL ROM bootable", "Altera SOCFPGA Preloader",
	"x86 setup.bin",
};

#endif

#endif
