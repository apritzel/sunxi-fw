# sunxi-fw

`sunxi-fw` is a command line tool that allows to inspect and extract from
firmware images for Allwinner CPU based systems.

It can detect and decode several firmware components used in Allwinner firmware
images:

- MBR or GPT partition tables
- mainline U-Boot SPL images, both in eGON and TOC0 format
- Allwinner BSP boot0 images
- mainline U-Boot legacy images
- mainline U-Boot FIT images
- Allwinner proprietary PhoenixSuite firmware images

## invocation

```
$ ./sunxi-fw -h
usage: ./sunxi-fw <action> [-vah] [-n name] [-o outputfile] [inputfile]
        info: print information about the image
        extract -n <id>: extract part of image
        dt-name: print name of board devicetree in SPL header
        list-dt-names: list all DT names in FIT image
        -o filename: output file name for extract
        -v: more verbose output
        -a: scan all of input file for parts
        -h: this help screen
```

## usage examples

The `info` command without further options gives an overview, listing firmware
components and their names. Each component will be given an ID, followed by a
colon. The offsets at the beginning of a line are 512-byte sectors:

```
$ sunxi-fw info u-boot-sunxi-with-spl.bin
@   0: spl: U-Boot SPLv2
        DT: sun50i-a64-pine64-plus
@  64: fit: U-Boot FIT image
        fit:uboot: "U-Boot (64-bit)"
        fit:atf: "ARM Trusted Firmware"
        fit:scp: "SCP firmware"
        fit:fdt-1: "sun50i-a64-pine64"
        fit:fdt-2: "sun50i-a64-pine64-plus"
        configuration: sun50i-a64-pine64
        configuration: sun50i-a64-pine64-plus
```

Adding `-v` to the `info` command gives more output:

```
$ sunxi-fw info -v u-boot-sunxi-with-spl.bin
@   0: spl: U-Boot SPLv2
        DT: suniv-f1c200s-lctech-pi
        size: 24576 bytes
        eGON checksum matches: 0x323f3a85
        U-Boot SPL 2024.01-rc2 (Nov 21 2023 - 16:58:04 +0000)

@  64: u-boot.img: U-Boot legacy image
                size: 361092 bytes
                OS: U-Boot
                arch: ARM
                type: Firmware
                comp: 0
        u-boot: name: U-Boot 2024.01-rc2 for sunxi boa
```

The `extract` command can save any firmware component that was given a name:

    $ sunxi-fw extract -n fit:fdt-1 -o device.dtb u-boot-sunxi-with-spl.bin
    $ file device.dtb
    device.dtb: Device Tree Blob version 17, size=39744, boot CPU=0, string block size=3149, DT structure block size=36532

The input file can be any regular file, a device file like `/dev/sdb`, or even
the output of a UNIX pipe:

```
$ 7z e -so some_dodgy_BSP_based_vendor.img.7z | sunxi-fw info -v
@   0: wty: PhoenixSuite image file
        header v3.0, 45 images, 1924 MB
                wty:sys_config.fex      :      35838 bytes @ +0x0000b800
                wty:board.fex           :       1024 bytes @ +0x00014400
                wty:config.fex          :      53248 bytes @ +0x00014800
                wty:split_xxxx.fex      :        512 bytes @ +0x00021800
                wty:sys_partition.fex   :       5601 bytes @ +0x00021c00
                wty:sunxi.fex           :      72192 bytes @ +0x00023400
                wty:boot0_nand.fex      :      61440 bytes @ +0x00035000
                wty:boot0_sdcard.fex    :      61440 bytes @ +0x00044000
                wty:u-boot.fex          :     917504 bytes @ +0x00053000
	...
                wty:Vvbmeta_vendor.fex  :          4 bytes @ +0x7825bc00
                wty:dtbo.fex            :    2097152 bytes @ +0x7825c000
                wty:Vdtbo.fex           :          4 bytes @ +0x7845c000
@ 544: boot0: Allwinner boot0
        size: 61440 bytes
        eGON checksum matches: 0x4d570301
        DRAM parameters:        A64             H616
                DRAM clock  :       0x288       0x288           -
                DRAM type   :         0x3         0x3           -
                ZQ value    :   0x3030303           -           -
                ODT enabled :   0xe0e0e0e         0x1           -
                DX ODT      :           -   0x3030303           -
                DX DRI      :           -   0xe0e0e0e           -
                CA DRI      :           -      0x1f12           -
                PARA1       :      0x1f12      0x30fb           -
                PARA2       :         0x1           0           -
                MR0         :      0x30fb       0x840           -
                MR1         :           0         0x4           -
                MR2         :       0x840         0x8           -
                MR3         :         0x4           0           -
                TPR0        :         0x8  0xc0001002           -
                TPR6        :           0  0x33808080           -
                TRP10       :           0    0x2f1107           -
                TRP11       :           0  0xddddcccc           -
                TRP12       :  0xc0001002  0xeddc7665           -
                TRP13       :           0        0x40           -
```
