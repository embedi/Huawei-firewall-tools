These are some tools we developed during [Huawei USG-6330 research](https://embedi.com/blog/first-glance-on-os-vrp-by-huawei/).

Few tips:

 * To build binaries for the device, you will need [OCTEON-SDK toolchain](http://www.cnusers.org/index.php?option=com_remository&Itemid=32&func=fileinfo&id=181)
 * To temporarily put a file to Linux you can do the following - set up the ftp server on your computer, pull a file from it to a flash card of a firewall using VRP commands, log in to Linux and run ldfs_tst_get.out to pull the file to the Linux side. Retrieving files from Linux can be done in a similar manner and is easily automated.



# make-firmware-solid-again

This tool is used to view, retrieve, replace files from Huawei firmware containers. We tested it with a few firmwares of Huawei USG-6330, and it worked fine, but the code needs to be cleaned and slightly redesigned to work with firmwares of other devices (see object_types).

View which files firmware contains:

`python make-firmware-solid-again.py USG6000V100R001C30SPC600.bin -list`

Retrieve file from firmware:

`python make-firmware-solid-again.py USG6000V100R001C30SPC600.bin -extract ROOTFS`

Replace file/files:

`python make-firmware-solid-again.py USG6000V100R001C30SPC600.bin -filename "MP File!" -replacement VRP_patched -type lzma`

If you want to add more files, just add another group of `filename replacement type` to the command line.

Currently, the tool can handle files of two types - lzma (used when replacing VRP, for example) and bin (plain). For lzma compression, we used a separate binary since Python lzma module lacked the required compression parameters. We also could not implement adding of tar.gz archives because Python tarfile module had not those parameters as well. When we needed to replace a .tar.gz we did the following:

 * `tar cf usrbin_usg_mod.tar *; gzip -Nk --best usrbin_usg_mod.tar`
 * Replaced file in firmware with `-type bin`


# patch-dat-vrp

As input, it takes the .c file with the code of injection, path to the VRP file, the name of function the code of which will be overwritten, and optionally an address where to trampoline to the body will be written. The tool compiles the source code to the object file and parses it, looking for references to external function names, then resolves them with corresponding function addresses in VRP by patching the assembly code of injection. Finally, it replaces .text section of VRP with patched code. The script handles the VRP functions only, not global variables. So, they have to be hardcoded as addresses in a source of injection. Also, it can inject only one-function .c files – the code of main().

You can find a proper example in the article.


# huahooks

The library that implements hooking mechanism can be LD_PRELOAD'ed to every process (modify /etc/mpua.start). You can specify a process name, module name, and pattern you want to be hooked. 
For sample usage look at huahooks.c
