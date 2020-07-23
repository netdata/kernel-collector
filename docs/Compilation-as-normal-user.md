# Compilation as normal user

The `kernel-collector` repository can be compiled as normal user, but before doing this it is necessary 
to do some steps as `root`.

## Steps as root

Before compiling this repository, you have to install necessary packages available on your
Linux distribution. The complete list of packages can be found inside the Docker files in this repository.

In case you are trying to compile on a kernel newer than `5.0`, it will be necessary to disable the
`assembly inline`, this can be done by editing the file `/usr/src/linux/include/generated/autoconf.h`
and commenting the line `//#define CONFIG_CC_HAS_ASM_INLINE 1`.

Finally, if your distribution does not create the symbolic link `/usr/src/linux` to your kernel source,
you will need to do it manually.

## Step as normal user

After the necessary installation has been prepared, you need to run the next command to compile the repository:

```bash
$ make
```
