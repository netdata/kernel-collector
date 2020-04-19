# Compilation as normal user

The `kernel-collector` repository can be compiled as normal user, but before this it is neessary to do
some steps as `root`.

## Steps as root

Before to compile this repository, it is necessary to install the nessary packages available on your
Linux distribution. The complete list of packages can be found inside the Docker files on this repository.

Case you are trying to compile on a kernel newer than `5.0`, it will be necessary to disable the
`assembly inline`, this can be done editing the file `/usr/src/linux-5.4.33/include/generated/autoconf.h`
and commenting the line `//#define CONFIG_CC_HAS_ASM_INLINE 1`.

## Step as normal user

After to do the necessary installation, you only need to run the next commands to compile the repository:

```bash
$ cd user/
$ make
```