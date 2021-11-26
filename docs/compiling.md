# Compiling

## 1. Package Installs

Before compiling this repository, you have to install necessary packages
available on your Linux distribution. The complete list of packages can be
found inside the Docker files in this repository.

## 2. Linux Source Code Directory

Also, if your distribution does not create the symlink `/usr/src/linux`,
pointing to the latest Linux source code of your current live kernel, you
should make one now.

## 3. Disabling Inline Assembly

In case you are trying to compile on a kernel newer than `5.0`, it will be
necessary to disable the `assembly inline` option; this can be done by editing
the file `/usr/src/linux/include/generated/autoconf.h` and commenting the line
`//#define CONFIG_CC_HAS_ASM_INLINE 1`.

## 4. Compile

Now you can simply run `make`:

```bash
$ make -j`nproc`
```
