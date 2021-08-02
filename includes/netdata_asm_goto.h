#ifndef _NETDATA_ASM_GOTO_H_
# define _NETDATA_ASM_GOTO_H_ 1

/*
This header allows us to compile our code on RH 7.x family.
*/

# include <linux/types.h>
# include <linux/version.h>

# ifndef RHEL_RELEASE_VERSION
#  define RHEL_RELEASE_VERSION(x,y) ((x << 8) + (y))
# endif

# if RHEL_RELEASE_CODE && \
    RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8,0)
#  ifdef asm_volatile_goto
#   undef asm_volatile_goto
#   define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")
#  endif
# endif

#endif
