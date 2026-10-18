/* vmagic.h —— vermagic 收割/构造/ELF 补丁（v4），见 vmagic.c 头注 */
#ifndef VK_VMAGIC_H
#define VK_VMAGIC_H

#include <elf.h>
#include <string.h>
#include <sys/syscall.h>

int  vk_patch_vermagic(unsigned char **pimg, unsigned long *plen, const char *target);
char *vk_parse_vermagic(const char *buf, long n);
char *vk_harvest_vermagic(void);
char *vk_build_vermagic(const char *ko_vermagic);

#endif
