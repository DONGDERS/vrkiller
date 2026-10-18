/* vmagic.c —— vermagic 收割/构造/ELF 补丁（v4）
 *
 * 机制（已对 v6.1 内核源码 kernel/module/version.c:80 核实）：
 *   same_magic(): modversions 下双方各 strcspn(vermagic," ") 跳过首 token
 *   （release），对余部（flags）strcmp —— v3 的"跳首 token"理论没错，
 *   错在构造的余部：vivo token 拼到了 aarch64 后面还带尾空格。
 *   v4 不再构造：首次 ENOEXEC 后 klogctl 收割内核日志里
 *   "version magic '...' should be '...'" 的期望串原样回填，
 *   覆盖任意 token 摆位 / 任意 flags / 非 modversions 内核（全量 strcmp）。
 *
 * 回填值常比原值长（如 6.1.145-android14-11-maybe-dirty … 81 字节 vs 56），
 * 原地写不下 → .modinfo 条目后整体后移（pad 上取整到 64，保各段
 * sh_offset 对齐），修 e_shoff / 各 sh_offset / .modinfo 的 sh_size；
 * 变短则原地写 + 残区清零（modinfo 里空串项被内核扫描器无害跳过）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/utsname.h>
#include "vmagic.h"

/* ---- ELF64 小端读写（blob=aarch64 LE，宿主自测=x86_64 LE，一致） ---- */
static uint64_t rd64(const unsigned char *p){ uint64_t v; memcpy(&v,p,8); return v; }
static uint32_t rd32(const unsigned char *p){ uint32_t v; memcpy(&v,p,4); return v; }
static uint16_t rd16(const unsigned char *p){ uint16_t v; memcpy(&v,p,2); return v; }
static void wr64(unsigned char *p, uint64_t v){ memcpy(p,&v,8); }

#define SHDR_OFF(h)  rd64((h)+24)
#define SHDR_SIZE(h) rd64((h)+32)
#define SHDR_TYPE(h) rd32((h)+4)
#define SHT_NOBITS_  8
#define ET_REL_      1

/* 把 blob 的 vermagic 值改写为 target（可能伸缩 blob，pimg/plen 指针更新）。
 * 返回 0=成功；-1=结构异常。已是 target 时直接返回 0。 */
#ifdef VKDEBUG
#define DBGRET(v, ...) do { printf("  [patch] ret %d: ", (v)); printf(__VA_ARGS__); } while(0)
#else
#define DBGRET(v, ...) do {} while(0)
#endif
int vk_patch_vermagic(unsigned char **pimg, unsigned long *plen, const char *target)
{
    unsigned char *img = *pimg;
    unsigned long len  = *plen;
    if (len < 64 || memcmp(img, ELFMAG, 4) != 0) { DBGRET(-1, "len/magic\\n"); return -1; }
    if (img[4] != 2 || img[5] != 1) { DBGRET(-1, "class\\n"); return -1; }
    if (rd16(img+16) != ET_REL_) { DBGRET(-1, "not ET_REL\\n"); return -1; }

    uint64_t e_shoff = rd64(img+40);
    uint16_t e_phnum = rd16(img+56), e_shentsize = rd16(img+58), e_shnum = rd16(img+60);
    uint64_t e_phoff = rd64(img+32);
    if (!e_shnum || e_shentsize < 64 || e_shoff + (uint64_t)e_shnum*e_shentsize > len) { DBGRET(-1, "shdr bounds\\n"); return -1; }

    unsigned char *v = memmem(img, len, "vermagic=", 9);
    if (!v) { DBGRET(-1, "no vermagic=\\n"); return -1; }
    v += 9;
    unsigned long oldlen = strnlen((char *)v, len - (unsigned long)(v - img));
    if (oldlen == len - (unsigned long)(v - img)) { DBGRET(-1, "no NUL\\n"); return -1; }
    size_t tlen = strlen(target);
    if (tlen > 255) { DBGRET(-1, "tlen>255\\n"); return -1; }
    if (oldlen == tlen && !memcmp(v, target, tlen)) return 0; /* 已是目标 */

    /* 找到包含 vermagic 的 section（.modinfo），拿它的 header */
    unsigned char *shbase = img + e_shoff;
    long midx = -1;
    unsigned long voff = (unsigned long)(v - 9 - img);
    for (uint16_t i = 0; i < e_shnum; i++) {
        const unsigned char *h = shbase + (uint64_t)i*e_shentsize;
        if (SHDR_TYPE(h) == SHT_NOBITS_) continue;
        uint64_t so = SHDR_OFF(h), ss = SHDR_SIZE(h);
        if (so <= voff && voff < so + ss) { midx = i; break; }
    }
    if (midx < 0) { DBGRET(-1, "no containing sec (voff=%lu)\\n", (unsigned long)voff); return -1; }

    unsigned long entry_end = voff + 9 + oldlen + 1; /* 条目 NUL 之后（blob 内偏移） */
    long delta = (long)(9 + tlen + 1) - (long)(9 + oldlen + 1);

    if (delta <= 0) {   /* 变短/等长：原地写 + 残区清零 */
        memcpy(v, target, tlen);
        memset(v + tlen, 0, oldlen + 1 - tlen);
        return 0;
    }

    /* 变长：条目后整体后移 pad（上取整到 64 保 sh_offset 对齐） */
    size_t pad = ((size_t)delta + 63) & ~(size_t)63;
    unsigned char *ni = realloc(img, len + pad);
    if (!ni) { DBGRET(-1, "realloc\\n"); return -1; }
    img = ni;
    memmove(img + entry_end + pad, img + entry_end, len - entry_end);
    memcpy(img + voff, "vermagic=", 9);          /* 键必须随条目重写，voff 是键起点 */
    memcpy(img + voff + 9, target, tlen);
    img[voff + 9 + tlen] = 0;
    /* 新条目尾到移位尾之间的空隙清零（空 modinfo 项，内核扫描器无害跳过）；
     * 顺序必须在写条目之后，且起点是新条目尾，否则会擦掉 target 尾部 */
    memset(img + voff + 9 + tlen + 1, 0,
           entry_end + pad - (voff + 9 + tlen + 1));

    if (e_shoff >= entry_end) { e_shoff += pad; wr64(img+40, e_shoff); }
    if (e_phnum && e_phoff >= entry_end) { e_phoff += pad; wr64(img+32, e_phoff); }
    shbase = img + e_shoff;
    for (uint16_t i = 0; i < e_shnum; i++) {
        unsigned char *h = shbase + (uint64_t)i*e_shentsize;
        uint64_t so = SHDR_OFF(h);
        if (so >= entry_end) { wr64(h+24, so + pad); continue; }
        if ((long)i == midx) { wr64(h+32, SHDR_SIZE(h) + pad); continue; }
        /* 其他段不可能横跨 entry_end（不重叠），NOBITS 无文件内容 */
    }
    if (e_phnum && e_phoff && e_phoff + (uint64_t)e_phnum*56 <= len) {
        for (uint16_t i = 0; i < e_phnum; i++) {
            unsigned char *p = img + e_phoff + (uint64_t)i*56;
            uint64_t po = rd64(p+8);
            if (po >= entry_end) { wr64(p+8, po + pad); continue; }
            uint64_t pf = rd64(p+32);
            if (po + pf > entry_end) wr64(p+32, pf + pad);
        }
    }
    *pimg = img;
    *plen = len + pad;
    return 0;
}

/* 解析内核日志：最后一条 "version magic '...' should be '...'" 的期望串。
 * 成功返回 malloc 串，失败返回 NULL。（独立导出供宿主单测） */
char *vk_parse_vermagic(const char *buf, long n)
{
    if (!buf || n <= 0) return NULL;
    const char *found = NULL;
    for (const char *p = buf; (p = strstr(p, "should be '")) != NULL; p += 11)
        found = p + 11;   /* 取最后一条 */
    if (!found) return NULL;
    const char *end = strchr(found, '\'');
    if (!end || end == found || (size_t)(end - found) > 200) return NULL;
    size_t tlen = (size_t)(end - found);
    /* 期望串必须是 release 开头（数字）+ 引号或行尾前不跨界 */
    if (*found < '0' || *found > '9' || strcspn(found, "'\r\n") != tlen) return NULL;
    char *out = malloc(tlen + 1);
    if (!out) return NULL;
    memcpy(out, found, tlen);
    out[tlen] = 0;
    return out;
}

/* 从内核日志收割期望 vermagic。成功返回 malloc 串，失败返回 NULL。
 * root + CAP_SYSLOG 下必成；READ_ALL 取环形缓冲尾部，本次失败的
 * 拒绝行必在尾部且完整。 */
char *vk_harvest_vermagic(void)
{
    size_t cap = 256 * 1024;
    char *buf = malloc(cap);
    if (!buf) return NULL;
    long n = syscall(SYS_syslog, 3, buf, (long)cap - 1); /* READ_ALL=尾部 */
    if (n <= 0) { free(buf); return NULL; }
    buf[n] = 0;
    char *out = vk_parse_vermagic(buf, n);
    free(buf);
    return out;
}

/* 兜底构造：uname 完整 release（含 -maybe-dirty 等）+ ko 原 flags，
 * /proc/version 含 " vivo" 时在末 token（arch）前插入 vivo（实测摆位）。
 * 成功返回 malloc 串。 */
char *vk_build_vermagic(const char *ko_vermagic)
{
    struct utsname u;
    if (uname(&u)) return NULL;
    const char *sp = strchr(ko_vermagic, ' ');
    if (!sp) return NULL;

    char procver[512] = "";
    FILE *f = fopen("/proc/version", "r");
    if (f) { size_t k = fread(procver, 1, sizeof procver - 1, f); procver[k] = 0; fclose(f); }
    int vivo = strstr(procver, " vivo") != NULL;

    /* flags 首尾去空格 */
    while (*sp == ' ') sp++;
    char flags[160];
    snprintf(flags, sizeof flags, "%s", sp);
    size_t fl = strlen(flags);
    while (fl && flags[fl-1] == ' ') flags[--fl] = 0;

    char out[256];
    if (vivo) {
        char *arch = strrchr(flags, ' ');       /* 末 token = arch（aarch64） */
        if (arch) {
            *arch = 0;
            snprintf(out, sizeof out, "%s %s vivo %s", u.release, flags, arch+1);
        } else {
            snprintf(out, sizeof out, "%s %s vivo", u.release, flags);
        }
    } else {
        snprintf(out, sizeof out, "%s %s", u.release, flags);
    }
    return strdup(out);
}
