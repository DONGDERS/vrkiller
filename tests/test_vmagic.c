/* test_vmagic.c —— v4 补丁/解析宿主单测（x86_64 上验 aarch64 LE blob）
 * 编译：gcc -I pack pack/vmagic.c pack/embed.c tests/test_vmagic.c -o /tmp/tvm
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>
#include "vmagic.h"
#include "embed.h"

static int fails = 0;
#define CHECK(c, msg...) do { if (!(c)) { printf("FAIL: " msg); fails++; } } while (0)

static uint64_t rd64(const unsigned char *p){ uint64_t v; memcpy(&v,p,8); return v; }
static uint32_t rd32(const unsigned char *p){ uint32_t v; memcpy(&v,p,4); return v; }
static uint16_t rd16(const unsigned char *p){ uint16_t v; memcpy(&v,p,2); return v; }

/* 结构+内容全面校验：ELF 合法、各段文件内、对齐保持、除 .modinfo 外逐字节不变、
 * .modinfo 里 vermagic=target 且其余条目按原序保留 */
static void validate(const unsigned char *orig, unsigned long olen,
                     const unsigned char *img, unsigned long nlen,
                     const char *target, const char *name)
{
    (void)olen;
    CHECK(!memcmp(img, ELFMAG, 3) && img[4] == ELFCLASS64, "%s: ELF magic/class\n", name);
    CHECK(rd16(img+16) == ET_REL, "%s: ET_REL\n", name);
    uint64_t shoff = rd64(img+40);
    uint16_t shnum = rd16(img+60), shentsize = rd16(img+58);
    CHECK(shentsize == sizeof(Elf64_Shdr), "%s: shentsize %u\n", name, shentsize);
    CHECK(shoff && shoff + (uint64_t)shnum * shentsize <= nlen, "%s: shdr table in file\n", name);

    int modinfo_idx = -1;
    for (int i = 0; i < shnum; i++) {
        const unsigned char *h = img + shoff + (uint64_t)i * shentsize;
        uint32_t type = rd32(h+4);
        uint64_t off = rd64(h+24), size = rd64(h+32), align = rd64(h+48);
        if (type != SHT_NOBITS)
            CHECK(off + size <= nlen, "%s: sec %d in file\n", name, i);
        if (align > 1)
            CHECK(off % align == 0, "%s: sec %d off %llu not align %llu\n",
                  name, i, (unsigned long long)off, (unsigned long long)align);
    }
    /* 用原文件的节名表定位 .modinfo */
    {
        uint64_t o_shoff = rd64(orig+40);
        uint16_t o_shnum = rd16(orig+60);
        uint16_t shstrndx = rd16(orig+62);
        const unsigned char *osh = orig + o_shoff + (uint64_t)shstrndx * shentsize;
        const char *shstr = (const char *)orig + rd64(osh+24);
        for (int i = 0; i < o_shnum; i++) {
            const unsigned char *h = orig + o_shoff + (uint64_t)i * shentsize;
            if (!strcmp(shstr + rd32(h), ".modinfo")) { modinfo_idx = i; break; }
        }
    }
    CHECK(modinfo_idx >= 0, "%s: found .modinfo\n", name);

    for (int i = 0; i < shnum; i++) {
        const unsigned char *oh = orig + rd64(orig+40) + (uint64_t)i * shentsize;
        const unsigned char *nh = img + shoff + (uint64_t)i * shentsize;
        uint32_t type = rd32(nh+4);
        uint64_t ooff = rd64(oh+24), osize = rd64(oh+32);
        uint64_t noff = rd64(nh+24), nsize = rd64(nh+32);
        if (i == modinfo_idx) {
            CHECK(nsize >= osize, "%s: modinfo size grew\n", name);
            /* 条目序=链接序，vermagic 不一定是首条——在节内定位 */
            const unsigned char *nv = memmem(img + noff, nsize, "vermagic=", 9);
            const unsigned char *ov = memmem(orig + ooff, osize, "vermagic=", 9);
            CHECK(nv && ov, "%s: vermagic entry present\n", name);
            if (!nv || !ov) continue;
            const char *val = (const char *)nv + 9;
            CHECK(!strncmp(val, target, strlen(target)) && val[strlen(target)] == 0,
                  "%s: vermagic value == target\n", name);
            /* 其余 modinfo 条目按原序保留（从各自 vermagic 条目之后走） */
            const char *op = (const char *)ov + 9 + strlen((const char *)ov + 9) + 1;
            const char *oe = (const char *)orig + ooff + osize;
            const char *np = val + strlen(target) + 1;
            const char *ne = (const char *)img + noff + nsize;
            while (op < oe && *op) {
                while (np < ne && !*np) np++;   /* 补丁垫的空条目（NUL）跳过 */
                CHECK(np < ne && !strcmp(op, np), "%s: entry '%.40s' preserved\n", name, op);
                op += strlen(op) + 1;
                np += strlen(np) + 1;
            }
        } else if (type != SHT_NOBITS) {
            CHECK(osize == nsize, "%s: sec %d size unchanged\n", name, i);
            CHECK(!memcmp(orig+ooff, img+noff, osize), "%s: sec %d bytes unchanged\n", name, i);
        }
    }
}

static void test_ko(const unsigned char *data, unsigned long len, const char *kmi,
                    const char *long_target, const char *short_target)
{
    unsigned char *b1 = malloc(len);
    unsigned long n1 = len;
    memcpy(b1, data, len);
    int rc = vk_patch_vermagic(&b1, &n1, long_target);
    CHECK(rc == 0, "%s: long patch rc=%d\n", kmi, rc);
    if (rc == 0) validate(data, len, b1, n1, long_target, kmi);

    /* 在已撑长的镜像上再补短串 */
    unsigned char *b2 = malloc(n1);
    unsigned long n2 = n1;
    memcpy(b2, b1, n1);
    rc = vk_patch_vermagic(&b2, &n2, short_target);
    CHECK(rc == 0, "%s: short-on-grown patch rc=%d\n", kmi, rc);
    if (rc == 0) validate(b1, n1, b2, n2, short_target, kmi);
    free(b2); free(b1);

    /* 原生镜像直接补短串（大多数 ko 应走原地） */
    unsigned char *b3 = malloc(len);
    unsigned long n3 = len;
    memcpy(b3, data, len);
    rc = vk_patch_vermagic(&b3, &n3, short_target);
    CHECK(rc == 0, "%s: short patch rc=%d\n", kmi, rc);
    if (rc == 0) {
        validate(data, len, b3, n3, short_target, kmi);
        if (n3 == len) printf("  %s: short patch in-place\n", kmi);
        else printf("  %s: short patch grew +%lu\n", kmi, n3 - len);
    }
    free(b3);

    /* 幂等：目标已等于各 ko 自己的当前值时返回 0 且不动（用原值而非固定串） */
    const unsigned char *ov = memmem(data, len, "vermagic=", 9);
    CHECK(ov != NULL, "%s: own vermagic present\n", kmi);
    if (ov) {
        char own[192];
        size_t ol = strnlen((const char *)ov + 9, len - (unsigned long)(ov - data) - 9);
        CHECK(ol < sizeof own, "%s: own vermagic len %zu\n", kmi, ol);
        if (ol < sizeof own) {
            memcpy(own, ov + 9, ol); own[ol] = 0;
            unsigned char *b4 = malloc(len);
            unsigned long n4 = len;
            memcpy(b4, data, len);
            rc = vk_patch_vermagic(&b4, &n4, own);
            CHECK(rc == 0 && n4 == len, "%s: idempotent\n", kmi);
            free(b4);
        }
    }
}

static void test_parse(void)
{
    /* 用例 1：真实设备日志行（v3 失败现场，两条） */
    const char *reallog =
        "<14>[21721.985551] vrkiller: vrkiller: version magic '6.1.166-dirty SMP preempt mod_unload modversions aarch64' should be '6.1.145-android14-11-maybe-dirty SMP preempt mod_unload modversions vivo aarch64'\n"
        "<14>[21721.985719] vrkiller: vrkiller: version magic '6.1 SMP preempt mod_unload modversions aarch64 vivo ' should be '6.1.145-android14-11-maybe-dirty SMP preempt mod_unload modversions vivo aarch64'\n";
    char *got = vk_parse_vermagic(reallog, (long)strlen(reallog));
    CHECK(got && !strcmp(got, "6.1.145-android14-11-maybe-dirty SMP preempt mod_unload modversions vivo aarch64"),
          "parse real log: got '%s'\n", got ? got : "(null)");
    free(got);

    /* 用例 2：缓冲首行被截断（尾部完整） */
    const char *trunc = "SMP preempt modversions aarch64' should be '5.10.101-android13-8 SMP preempt mod_unload modversions aarch64'\n";
    got = vk_parse_vermagic(trunc, (long)strlen(trunc));
    CHECK(got && !strcmp(got, "5.10.101-android13-8 SMP preempt mod_unload modversions aarch64"),
          "parse truncated-head: got '%s'\n", got ? got : "(null)");
    free(got);

    /* 用例 3：无匹配 → NULL */
    got = vk_parse_vermagic("hello world\nno magic here\n", 26);
    CHECK(!got, "parse no-match\n");
    free(got);

    /* 用例 4：期望串跨行 → 拒绝 */
    const char *broken = "should be '6.1.145-android14-11-maybe-dirty\n SMP preempt aarch64'\n";
    got = vk_parse_vermagic(broken, (long)strlen(broken));
    CHECK(!got, "parse cross-line reject\n");
    free(got);

    /* 用例 5：非数字开头 → 拒绝 */
    got = vk_parse_vermagic("should be 'SMP preempt aarch64'\n", 32);
    CHECK(!got, "parse non-digit reject\n");
    free(got);
}

int main(void)
{
    const char *LONG_T = "6.1.145-android14-11-maybe-dirty SMP preempt mod_unload modversions vivo aarch64";
    const char *SHORT_T = "0 SMP preempt mod_unload modversions vivo aarch64";
    test_ko(vk_android12_5_10, vk_android12_5_10_len, "android12-5.10", LONG_T, SHORT_T);
    test_ko(vk_android13_5_10, vk_android13_5_10_len, "android13-5.10", LONG_T, SHORT_T);
    test_ko(vk_android13_5_15, vk_android13_5_15_len, "android13-5.15", LONG_T, SHORT_T);
    test_ko(vk_android14_5_15, vk_android14_5_15_len, "android14-5.15", LONG_T, SHORT_T);
    test_ko(vk_android14_6_1,  vk_android14_6_1_len,  "android14-6.1",  LONG_T, SHORT_T);
    test_ko(vk_android15_6_6,  vk_android15_6_6_len,  "android15-6.6",  LONG_T, SHORT_T);
    test_ko(vk_android16_6_12, vk_android16_6_12_len, "android16-6.12", LONG_T, SHORT_T);
    test_ko(vk_android17_6_18, vk_android17_6_18_len, "android17-6.18", LONG_T, SHORT_T);
    test_parse();

    /* uname 构造路径（宿主环境跑通即可，验证格式） */
    char *built = vk_build_vermagic("6.1.166-dirty SMP preempt mod_unload modversions aarch64");
    CHECK(built && strlen(built) > 10 && strstr(built, "SMP preempt mod_unload modversions aarch64"),
          "build: '%s'\n", built ? built : "(null)");
    free(built);

    if (fails) { printf("%d FAILURES\n", fails); return 1; }
    printf("ALL TESTS PASS\n");
    return 0;
}
