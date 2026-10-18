/* VrKiller 打包器 —— 单文件可执行：自动检测内核 KMI，从内存注入对应的 vrkiller.ko
 *
 * 用法（root，任意目录）：
 *   ./vrkiller          自动: uname -> 认 KMI -> init_module 内存装载 -> 回读 dmesg 打印"结论"行
 *   ./vrkiller clean    rmmod（清理残留）
 *
 * 嵌入 8 个 GKI KMI（android12-5.10 ~ android17-6.18），ko 数据全在二进制内，
 * 不写临时文件，不调外部 insmod。
 *
 * ENOEXEC 重试（v4 阶梯，不编名字抄答案）：内核对 modversions 模块按
 * same_magic 跳过 vermagic 首 token（release）只 strcmp 余部
 * （kernel/module/version.c:80）——vivo 把自有 token 烤进 arch 前，余部
 * 对不上即 ENOEXEC。门判错时把期望串原话 pr_err 进日志，故：
 *   A. finit_module(IGNORE_VERMAGIC)（FORCE_LOAD=y 才有效，GKI 默认 =n）
 *   B. klogctl 抄期望串 → B1 短 release+flags 原文原地回填 / B2 全串回填
 *      （放不下才做 .modinfo 撑长 ELF 移位，见 vmagic.c）
 *   C. klog 不可读 → uname+原 flags(+vivo) 构造兜底
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include "embed.h"
#include "vmagic.h"

struct vk { const char *kmi; const unsigned char *data; unsigned long len; };
static const struct vk table[] = {
    {"android12-5.10", vk_android12_5_10, vk_android12_5_10_len},
    {"android13-5.10", vk_android13_5_10, vk_android13_5_10_len},
    {"android13-5.15", vk_android13_5_15, vk_android13_5_15_len},
    {"android14-5.15", vk_android14_5_15, vk_android14_5_15_len},
    {"android14-6.1",  vk_android14_6_1,  vk_android14_6_1_len},
    {"android15-6.6",  vk_android15_6_6,  vk_android15_6_6_len},
    {"android16-6.12", vk_android16_6_12, vk_android16_6_12_len},
    {"android17-6.18", vk_android17_6_18, vk_android17_6_18_len},
};

static void print_kernel_log(void)
{
    char buf[65536];
    long n = syscall(SYS_syslog, 3, buf, (long)sizeof buf - 1); /* SYSLOG_ACTION_READ_ALL */
    if (n <= 0) {
        printf("vrkiller: 内核日志读取失败(%s)，请手动 dmesg | grep vrkiller\n", strerror(errno));
        return;
    }
    buf[n] = 0;
    int shown = 0;
    for (char *p = buf, *e; (e = strchr(p, '\n')); p = e + 1) {
        *e = 0;
        if (strstr(p, "vrkiller")) { printf("  %s\n", p); shown++; }
    }
    if (!shown) printf("vrkiller: 内核日志暂无 vrkiller 行（可能有延迟，稍后 dmesg | grep vrkiller）\n");
}

static const char *blob_vermagic(const void *blob, unsigned long len)
{
    const unsigned char *v = memmem(blob, len, "vermagic=", 9);
    if (!v) return NULL;
    v += 9;
    if (!memchr(v, 0, len - (unsigned long)(v - (const unsigned char *)blob))) return NULL;
    return (const char *)v;
}

static long load_with_vermagic(const unsigned char *data, unsigned long len,
                               const char *vm, const char *label)
{
    unsigned long plen = len;
    unsigned char *buf = malloc(len);
    long r = -1;
    if (buf) {
        memcpy(buf, data, len);
        if (vk_patch_vermagic(&buf, &plen, vm) == 0) {
            printf("vrkiller: vermagic 回填 '%s'（%s），重试装载\n", vm, label);
            r = syscall(SYS_init_module, buf, plen, "");
        } else {
            printf("vrkiller: vermagic 补丁失败（ELF 结构异常？）\n");
        }
        free(buf);
    }
    return r;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 1 && !strcmp(argv[1], "clean")) {
        if (syscall(SYS_delete_module, "vrkiller", 0) == 0) printf("vrkiller: 已卸载\n");
        else printf("vrkiller: 卸载失败: %s\n", strerror(errno));
        return 0;
    }

    struct utsname u;
    if (uname(&u)) { printf("vrkiller: uname 失败: %s\n", strerror(errno)); return 1; }
    printf("vrkiller: 内核 %s\n", u.release);

    /* KMI = android<rel>-<maj.min>，从 release 的 androidN-M 段 + 版本前缀合成 */
    char *a = strstr(u.release, "android");
    int arel = 0, gen = 0, maj = 0, min = 0;
    if (a) sscanf(a, "android%d-%d", &arel, &gen);
    sscanf(u.release, "%d.%d", &maj, &min);
    if (!arel || !maj) {
        printf("vrkiller: 无法从内核版本串解析 KMI，拒绝盲装\n");
        return 1;
    }
    char kmi[32];
    snprintf(kmi, sizeof kmi, "android%d-%d.%d", arel, maj, min);

    const struct vk *vk = NULL;
    for (size_t i = 0; i < sizeof table / sizeof table[0]; i++)
        if (!strcmp(table[i].kmi, kmi)) { vk = &table[i]; break; }
    if (!vk) {
        printf("vrkiller: KMI %s 不在嵌入表内（支持: android12-5.10 android13-5.10 "
               "android13-5.15 android14-5.15 android14-6.1 android15-6.6 android16-6.12 "
               "android17-6.18），拒绝盲装\n", kmi);
        return 1;
    }
    printf("vrkiller: 命中嵌入模块 vrkiller-%s.ko（%lu 字节）\n", vk->kmi, vk->len);

    /* 已在场则不重复注入 */
    FILE *m = fopen("/proc/modules", "r");
    if (m) {
        char line[128]; int loaded = 0;
        while (fgets(line, sizeof line, m))
            if (!strncmp(line, "vrkiller ", 9)) { loaded = 1; break; }
        fclose(m);
        if (loaded) {
            printf("vrkiller: 模块已在场，跳过注入，直接读结论\n");
            print_kernel_log();
            return 0;
        }
    }

    long r = syscall(SYS_init_module, vk->data, vk->len, "");
    if (r != 0 && errno == ENOEXEC) {
        /* 阶梯（不编名字，抄内核的答案）：
         * A. finit_module(IGNORE_VERMAGIC)——FORCE_LOAD=y 的内核一步过（GKI =n，无声败）
         * B. klog 收割内核 pr_err 的期望串（门自己交钥匙）：
         *    B1. modversions 内核跳过首 token → "0"+内核 flags 原文，原地放下
         *    B2. 非 modversions/放不下 → 全串原样回填（必要时 ELF 撑长手术）
         * C. klog 不可读 → uname+原 flags(+vivo) 构造兜底 */
        int fd = (int)syscall(SYS_memfd_create, "vrkiller", 1u /*MFD_CLOEXEC*/);
        if (fd >= 0) {
            ssize_t wn = write(fd, vk->data, vk->len);
            if (wn == (ssize_t)vk->len) {
                printf("vrkiller: A 路 finit_module(IGNORE_VERMAGIC) …\n");
                r = syscall(SYS_finit_module, fd, "", 2u /*MODULE_INIT_IGNORE_VERMAGIC*/);
                if (r != 0) printf("vrkiller: A 路败: %s\n", strerror(errno));
            }
            close(fd);
        }
        if (r != 0) {
            char *target = vk_harvest_vermagic();
            const char *src = "内核日志";
            if (target) {
                printf("vrkiller: 内核期望 vermagic '%s'\n", target);
            } else {
                src = "uname 构造";
                const char *ko_vm = blob_vermagic(vk->data, vk->len);
                target = ko_vm ? vk_build_vermagic(ko_vm) : NULL;
                if (target) printf("vrkiller: 内核日志不可读，uname 构造 '%s'\n", target);
            }
            if (!target) {
                printf("vrkiller: 期望 vermagic 不可得（klog/uname 双败）\n");
            } else {
                char *sp = strchr(target, ' ');
                if (sp && strcmp(src, "uname 构造") != 0) {
                    char shortvm[200];
                    snprintf(shortvm, sizeof shortvm, "0%s", sp); /* release=自由位 */
                    r = load_with_vermagic(vk->data, vk->len, shortvm, "B1 短串");
                    if (r != 0 && strcmp(shortvm, target))
                        r = load_with_vermagic(vk->data, vk->len, target, "B2 全串");
                } else {
                    r = load_with_vermagic(vk->data, vk->len, target, src);
                }
            }
            free(target);
        }
    }
    if (r != 0) {
        printf("vrkiller: 结论 —— 注入失败: %s\n", strerror(errno));
        if (errno == EPERM)  printf("vrkiller: （EPERM 多半是内核模块签名强制）\n");
        if (errno == EEXIST) printf("vrkiller: （EEXIST 模块已存在，跑 clean 后重试）\n");
        print_kernel_log();   /* 内核侧真实拒绝原因（unknown symbol / 签名 / vermagic）随结论一起给 */
        return 1;
    }
    printf("vrkiller: 注入成功，等待内核日志 ...\n");
    usleep(300000);
    print_kernel_log();
    return 0;
}
