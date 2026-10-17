/* VrKiller 打包器 —— 单文件可执行：自动检测内核 KMI，从内存注入对应的 vrkiller.ko
 *
 * 用法（root，任意目录）：
 *   ./vrkiller          自动: uname -> 认 KMI -> init_module 内存装载 -> 回读 dmesg 打印"结论"行
 *   ./vrkiller clean    rmmod（清理残留）
 *
 * 嵌入 8 个 GKI KMI（android12-5.10 ~ android17-6.18），ko 数据全在二进制内，
 * 不写临时文件，不调外部 insmod。
 *
 * ENOEXEC 重试：vivo 系内核把 LOCALVERSION 后缀（如 " vivo "）烤进了 vermagic，
 * modversions 下内核跳过版本串首 token 后 strcmp 余部——我们余部没有该后缀即
 * ENOEXEC。此时把内嵌 ko 的 vermagic 值显式改写为 "6.1" + 原 flags + " vivo "
 * （首 token 被跳过，版本串本身无所谓），长度校验后原地落位，二次装载。
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
        /* vivo 系内核 vermagic 尾带 LOCALVERSION 后缀（实测 " vivo "）。
         * modversions 下 same_magic 跳过首 token 只比余部——把值显式改写为
         * "6.1" + 原 flags + " vivo "，先做长度账，再原地落位 + 显式 NUL。 */
        char *buf = malloc(vk->len);
        if (buf) {
            memcpy(buf, vk->data, vk->len);
            char *v = memmem(buf, vk->len, "vermagic=", 9);
            if (v) {
                v += 9;
                char *flags = strchr(v, ' ');
                if (flags && !strstr(flags, "vivo")) {
                    size_t flen = strlen(flags);   /* 含前导空格，不含 NUL */
                    size_t vlen = strlen(v);
                    if (3 + flen + 6 + 1 <= vlen) {
                        memcpy(v, "6.1", 3);
                        memmove(v + 3, flags, flen);
                        memcpy(v + 3 + flen, " vivo ", 6);
                        v[3 + flen + 6] = '\0';
                        printf("vrkiller: vermagic 已原地补 vivo 后缀，重试装载\n");
                        r = syscall(SYS_init_module, buf, vk->len, "");
                    }
                }
            }
            free(buf);
        }
    }
    if (r != 0) {
        printf("vrkiller: 结论 —— 注入失败: %s\n", strerror(errno));
        if (errno == EPERM)  printf("vrkiller: （EPERM 多半是内核模块签名强制）\n");
        if (errno == EEXIST) printf("vrkiller: （EEXIST 模块已存在，跑 clean 后重试）\n");
        if (errno == ENOEXEC)printf("vrkiller: （ENOEXEC 格式仍被拒，请抓 dmesg 里的 version magic 行回报）\n");
        return 1;
    }
    printf("vrkiller: 注入成功，等待内核日志 ...\n");
    usleep(300000);
    print_kernel_log();
    return 0;
}
