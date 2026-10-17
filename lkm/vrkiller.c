// SPDX-License-Identifier: GPL-2.0
/*
 * VrKiller - 单文件版 vr 探针处理工具（从 dfroot.c W1c 抽离）
 *
 * 功能（全自动，无需参数）：
 *   1. 定位 __tracepoint_sys_exit（kallsyms）
 *   2. 解析运行内核 BTF，取 struct tracepoint::funcs 成员偏移
 *      （vivo 加了 probestub，funcs 在 0x48 而非 mainline 的 0x40；
 *        硬编码恒错，BTF 是唯一可信的每机真值）
 *   3. 读 funcs 槽位判活：
 *        已是 NULL        -> vr 本来就是废的，不动
 *        合法内核指针     -> 零写拆除（纯数据写，无钩子无回调）+ 回读确认
 *        非指针垃圾值     -> 拒绝盲写，中止，一个字节都不动
 *
 * 无 UMH、不动 SELinux、不碰 defex。装完即完成使命，留在场可
 * `rmmod vrkiller`；临时性质，重启自动归零。
 *
 * 用法（需 root）：
 *   insmod vrkiller.ko
 *   dmesg | grep vrkiller     # 看"结论"行
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("VrKiller: locate and disarm vivo vr sys_exit tracepoint probe");

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

/* BTF resolver helpers. Prototypes MUST textually match the real kernel
 * signatures - the ko calls them through kallsyms pointers and the kernel's
 * kCFI hashes the whole function type (a mismatched return type = BRK
 * panic). Same typedefs as dfroot.c, proven on-device. */
struct file;
typedef struct file   *(*filp_open_t)(const char *, int, umode_t);
typedef ssize_t        (*kernel_read_t)(struct file *, void *, size_t, loff_t *);
typedef int            (*filp_close_t)(struct file *, void *);
typedef void          *(*vzalloc_t)(unsigned long);
typedef void           (*vfree_t)(const void *);

/* ---- BTF 解析：取 offsetof(struct tracepoint, funcs) ------------------
 * 逐块读 /sys/kernel/btf/vmlinux（单次 kernel_read 会短读，真机实证），
 * 走到名为 "tracepoint" 的 STRUCT，再找 "funcs" 成员。逻辑与真机验证过
 * 的 vrsolve/dfroot 完全一致。失败返回 0。 */
static unsigned long __nocfi vk_btf_funcs(filp_open_t f_open,
                                          kernel_read_t k_read,
                                          filp_close_t f_close,
                                          vzalloc_t valloc, vfree_t vfree)
{
    struct file *f;
    void *buf;
    loff_t pos = 0;
    ssize_t n;
    unsigned char *b;
    unsigned long types, strtab, tp_end, p;
    unsigned long off = 0;
    const unsigned int BTF_SZ = 8u * 1024 * 1024;

    f = f_open("/sys/kernel/btf/vmlinux", O_RDONLY, 0);
    if (IS_ERR_OR_NULL(f)) {
        pr_info("vrkiller: BTF 不可用（/sys/kernel/btf/vmlinux 打不开）\n");
        return 0;
    }
    buf = valloc(BTF_SZ);
    if (!buf) {
        f_close(f, NULL);
        return 0;
    }
    {
        size_t total = 0;
        while (total < BTF_SZ) {
            size_t chunk = BTF_SZ - total;
            if (chunk > 1024 * 1024)
                chunk = 1024 * 1024;
            n = k_read(f, buf + total, chunk, &pos);
            if (n <= 0)
                break;
            total += (size_t)n;
        }
        n = (ssize_t)total;
    }
    f_close(f, NULL);
    if (n < 64) {
        pr_warn("vrkiller: BTF 读取过短（%zd 字节）\n", n);
        vfree(buf);
        return 0;
    }
    b = buf;
    {
        unsigned short magic = b[0] | ((unsigned short)b[1] << 8);
        unsigned int hdr_len, type_off, type_len, str_off;
        if (magic != 0xeb9f) {
            pr_warn("vrkiller: BTF 魔数异常 %04x\n", magic);
            vfree(buf);
            return 0;
        }
        hdr_len  = b[4] | (b[5] << 8) | (b[6] << 16) | ((unsigned int)b[7] << 24);
        type_off = b[8] | (b[9] << 8) | (b[10] << 16) | ((unsigned int)b[11] << 24);
        type_len = b[12] | (b[13] << 8) | (b[14] << 16) | ((unsigned int)b[15] << 24);
        str_off  = b[16] | (b[17] << 8) | (b[18] << 16) | ((unsigned int)b[19] << 24);
        if ((long)hdr_len + type_off + type_len > n) {
            pr_warn("vrkiller: BTF 不完整\n");
            vfree(buf);
            return 0;
        }
        types  = hdr_len + type_off;
        strtab = hdr_len + str_off;
        tp_end = types + type_len;
    }

    p = types;
    while (p + 12 <= tp_end) {
        unsigned int info = b[p+4] | (b[p+5] << 8) | (b[p+6] << 16) | ((unsigned int)b[p+7] << 24);
        unsigned int kind = (info >> 24) & 0x1f;
        unsigned int vlen = info & 0xffff;
        unsigned long pay;
        if (kind == 4) { /* STRUCT */
            unsigned long j, m = p + 12;
            if (m + (unsigned long)vlen * 12 > tp_end) break;
            for (j = 0; j < vlen; j++, m += 12) {
                unsigned int mn = b[m] | (b[m+1] << 8) | (b[m+2] << 16) | ((unsigned int)b[m+3] << 24);
                unsigned int mo = b[m+8] | (b[m+9] << 8) | (b[m+10] << 16) | ((unsigned int)b[m+11] << 24);
                const char *nm;
                if (strtab + mn >= (unsigned long)n)
                    continue;
                nm = (const char *)b + strtab + mn;
                if (!strcmp(nm, "funcs")) {
                    off = mo / 8;   /* BTF 成员偏移单位是 bit */
                    goto out;
                }
            }
        }
        pay = 0;
        switch (kind) {
            case 1: pay = 4; break;              /* INT */
            case 3: pay = 12; break;             /* ARRAY */
            case 4: case 5: pay = (unsigned long)vlen * 12; break; /* STRUCT/UNION */
            case 6: pay = (unsigned long)vlen * 8; break;  /* ENUM */
            case 13: pay = (unsigned long)vlen * 8; break; /* FUNC_PROTO */
            case 14: pay = 8; break;             /* VAR */
            case 15: pay = (unsigned long)vlen * 12; break; /* DATASEC */
            case 17: pay = 8; break;             /* DECL_TAG */
            case 19: pay = (unsigned long)vlen * 12; break; /* ENUM64 */
            default: pay = 0; break;             /* PTR/FWD/typedef/FUNC 等 */
        }
        p += 12 + pay;
    }
out:
    if (off > 0x100) {
        pr_warn("vrkiller: BTF 解出的 funcs 偏移不合理 %lu，弃用\n", off);
        off = 0;
    }
    vfree(buf);
    return off;
}

static int __nocfi __init vrkiller_init(void)
{
    kallsyms_lookup_name_t get_addr;
    filp_open_t f_open;
    kernel_read_t k_read;
    filp_close_t f_close;
    vzalloc_t valloc;
    vfree_t vfree;
    struct kprobe kln_kp;
    char *tp;
    unsigned long off, cur;

    /* kallsyms_lookup_name 未导出，用 kprobe 取地址（dfroot 同款） */
    kln_kp = (struct kprobe){ .symbol_name = "kallsyms_lookup_name" };
    if (register_kprobe(&kln_kp) < 0) {
        pr_err("vrkiller: 结论 —— 中止：kallsyms_lookup_name 不可用，未动任何内存\n");
        return -EINVAL;
    }
    get_addr = (kallsyms_lookup_name_t)kln_kp.addr;
    unregister_kprobe(&kln_kp);

    tp = (char *)get_addr("__tracepoint_sys_exit");
    if (!tp) {
        pr_err("vrkiller: 结论 —— 中止：__tracepoint_sys_exit 不在 kallsyms，未动任何内存\n");
        return 0;
    }
    f_open  = (filp_open_t)get_addr("filp_open");
    k_read  = (kernel_read_t)get_addr("kernel_read");
    f_close = (filp_close_t)get_addr("filp_close");
    valloc  = (vzalloc_t)get_addr("vzalloc");
    vfree   = (vfree_t)get_addr("vfree");
    if (!f_open || !k_read || !f_close || !valloc || !vfree) {
        pr_err("vrkiller: 结论 —— 中止：BTF 读取所需内核符号不全，未动任何内存\n");
        return 0;
    }

    off = vk_btf_funcs(f_open, k_read, f_close, valloc, vfree);
    if (!off) {
        pr_err("vrkiller: 结论 —— 中止：funcs 偏移无法从 BTF 解析，拒绝盲写，未动任何内存\n");
        return 0;
    }
    pr_info("vrkiller: 定位完成 —— __tracepoint_sys_exit @ %px，funcs 成员偏移 0x%lx（BTF）\n",
            tp, off);

    {
        void **funcs_slot = (void **)(tp + off);
        cur = (unsigned long)READ_ONCE(*funcs_slot);
        if (!cur) {
            pr_info("vrkiller: funcs 槽位已是空 —— vr 本来就是废的，不动\n");
            pr_info("vrkiller: 结论 —— 无需处理：vr sys_exit 探针此前已被拆除\n");
            return 0;
        }
        if (!(cur >= 0xffffff8000000000UL && !(cur & 7))) {
            pr_err("vrkiller: funcs 槽位是非法指针 %lx，拒绝盲写，未动任何内存\n", cur);
            pr_err("vrkiller: 结论 —— 中止：槽位值不像内核指针，vr 状态保持原样\n");
            return 0;
        }
        pr_info("vrkiller: funcs=%lx —— vr sys_exit 探针在场（活着），开始拆除\n", cur);
        WRITE_ONCE(*funcs_slot, NULL);
        /* 回读验证才算数 */
        if (READ_ONCE(*funcs_slot) == NULL) {
            pr_info("vrkiller: 回读确认 funcs=0 —— 拆除生效\n");
            pr_info("vrkiller: 结论 —— 完成：vr sys_exit 探针已废（funcs 已清零）\n");
        } else {
            pr_err("vrkiller: 结论 —— 异常：写入后回读非空（%lx），请立即回报\n",
                   (unsigned long)READ_ONCE(*funcs_slot));
        }
    }
    return 0;
}

static void __exit vrkiller_exit(void)
{
}

module_init(vrkiller_init);
module_exit(vrkiller_exit);
