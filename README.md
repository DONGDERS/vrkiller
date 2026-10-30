# VrKiller

单文件可执行：自动识别内核 KMI，从内存注入对应的 `vrkiller.ko`，拆除 vivo `vr.ko` 的 `sys_exit` tracepoint 探针。

- 内嵌 8 个 GKI KMI（android12-5.10 ~ android17-6.18），按 `uname` 自动选择，不需要选文件
- 装载走 `init_module`，不落临时文件、不调外部 insmod
- 全自动：kallsyms 定位 `__tracepoint_sys_exit` → BTF 解析 `funcs` 成员偏移 → 读槽位判活：
  - 已是空 → vr 本来就是废的，不动
  - 合法内核指针 → 零写拆除 + 回读确认
  - 非法值 → 拒绝盲写，原样退场
- 结果直接打印在终端（找「结论」行）；内核侧行可 `dmesg | grep vrkiller`

## 使用教程

```
使用任意可获取Root的终端
su
cp /sdcard/你的文件 /data/local/tmp
chmod 777 /data/local/tmp/vrkiller
/data/local/tmp/vrkiller
```

清理：`/data/local/tmp/vrkiller clean`

## 说明

- 临时性质：重启后 vr.ko 重新武装，需要重跑一次；模块可用 `clean` 或 `rmmod vrkiller` 清除
- 拆除是纯数据写（清零 tracepoint 的 funcs 指针），无钩子无回调，失败路径全部显式中止
- 无 UMH、不动 SELinux、不碰 defex

## 构建

- `lkm-vrkiller/`：内核模块源码（C），CI 按 8 KMI 矩阵出 artifact
- `pack/`：打包器（C），把 8 颗 ko 嵌进单文件二进制，NDK 静态编译

Release 页提供已打包的 `vrkiller` 二进制。
## License
本项目使用 [GNU General Public License v2.0](LICENSE)。
其中 `lkm-vrkiller/` 内核模块依赖 Linux 内核导出符号（GPL-2.0），因此沿用 GPL-2.0。

This project is licensed under the [GNU General Public License v2.0](LICENSE).
