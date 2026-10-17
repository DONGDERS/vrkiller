# VrKiller

单文件内核模块：定位并拆除 vivo `vr.ko` 的 `sys_exit` tracepoint 探针（W1c 抽离版）。

## 行为（全自动，无需参数）

1. kallsyms 定位 `__tracepoint_sys_exit`
2. 解析运行内核 BTF 取 `struct tracepoint::funcs` 成员偏移（点名校验结构体名，不赌 BTF 序）
3. 读 funcs 槽位判活：已空→不动；合法指针→零写拆除+回读确认；非法值→拒绝盲写

无 UMH、不动 SELinux、不碰 defex；临时性质，重启自动归零，`rmmod vrkiller` 可清。

## 用法（root）

```
insmod vrkiller-<kmi>.ko
dmesg | grep vrkiller    # 看"结论"行
```

## 构建

CI 按 8 个 GKI KMI 矩阵构建（ddk-min），产物在 Actions artifact，不自动发 release。

注意：funcs 每次开机随 vr.ko 重载而重新武装，本工具是一次性手术刀，重启后需重跑。
