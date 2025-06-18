# 14. 内核与性能调优

Linux 内核是操作系统的核心，它直接管理硬件并为所有程序提供基础服务。理解如何与内核交互并对其进行微调，是高级系统管理和性能优化的关键。

## Linux 内核简介

内核负责：
- **进程管理**: 调度哪些进程可以使用 CPU。
- **内存管理**: 分配和跟踪内存使用。
- **设备驱动**: 作为硬件和软件之间的接口。
- **系统调用**: 提供应用程序与内核通信的接口。

## 内核模块管理

Linux 内核采用模块化设计，这意味着许多功能和设备驱动可以作为模块在需要时动态加载，而无需重新编译整个内核。

### `lsmod` - 列出已加载的模块
此命令显示当前加载到内核中的所有模块及其依赖关系。
```bash
lsmod
```

### `modinfo` - 显示模块信息
显示特定模块的详细信息，如作者、描述和支持的参数。
```bash
modinfo usb_storage
```

### `modprobe` - 智能地加载/卸载模块
`modprobe` 是管理内核模块的首选工具。它会自动处理模块依赖关系。
```bash
# 加载一个模块及其依赖
sudo modprobe usb_storage

# 卸载一个模块
sudo modprobe -r usb_storage
```
内核模块的配置文件通常位于 `/etc/modprobe.d/` 目录下。

## 通过 `/proc` 和 `/sys` 与内核交互

### `/proc` 文件系统
`/proc` 是一个虚拟文件系统，提供了查看和修改内核运行时参数的接口。文件内容是在被读取时由内核动态生成的。
```bash
# 查看 CPU 信息
cat /proc/cpuinfo

# 查看内存信息
cat /proc/meminfo

# 查看系统平均负载
cat /proc/loadavg
```
一些在 `/proc/sys/` 下的参数是可写的，允许你动态修改内核行为。

### `/sys` 文件系统
`/sys` 是一个比 `/proc` 更现代、结构更清晰的虚拟文件系统，主要用于展示设备驱动模型和硬件信息。例如，你可以通过 `/sys` 来调整 I/O 调度器或控制设备的电源状态。
```bash
# 查看 sda 磁盘的 I/O 调度器
cat /sys/block/sda/queue/scheduler
# 输出示例: [mq-deadline] kyber bfq none
```

## 使用 `sysctl` 进行运行时调优

直接编辑 `/proc/sys` 下的文件来进行参数调整是临时的，系统重启后会失效。`sysctl` 命令和 `/etc/sysctl.conf` 文件提供了一种持久化这些设置的方法。

### `sysctl` 命令
- **查看所有内核参数**:
  ```bash
  sudo sysctl -a
  ```
- **查看特定参数**:
  ```bash
  sudo sysctl net.ipv4.ip_forward
  # 输出: net.ipv4.ip_forward = 0
  ```
- **动态修改参数**:
  ```bash
  # 启用 IP 转发
  sudo sysctl -w net.ipv4.ip_forward=1
  ```

### 永久化设置 (`/etc/sysctl.conf`)
要使内核参数设置在重启后依然有效，需要将它们添加到 `/etc/sysctl.conf` 文件或 `/etc/sysctl.d/` 目录下的 `.conf` 文件中。

**编辑 `/etc/sysctl.conf`**:
```
# 示例: 增加 TCP 连接队列大小
net.core.somaxconn = 1024
# 示例: 增加系统文件句柄限制
fs.file-max = 2097152
```
编辑完成后，运行 `sudo sysctl -p` 来加载新设置，使其立即生效。

## 常见性能调优领域

性能调优是一个复杂的过程，需要明确的目标和基准测试。以下是一些常见的调优领域。

### 1. CPU 调优
- **I/O 调度器**: 对于不同的工作负载（如数据库服务器 vs. 文件服务器），选择合适的 I/O 调度器 (`mq-deadline`, `bfq`, `kyber`) 可以显著影响性能。
- **进程优先级**: 使用 `nice` 和 `renice` 为关键进程分配更高的 CPU 优先级。

### 2. 内存调优
- **Swappiness**: 内核参数 `vm.swappiness` 控制了系统使用交换空间 (Swap) 的倾向。值的范围是 0-100。
  - `vm.swappiness=60` (默认值): 标准设置。
  - `vm.swappiness=10`: 告诉内核尽可能少地使用交换空间，优先保留内存在物理 RAM 中。这对于性能敏感的应用（如数据库）通常是有利的。
  - `vm.swappiness=0`: 在内核版本 3.5 之后，仅在物理内存完全用尽时才使用交换空间。
  ```bash
  # 临时设置
  sudo sysctl -w vm.swappiness=10
  # 永久设置 (写入 sysctl.conf)
  # vm.swappiness=10
  ```
- **OOM Killer**: 当系统内存严重不足时，Out-Of-Memory (OOM) Killer 会选择并杀死一个进程来释放内存。你可以通过调整进程的 `oom_score_adj` 值来影响 OOM Killer 的决策。

### 3. 网络调优
网络栈是性能调优最常见的领域之一，尤其是在高流量服务器上。
- **TCP 缓冲区大小**: `net.core.rmem_max`, `net.core.wmem_max`, `net.ipv4.tcp_rmem`, `net.ipv4.tcp_wmem` 等参数控制了 TCP 连接的内存缓冲区大小，调整它们可以提高网络吞吐量。
- **连接队列**: `net.core.somaxconn` 和 `net.ipv4.tcp_max_syn_backlog` 控制了等待处理的传入连接队列的大小。在高并发服务器上，默认值可能太小。
- **文件句柄限制**: `fs.file-max` 和 `fs.nr_open` 控制了系统级和进程级的文件句柄限制。每个网络连接都会消耗一个文件句柄，因此在高并发环境下需要调高此限制。

## 性能分析工具

- **`top`/`htop`**: 快速查看 CPU 和内存占用最高的进程。
- **`vmstat`**: 报告关于进程、内存、分页、块 I/O、陷阱和 CPU 活动的虚拟内存统计信息。
- **`iostat`**: 报告 CPU 统计信息和输入/输出统计信息。
- **`perf`**: 一个非常强大的 Linux 性能分析工具。它可以对硬件事件（如 CPU 周期、缓存命中/未命中）和软件事件（如系统调用、调度事件）进行采样。
  ```bash
  # 监控整个系统的性能事件
  sudo perf top
  ```

性能调优是一个"测量、调整、再测量"的循环过程。在没有明确的性能瓶颈和基准数据的情况下，随意修改内核参数可能会对系统稳定性产生负面影响。 