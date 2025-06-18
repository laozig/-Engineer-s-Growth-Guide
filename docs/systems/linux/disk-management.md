# 13. 磁盘与文件系统管理

管理存储是 Linux 系统管理的一项核心任务。这包括了解系统上有哪些磁盘、它们是如何被划分的、使用了什么文件系统，以及如何挂载它们以供访问。

## 查看磁盘和分区

### `lsblk` (List Block Devices)
`lsblk` 命令以树状图的形式清晰地列出系统上所有的块设备（磁盘、分区、光驱等）。

```bash
lsblk

# 输出示例:
# NAME        MAJ:MIN RM   SIZE RO TYPE MOUNTPOINT
# sda           8:0    0    20G  0 disk
# ├─sda1        8:1    0   512M  0 part /boot/efi
# └─sda2        8:2    0  19.5G  0 part /
# sdb           8:16   0    50G  0 disk
# sr0          11:0    1  1024M  0 rom
```
- `sda`, `sdb`: 物理硬盘。
- `sda1`, `sda2`: `sda` 硬盘上的分区。
- `MOUNTPOINT`: 分区的挂载点。`sda2` 被挂载为根目录 `/`。

## 检查磁盘空间使用情况

### `df` (Disk Free)
`df` 命令用于报告文件系统的总空间、已用空间、可用空间和挂载点。

- 使用 `-h` (human-readable) 选项可以获得更易读的输出。

```bash
df -h

# 输出示例:
# Filesystem      Size  Used Avail Use% Mounted on
# udev            987M     0  987M   0% /dev
# tmpfs           200M  1.1M  199M   1% /run
# /dev/sda2        19G  4.5G   14G  25% /
# /dev/sda1       511M  4.0K  511M   1% /boot/efi
```

### `du` (Disk Usage)
`du` 命令用于估算文件和目录占用的磁盘空间。

- `du -sh <目录>` 是一个非常常用的组合：
  - `-s` (summarize): 只显示总计大小。
  - `-h` (human-readable): 以易读格式显示。

```bash
# 查看 /var/log 目录的总大小
du -sh /var/log

# 查看当前目录下每个子目录的大小
du -h --max-depth=1
```

## Linux 文件系统简介
文件系统是操作系统用来组织和管理磁盘上文件的一种结构。
- **ext4**: 是许多 Linux 发行版默认的日志文件系统，非常成熟、稳定和可靠。
- **XFS**: 一个高性能的日志文件系统，特别擅长处理大文件和大型文件系统。常用于 RHEL/CentOS。
- **Btrfs (B-tree File System)**: 一个现代的写时复制 (Copy-on-Write) 文件系统，支持快照、校验和、内置 RAID 等高级功能。

## 磁盘分区

**警告**: 分区操作是危险的，可能会导致数据丢失。在对生产环境的磁盘进行操作前，请务必备份数据。

分区是将一个物理磁盘划分为一个或多个逻辑区域的过程。
- **MBR (Master Boot Record)**: 传统的分区方案。最多支持4个主分区，或3个主分区+1个扩展分区。磁盘最大容量限制为 2TB。
- **GPT (GUID Partition Table)**: 现代的分区方案。默认支持多达128个分区，并且没有 2TB 的容量限制。是现代 UEFI 系统的标准。

### `fdisk` 和 `gdisk`
- **`fdisk`**: 用于 MBR 分区的经典工具。
- **`gdisk`**: 专门用于 GPT 分区的工具，其操作界面与 `fdisk` 非常相似。

**使用 `fdisk` 进行分区的基本流程 (以 `/dev/sdb` 为例)**:
1.  启动 `fdisk`: `sudo fdisk /dev/sdb`
2.  在 `fdisk` 提示符下：
    - `p`: 打印当前分区表。
    - `n`: 创建一个新分区。
    - `d`: 删除一个分区。
    - `t`: 更改分区的类型 ID。
    - `w`: 将更改写入磁盘并退出。**在执行此操作前，所有更改都只在内存中。**
    - `q`: 不保存更改并退出。

## 创建文件系统

分区完成后，你需要在新的分区上创建一个文件系统，这个过程称为"格式化"。

### `mkfs` (Make Filesystem)
`mkfs` 是一个前端命令，实际工作由特定文件系统的工具完成（如 `mkfs.ext4`, `mkfs.xfs`）。

```bash
# 在 /dev/sdb1 分区上创建一个 ext4 文件系统
sudo mkfs.ext4 /dev/sdb1

# 在 /dev/sdb2 分区上创建一个 xfs 文件系统
sudo mkfs.xfs /dev/sdb2
```

## 挂载和卸载文件系统

为了访问文件系统，你需要将其"挂载"到文件系统树中的一个目录上（称为挂载点）。

### `mount` 和 `umount`
- **`mount`**: 挂载文件系统。
- **`umount`**: 卸载文件系统。

```bash
# 创建一个挂载点目录
sudo mkdir /data

# 将 /dev/sdb1 分区挂载到 /data 目录
sudo mount /dev/sdb1 /data

# 查看 /data 目录的内容
ls /data

# 完成操作后，卸载文件系统
sudo umount /data
```

### 永久挂载: `/etc/fstab`

手动挂载是临时的，系统重启后会失效。要实现开机自动挂载，需要编辑 `/etc/fstab` (file systems table) 文件。

此文件的每一行代表一个要挂载的文件系统，格式如下：
`<device> <mount_point> <filesystem_type> <options> <dump> <pass>`

- **`<device>`**:
  - 可以是设备名，如 `/dev/sdb1`。
  - **推荐使用 `UUID`**。UUID 是分区的唯一标识符，不会因为磁盘顺序改变而变化。使用 `blkid /dev/sdb1` 命令可以获取 UUID。
- **`<mount_point>`**: 挂载点目录，如 `/data`。
- **`<filesystem_type>`**: 文件系统类型，如 `ext4`。
- **`<options>`**: 挂载选项。`defaults` 通常是一个不错的起点，它包含了一组标准选项 (如 `rw`, `suid`, `dev`, `exec`, `auto`, `nouser`, `async`)。
- **`<dump>`**: `dump` 工具使用的标志，通常设为 `0`。
- **`<pass>`**: 文件系统检查 (`fsck`) 的顺序。根目录应为 `1`，其他文件系统为 `2`，`0` 表示不检查。

**`/etc/fstab` 示例行**:
```
# 使用 UUID (推荐)
UUID=1234abcd-56ef-7890-ghij-klmnopqrstuv /data ext4 defaults 0 2

# 使用设备名
/dev/sdb1 /data ext4 defaults 0 2
```

编辑完 `/etc/fstab`后，可以运行 `sudo mount -a` 来挂载文件中所有尚未挂载的条目，这也可以用来测试你的配置是否正确。如果命令出错，说明你的 `fstab` 文件有语法问题，需要立即修复，否则系统可能无法正常启动。 