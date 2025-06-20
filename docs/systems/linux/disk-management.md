# Linux 磁盘管理

磁盘管理是系统管理的重要组成部分，涉及分区创建、文件系统格式化、挂载管理以及高级存储技术的应用。本文将介绍 Linux 中常用的磁盘管理工具和技术。

## 磁盘和分区基础

### 设备命名约定

Linux 中的磁盘和分区遵循特定的命名约定：

- **传统 SATA/IDE 硬盘**：`/dev/sdX`（X 是字母，如 a、b、c）
  - 分区表示为 `/dev/sdXY`（Y 是数字，如 1、2、3）
- **NVMe 固态硬盘**：`/dev/nvmeXnY`
  - 例如：`/dev/nvme0n1p1`（第一个 NVMe 设备的第一个分区）
- **虚拟磁盘**：`/dev/vdX`（常见于虚拟机环境）

### 查看磁盘和分区信息

```bash
# 列出所有磁盘和分区
sudo fdisk -l

# 使用 lsblk 查看块设备
lsblk

# 查看分区的文件系统类型和使用情况
df -Th

# 查看特定磁盘的详细信息
sudo smartctl -a /dev/sda

# 查看磁盘使用情况
du -sh /path/to/directory
```

## 分区管理

### 分区表类型

1. **MBR (Master Boot Record)**
   - 传统分区表格式
   - 最多支持4个主分区或3个主分区加1个扩展分区
   - 单个分区最大支持2TB

2. **GPT (GUID Partition Table)**
   - 现代分区表格式，支持大容量磁盘
   - 理论上支持无限数量的分区（实际受操作系统限制）
   - 单个分区支持超过2TB

### 使用 fdisk 进行分区管理

`fdisk` 是一个交互式的分区工具，主要用于 MBR 分区表。

```bash
# 启动 fdisk
sudo fdisk /dev/sdb

# 常用命令（在 fdisk 交互式界面中）：
# p - 打印分区表
# n - 创建新分区
# d - 删除分区
# t - 更改分区类型
# w - 写入更改并退出
# q - 放弃更改并退出
```

### 使用 parted 进行分区管理

`parted` 支持 GPT 分区表，适用于大容量磁盘。

```bash
# 启动 parted
sudo parted /dev/sdc

# 常用命令（在 parted 交互式界面中）：
# print - 显示分区表
# mklabel gpt - 创建 GPT 分区表
# mkpart - 创建新分区
# rm - 删除分区
# quit - 退出
```

### 使用 gdisk 进行 GPT 分区管理

```bash
# 安装 gdisk
sudo apt install gdisk   # Debian/Ubuntu
sudo yum install gdisk   # CentOS/RHEL

# 使用 gdisk
sudo gdisk /dev/sdc
```

## 文件系统管理

### 常见文件系统类型

- **ext4**：Linux 上最常用的文件系统，稳定可靠
- **XFS**：高性能文件系统，特别适合大文件和大容量存储
- **Btrfs**：现代文件系统，支持快照、RAID、压缩等高级功能
- **F2FS**：为闪存设备优化的文件系统
- **NTFS/FAT32**：Windows 文件系统，Linux 提供读写支持

### 创建文件系统（格式化）

```bash
# 格式化为 ext4
sudo mkfs.ext4 /dev/sdb1

# 格式化为 XFS
sudo mkfs.xfs /dev/sdc1

# 格式化为 Btrfs
sudo mkfs.btrfs /dev/sdd1

# 格式化为 FAT32（用于跨平台兼容）
sudo mkfs.vfat -F 32 /dev/sde1
```

### 检查和修复文件系统

```bash
# 检查 ext4 文件系统
sudo fsck.ext4 /dev/sdb1

# 检查 XFS 文件系统
sudo xfs_repair /dev/sdc1

# 强制检查已挂载的 ext4 文件系统（需要在下次重启时进行）
sudo touch /forcefsck
```

## 挂载和卸载文件系统

### 临时挂载

```bash
# 挂载分区到指定目录
sudo mount /dev/sdb1 /mnt/data

# 指定文件系统类型挂载
sudo mount -t ext4 /dev/sdb1 /mnt/data

# 以只读方式挂载
sudo mount -o ro /dev/sdb1 /mnt/data

# 挂载 ISO 文件
sudo mount -o loop ubuntu.iso /mnt/iso
```

### 卸载文件系统

```bash
# 卸载文件系统
sudo umount /mnt/data

# 或者通过设备路径卸载
sudo umount /dev/sdb1

# 强制卸载（当设备忙时）
sudo umount -l /mnt/data
```

### 永久挂载（/etc/fstab）

编辑 `/etc/fstab` 文件以配置启动时自动挂载：

```bash
sudo nano /etc/fstab
```

`/etc/fstab` 条目格式：
```
<设备>  <挂载点>  <文件系统类型>  <挂载选项>  <dump>  <fsck顺序>
```

示例：
```
/dev/sdb1  /mnt/data  ext4  defaults  0  2
UUID=1234-5678  /media/backup  xfs  defaults  0  2
```

使用 UUID 或 LABEL 替代设备路径更加稳定：
```bash
# 查找分区的 UUID
sudo blkid

# 使用 UUID 挂载
UUID=1234-5678-90ab-cdef  /mnt/data  ext4  defaults  0  2

# 设置文件系统标签
sudo e2label /dev/sdb1 DATA

# 使用标签挂载
LABEL=DATA  /mnt/data  ext4  defaults  0  2
```

### 常用挂载选项

- **defaults**：使用默认选项（rw, suid, dev, exec, auto, nouser, async）
- **auto/noauto**：是否在启动时或使用 `mount -a` 时自动挂载
- **exec/noexec**：允许/禁止执行文件
- **ro/rw**：只读/读写模式
- **user/nouser**：允许/禁止普通用户挂载
- **sync/async**：同步/异步 I/O 操作
- **noatime**：不更新文件访问时间，提高性能

## 逻辑卷管理 (LVM)

LVM（Logical Volume Manager）提供了更灵活的磁盘管理方式，允许调整分区大小、添加存储空间等操作而无需重新分区。

### LVM 概念

- **物理卷 (PV, Physical Volume)**：实际的磁盘分区或整个磁盘
- **卷组 (VG, Volume Group)**：由一个或多个物理卷组成的存储池
- **逻辑卷 (LV, Logical Volume)**：从卷组中分配的虚拟分区，可以格式化并挂载

### 安装 LVM 工具

```bash
# Debian/Ubuntu
sudo apt install lvm2

# CentOS/RHEL
sudo yum install lvm2
```

### 创建 LVM 系统

1. 创建物理卷：
```bash
sudo pvcreate /dev/sdb1 /dev/sdc1
```

2. 创建卷组：
```bash
sudo vgcreate myvg /dev/sdb1 /dev/sdc1
```

3. 创建逻辑卷：
```bash
# 创建固定大小的逻辑卷
sudo lvcreate -L 10G -n mylv myvg

# 创建使用卷组所有可用空间的逻辑卷
sudo lvcreate -l 100%FREE -n mylv myvg
```

4. 格式化和挂载逻辑卷：
```bash
sudo mkfs.ext4 /dev/myvg/mylv
sudo mkdir /mnt/lvm
sudo mount /dev/myvg/mylv /mnt/lvm
```

### LVM 管理命令

```bash
# 显示物理卷信息
sudo pvs
sudo pvdisplay

# 显示卷组信息
sudo vgs
sudo vgdisplay

# 显示逻辑卷信息
sudo lvs
sudo lvdisplay
```

### 扩展和缩减 LVM

```bash
# 扩展卷组（添加新的物理卷）
sudo pvcreate /dev/sdd1
sudo vgextend myvg /dev/sdd1

# 扩展逻辑卷
sudo lvextend -L +5G /dev/myvg/mylv
sudo resize2fs /dev/myvg/mylv  # 对于 ext4 文件系统

# 对于 XFS 文件系统
sudo lvextend -L +5G /dev/myvg/mylv
sudo xfs_growfs /mnt/lvm

# 缩减逻辑卷（先卸载并检查文件系统）
sudo umount /mnt/lvm
sudo fsck -f /dev/myvg/mylv
sudo resize2fs /dev/myvg/mylv 5G
sudo lvreduce -L 5G /dev/myvg/mylv
```

## RAID 配置

RAID（Redundant Array of Independent Disks）提供数据冗余和/或性能提升。

### 软件 RAID 创建（mdadm）

```bash
# 安装 mdadm
sudo apt install mdadm  # Debian/Ubuntu
sudo yum install mdadm  # CentOS/RHEL

# 创建 RAID 1（镜像）
sudo mdadm --create /dev/md0 --level=1 --raid-devices=2 /dev/sdb1 /dev/sdc1

# 创建 RAID 5（奇偶校验）
sudo mdadm --create /dev/md0 --level=5 --raid-devices=3 /dev/sdb1 /dev/sdc1 /dev/sdd1

# 创建 RAID 0（条带化，无冗余）
sudo mdadm --create /dev/md0 --level=0 --raid-devices=2 /dev/sdb1 /dev/sdc1
```

### RAID 管理

```bash
# 查看 RAID 状态
cat /proc/mdstat
sudo mdadm --detail /dev/md0

# 保存 RAID 配置
sudo mdadm --detail --scan >> /etc/mdadm/mdadm.conf

# 停止 RAID 阵列
sudo mdadm --stop /dev/md0

# 添加备用磁盘
sudo mdadm --add /dev/md0 /dev/sde1
```

## 磁盘加密

### 使用 LUKS 加密分区

```bash
# 安装 cryptsetup
sudo apt install cryptsetup  # Debian/Ubuntu
sudo yum install cryptsetup  # CentOS/RHEL

# 初始化加密分区
sudo cryptsetup luksFormat /dev/sdb1

# 打开加密分区（会提示输入密码）
sudo cryptsetup luksOpen /dev/sdb1 encrypted_data

# 格式化已解锁的设备
sudo mkfs.ext4 /dev/mapper/encrypted_data

# 挂载
sudo mount /dev/mapper/encrypted_data /mnt/secure

# 卸载和关闭
sudo umount /mnt/secure
sudo cryptsetup luksClose encrypted_data
```

### 配置自动挂载加密分区

编辑 `/etc/crypttab`：
```
encrypted_data UUID=<uuid-of-encrypted-device> none luks
```

然后在 `/etc/fstab` 中添加：
```
/dev/mapper/encrypted_data  /mnt/secure  ext4  defaults  0  2
```

## 磁盘配额

磁盘配额限制用户或组可以使用的磁盘空间。

### 安装配额工具

```bash
# Debian/Ubuntu
sudo apt install quota

# CentOS/RHEL
sudo yum install quota
```

### 配置配额

1. 修改 `/etc/fstab` 添加配额选项：
```
/dev/sdb1  /home  ext4  defaults,usrquota,grpquota  0  2
```

2. 重新挂载文件系统：
```bash
sudo mount -o remount /home
```

3. 初始化配额数据库：
```bash
sudo quotacheck -cugm /home
```

4. 启用配额：
```bash
sudo quotaon /home
```

5. 设置用户配额：
```bash
sudo edquota -u username
```

6. 查看配额使用情况：
```bash
sudo quota -u username
sudo repquota -a
```

## 磁盘性能和监控

### 监控工具

```bash
# I/O 统计
iostat -x 2

# 实时 I/O 监控
iotop

# 显示文件系统和挂载点的 I/O 统计
sudo iotop

# 磁盘使用情况
df -h

# 目录大小
du -sh /path/to/directory

# 查找大文件
find / -type f -size +100M -exec ls -lh {} \; | sort -k5 -rh
```

### 优化磁盘性能

```bash
# 启用 noatime 挂载选项
/dev/sda1  /  ext4  defaults,noatime  0  1

# 使用 fstrim 对 SSD 进行 TRIM 操作
sudo fstrim -av

# 设置 I/O 调度器
echo deadline > /sys/block/sda/queue/scheduler

# 预读取文件系统缓存
sudo blockdev --setra 4096 /dev/sda
```

## 备份和恢复

### 使用 dd 创建整个磁盘或分区的镜像

```bash
# 备份整个磁盘
sudo dd if=/dev/sda of=/path/to/disk.img bs=4M status=progress

# 备份分区
sudo dd if=/dev/sda1 of=/path/to/partition.img bs=4M status=progress

# 恢复镜像
sudo dd if=/path/to/disk.img of=/dev/sda bs=4M status=progress
```

### 使用 rsync 备份数据

```bash
# 本地备份
rsync -avhP /source/directory/ /backup/directory/

# 远程备份
rsync -avhP -e ssh /source/directory/ user@remote:/backup/directory/
```

## 常见问题排查

### 文件系统问题

```bash
# 检查日志
dmesg | grep -i error
dmesg | grep -i sda

# 检查 S.M.A.R.T 数据
sudo smartctl -a /dev/sda

# 运行长时间 S.M.A.R.T 测试
sudo smartctl -t long /dev/sda

# 查看测试结果
sudo smartctl -l selftest /dev/sda

# 检查坏块
sudo badblocks -v /dev/sda
```

### 空间不足问题

```bash
# 查找大文件
find / -type f -size +100M -exec ls -lh {} \; | sort -k5 -rh | head -20

# 查找大目录
du -h --max-depth=2 / | sort -hr | head -20

# 清理日志文件
sudo journalctl --vacuum-time=2d

# 清理软件包缓存
sudo apt clean  # Debian/Ubuntu
sudo dnf clean all  # CentOS/RHEL/Fedora
```

## 参考资源

- [Linux 文件系统层次结构标准](https://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html)
- [LVM 管理指南](https://www.centos.org/docs/5/html/Cluster_Logical_Volume_Manager/index.html)
- [RAID Wiki](https://raid.wiki.kernel.org/index.php/Linux_Raid)
- [Linux 文件系统性能优化](https://www.kernel.org/doc/Documentation/filesystems/) 