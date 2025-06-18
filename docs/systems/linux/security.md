# 15. 系统安全 (Firewall, SELinux/AppArmor)

Linux 系统安全是一个广阔而深入的领域。本章将重点介绍两个核心的防御层面：网络防火墙和强制访问控制系统 (MAC)。

## 1. 网络防火墙

防火墙是位于你的计算机和外部网络之间的一道屏障，它根据预设的规则来允许或拒绝网络流量。这是抵御未授权访问的第一道防线。

### UFW (Uncomplicated Firewall) - 适用于 Debian/Ubuntu

UFW 是 `iptables` 的一个用户友好前端，旨在简化防火墙的配置。非常适合桌面用户和初学者。

**基本操作**:
```bash
# 检查 UFW 状态
sudo ufw status verbose

# 启用 UFW
sudo ufw enable

# 禁用 UFW
sudo ufw disable

# 设置默认规则 (一个好的起点是默认拒绝所有入站连接，允许所有出站连接)
sudo ufw default deny incoming
sudo ufw default allow outgoing

# 允许特定端口或服务
sudo ufw allow ssh      # 按服务名 (会查询 /etc/services)
sudo ufw allow 80/tcp   # 按端口和协议
sudo ufw allow 1000:2000/tcp # 允许一个端口范围

# 拒绝连接
sudo ufw deny http

# 删除规则
sudo ufw delete allow 80/tcp
```

### firewalld - 适用于 RHEL/CentOS/Fedora

`firewalld` 是一个动态的防火墙管理器，其核心概念是**区域 (zones)**。一个区域是一组描述了对进入的网络流量的信任级别的规则。你可以根据网络接口所在的网络环境（如家庭、公共场所、公司）为其分配不同的区域。

**常用区域**:
- `public`: 用于公共网络。默认只接受特定的入站连接。
- `home`: 用于家庭网络。信任区域内的大多数计算机，只接受特定的入站连接。
- `work`: 用于工作网络。信任区域内的大多数计算机，只接受特定的入站连接。
- `trusted`: 信任所有网络连接。

**基本操作 (`firewall-cmd`)**:
```bash
# 查看防火墙状态
sudo firewall-cmd --state

# 查看默认区域
sudo firewall-cmd --get-default-zone

# 查看所有区域的配置
sudo firewall-cmd --list-all

# 查看 public 区域的配置
sudo firewall-cmd --zone=public --list-all

# 临时添加一个服务到 public 区域 (重启后失效)
sudo firewall-cmd --zone=public --add-service=http

# 永久添加一个服务到 public 区域
sudo firewall-cmd --zone=public --add-service=http --permanent

# 重新加载配置使永久规则生效
sudo firewall-cmd --reload
```

### iptables
`iptables` 是 Linux 内核中 Netfilter 框架的传统命令行工具。它非常强大和灵活，但语法也相对复杂。UFW 和 firewalld 在底层都是通过管理 `iptables` 规则来工作的。

`iptables` 的核心概念是**链 (Chains)**，它是一系列规则的列表。
- `INPUT`: 处理发往本机的入站数据包。
- `OUTPUT`: 处理由本机生成的出站数据包。
- `FORWARD`: 处理流经本机的数据包（路由）。

查看当前的 `INPUT` 链规则：
```bash
sudo iptables -L INPUT -n --line-numbers
```
直接操作 `iptables` 通常只在需要进行非常精细化控制的场景下进行。

## 2. 强制访问控制 (Mandatory Access Control, MAC)

标准的文件权限 (rwx) 是**自主访问控制 (DAC)**，即文件的所有者可以决定谁能访问它。而 MAC 是一个更严格的安全模型，由系统管理员定义一个全局策略，限制所有进程（即使是作为 `root` 运行的进程）能做什么。

### SELinux (Security-Enhanced Linux) - 适用于 RHEL/CentOS/Fedora

SELinux 为系统中的每一个进程和对象（文件、套接字等）都打上一个安全**标签 (context)**。内核根据预设的策略规则，来决定一个特定标签的进程是否有权限对另一个特定标签的对象执行某个操作。

**核心概念**:
- **模式 (Mode)**:
  - `Enforcing`: 强制执行策略，拒绝所有违反策略的行为并记录日志。
  - `Permissive`: 不强制执行策略，只记录违反策略的行为。这对于调试策略问题非常有用。
  - `Disabled`: 完全禁用。
- **布尔值 (Booleans)**: 一些策略可以通过开启/关闭布尔值来进行微调，而无需编写策略代码。

**基本命令**:
```bash
# 查看 SELinux 状态
sestatus

# 临时切换到 Permissive 模式
sudo setenforce 0

# 切换回 Enforcing 模式
sudo setenforce 1

# 查看 SELinux 相关的布尔值
getsebool -a

# 示例：允许 Apache 访问用户主目录
# 临时设置
sudo setsebool httpd_enable_homedirs 1
# 永久设置
sudo setsebool -P httpd_enable_homedirs 1

# 查看文件的安全标签
ls -Z /var/www/html/

# 查看进程的安全标签
ps auxZ | grep httpd
```
SELinux 的日志通常记录在 `/var/log/audit/audit.log` 中。使用 `audit2why` 和 `audit2allow` 工具可以帮助分析和修复 SELinux 拒绝访问的问题。

### AppArmor (Application Armor) - 适用于 Debian/Ubuntu/SUSE

AppArmor 也是一个 MAC 系统，但它通过**路径名**而不是安全标签来限制进程。它为每个应用程序定义一个**配置文件 (profile)**，该文件明确列出了该应用程序可以访问哪些文件以及可以执行哪些操作（如读、写、执行、网络访问等）。

**核心概念**:
- **模式 (Mode)**:
  - `Enforce`: 强制执行策略。
  - `Complain`: 只记录违规行为，不强制执行。
- **配置文件**: 通常位于 `/etc/apparmor.d/`。

**基本命令**:
```bash
# 查看 AppArmor 状态
sudo apparmor_status

# 将所有配置文件切换到 complain 模式
sudo aa-complain /etc/apparmor.d/*

# 将单个配置文件切换到 enforce 模式
sudo aa-enforce /etc/apparmor.d/usr.bin.firefox
```
AppArmor 的日志通常也记录在系统审计日志中，可以通过 `journalctl` 或 `dmesg` 查看。

## 总结
- **防火墙** 控制网络层面的访问。
- **SELinux/AppArmor** 控制进程层面的访问，即使网络流量被允许进入，它们也能限制一个被攻破的服务所能造成的损害。
- 将两者结合使用，可以构建一个深度防御的、更安全的 Linux 系统。 