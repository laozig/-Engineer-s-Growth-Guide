# 10. 网络配置与管理

在 Linux 系统中，网络管理是核心技能之一，无论是配置一台个人电脑还是管理成百上千台服务器。本章将介绍用于查看、配置和排查网络问题的基本命令和概念。

## 查看网络接口和 IP 地址

### 1. `ip` 命令 (现代首选)

`ip` 命令是 `iproute2` 工具包的一部分，是用于网络配置的现代标准工具，功能强大。

**查看所有网络接口的信息**:
`ip addr show` 或简写 `ip a` 是最常用的命令之一。
```bash
ip a

# 输出示例:
# 1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
#     link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
#     inet 127.0.0.1/8 scope host lo
#        valid_lft forever preferred_lft forever
#     inet6 ::1/128 scope host
#        valid_lft forever preferred_lft forever
# 2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
#     link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff
#     inet 192.168.1.100/24 brd 192.168.1.255 scope global dynamic eth0
#        valid_lft 85651sec preferred_lft 85651sec
#     inet6 fe80::5054:ff:fe12:3456/64 scope link
#        valid_lft forever preferred_lft forever
```
- **`lo`**: 环回接口 (Loopback)，总是指向本机 (`127.0.0.1`)。
- **`eth0`**: 第一个以太网接口。`inet 192.168.1.100/24` 是它的 IPv4 地址和子网掩码。
- **`UP`**: 表示接口已启用。

**查看路由表**:
`ip route show` 或 `ip r` 显示了内核的路由表，决定了网络流量的去向。
```bash
ip r
# default via 192.168.1.1 dev eth0
# 192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100
```
- `default via 192.168.1.1`: 表示默认网关是 `192.168.1.1`。

### 2. `ifconfig` (传统工具)

`ifconfig` (interface configuration) 是一个较旧的工具，在一些新的极简系统中可能默认未安装。虽然 `ip` 命令是首选，但 `ifconfig` 仍然很常用。

```bash
ifconfig
```

## 检查网络连通性

### 1. `ping`
`ping` 是最基础的网络诊断工具，用于测试与另一台主机之间的连通性。它通过发送 ICMP "echo request" 包并等待响应来工作。

```bash
# ping 一个域名 (会解析其 IP 地址)
# 在 Linux 中，ping 会持续发送，直到你按 Ctrl+C 停止
ping google.com

# 使用 -c (count) 选项指定发送数据包的数量
ping -c 4 8.8.8.8
```
如果 `ping` 成功，说明你的机器和目标主机之间存在一条有效的网络路径。如果失败，可能是网络配置问题、防火墙或目标主机不在线。

### 2. `traceroute`
`traceroute` (或在 Windows 中的 `tracert`) 用于显示数据包从你的计算机到目标主机所经过的路由路径。这对于诊断网络延迟问题非常有用，可以帮你定位问题出在哪一跳（hop）。

```bash
traceroute google.com
```

## DNS 配置与查询

DNS (Domain Name System) 负责将人类可读的域名（如 `google.com`）解析为机器可读的 IP 地址（如 `172.217.160.142`）。

### `/etc/resolv.conf` 文件
这个文件指定了系统将使用哪些 DNS 服务器（nameserver）进行查询。
```bash
cat /etc/resolv.conf
# 输出示例:
# nameserver 8.8.8.8
# nameserver 8.8.4.4
```

### DNS 查询工具

- **`dig` (Domain Information Groper)**: 功能强大，提供非常详细的查询信息，是网络管理员的首选。
  ```bash
  dig github.com
  ```
- **`nslookup` (Name Server Lookup)**: 一个较老但仍然很实用的工具。
  ```bash
  nslookup github.com
  ```
- **`host`**: 一个简单的工具，快速将域名转换为 IP 或反之。
  ```bash
  host github.com
  ```

## 查看网络连接和端口

要了解你的系统正在进行哪些网络通信，以及哪些服务在监听连接，可以使用以下工具。

### 1. `ss` (现代首选)

`ss` (socket statistics) 是 `netstat` 的现代替代品，速度更快，能提供更多信息。

- **`ss -tunlp`**: 一个非常实用的选项组合。
  - `-t`: 显示 TCP 连接。
  - `-u`: 显示 UDP 连接。
  - `-n`: 不解析服务名，直接显示端口号（更快）。
  - `-l`: 只显示监听 (listening) 状态的套接字。
  - `-p`: 显示使用该套接字的进程。

```bash
sudo ss -tunlp
# 输出示例:
# Proto  Recv-Q  Send-Q  Local Address:Port   Peer Address:Port  State   PID/Program name
# tcp    0       0       0.0.0.0:22           0.0.0.0:*          LISTEN  1234/sshd
# tcp    0       0       127.0.0.1:631        0.0.0.0:*          LISTEN  5678/cupsd
```
这个输出告诉我们，`sshd` 服务正在监听所有网络接口 (`0.0.0.0`) 的 22 端口，`cupsd` 服务正在监听本地的 631 端口。

### 2. `netstat` (传统工具)

`netstat` 的功能与 `ss` 类似。
```bash
sudo netstat -tunlp
```

## 现代网络管理工具

在桌面环境和许多现代服务器上，网络配置通常由一个专门的服务来管理，而不是手动编辑配置文件。

### 1. `NetworkManager` (`nmcli`)
`NetworkManager` 在大多数桌面发行版（如 Ubuntu, Fedora）和 RHEL/CentOS 服务器上是默认的网络管理服务。`nmcli` 是其强大的命令行客户端。

- **查看设备状态**: `nmcli device status`
- **查看所有连接**: `nmcli connection show`
- **启用/禁用连接**: `nmoli connection up/down <connection_name>`

### 2. `systemd-networkd` (`networkctl`)
`systemd-networkd` 是一个轻量级的网络管理服务，常见于服务器和嵌入式系统。`networkctl` 是其命令行工具。

- **查看网络设备状态**: `networkctl status`
- **重新加载配置**: `sudo networkctl reload`

手动编辑 `/etc/network/interfaces` (Debian/Ubuntu) 或 `/etc/sysconfig/network-scripts/` (Red Hat/CentOS) 下的配置文件正在变得越来越少见，但了解其基本结构仍然有益，尤其是在没有高级管理工具的旧系统或最小化安装环境中。 