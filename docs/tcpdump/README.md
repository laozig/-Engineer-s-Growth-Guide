# tcpdump 命令行网络抓包工具

<div align="center">
  <img src="../../assets/tcpdump-logo.png" alt="tcpdump Logo" width="200">
</div>

> tcpdump是一款功能强大的命令行网络数据包分析工具，允许用户捕获和显示发送或接收在特定网络接口上的TCP/IP和其他数据包。

## 目录

- [简介](#简介)
- [安装](#安装)
- [基本使用](#基本使用)
- [过滤表达式](#过滤表达式)
- [输出格式](#输出格式)
- [高级用法](#高级用法)
- [实用示例](#实用示例)
- [技巧与窍门](#技巧与窍门)
- [常见问题](#常见问题)
- [参考资源](#参考资源)

## 简介

tcpdump是Unix/Linux系统下的标准网络分析工具，它直接从网络接口捕获原始数据包，进行解码并以文本形式显示。相比图形化工具如Wireshark，tcpdump具有占用资源少、适合远程服务器、可编程和自动化等优势，是网络故障排查、安全分析和协议开发的重要工具。

### 主要特点

- **轻量级**：资源占用极小，适用于资源有限的环境
- **高效率**：能够处理高速网络流量
- **灵活性**：强大的过滤语法，精确定位需要的数据包
- **可移植性**：几乎所有Unix/Linux系统默认自带
- **自动化**：可轻松集成到脚本中实现自动化分析
- **远程适用**：通过SSH等远程连接在服务器上运行

### 适用场景

- 网络故障排查
- 安全事件调查
- 网络流量监控
- 协议分析与开发
- 网络性能评估
- 服务器性能问题定位

## 安装

### Linux系统

大多数Linux发行版已默认安装tcpdump，如果没有，可以通过包管理器安装：

```bash
# Debian/Ubuntu系统
sudo apt update
sudo apt install tcpdump

# RHEL/CentOS系统
sudo yum install tcpdump

# Fedora系统
sudo dnf install tcpdump

# Arch Linux
sudo pacman -S tcpdump
```

### macOS系统

macOS系统默认已安装tcpdump，无需额外安装。

### Windows系统

Windows系统可以通过以下方式获取类似功能：

1. **WinDump**：tcpdump的Windows移植版
2. **在WSL(Windows Subsystem for Linux)中安装tcpdump**
3. **使用Cygwin或MSYS2环境安装tcpdump**

```bash
# 在WSL中安装
wsl sudo apt install tcpdump
```

### 验证安装

```bash
# 检查版本
tcpdump --version
```

## 基本使用

### 命令语法

```bash
tcpdump [options] [expression]
```

### 常用选项

| 选项 | 描述 |
|------|------|
| `-i interface` | 指定捕获接口 |
| `-c count` | 指定捕获包数量 |
| `-n` | 不将地址解析为名称 |
| `-nn` | 不解析地址和端口 |
| `-v, -vv, -vvv` | 增加详细程度 |
| `-X` | 以十六进制和ASCII显示包内容 |
| `-w file.pcap` | 将捕获写入文件 |
| `-r file.pcap` | 从文件读取捕获 |
| `-s snaplen` | 设置捕获长度 |
| `-q` | 快速输出(更少协议信息) |
| `-t` | 不打印时间戳 |
| `-tttt` | 以可读格式打印时间戳 |

### 基本命令示例

```bash
# 显示在eth0接口的所有流量
sudo tcpdump -i eth0

# 捕获来自特定主机的100个数据包
sudo tcpdump -c 100 host 192.168.1.1

# 捕获特定端口流量
sudo tcpdump -i eth0 port 80

# 同时显示十六进制和ASCII输出
sudo tcpdump -i eth0 -X
```

## 过滤表达式

tcpdump的过滤表达式使用Berkeley Packet Filter (BPF)语法，可以非常精确地筛选数据包。

### 基本过滤类型

#### 按协议过滤

```bash
# 捕获TCP数据包
tcpdump tcp

# 捕获UDP数据包
tcpdump udp

# 捕获ICMP数据包
tcpdump icmp

# 捕获IPv6数据包
tcpdump ip6
```

#### 按主机过滤

```bash
# 捕获特定主机的数据包(源或目的)
tcpdump host 192.168.1.1

# 捕获特定源主机的数据包
tcpdump src host 192.168.1.1

# 捕获特定目的主机的数据包
tcpdump dst host 192.168.1.1
```

#### 按端口过滤

```bash
# 捕获特定端口的数据包
tcpdump port 80

# 捕获特定源端口的数据包
tcpdump src port 1025

# 捕获特定目的端口的数据包
tcpdump dst port 80
```

### 复合表达式

使用逻辑运算符组合多个条件：

- `and` 或 `&&` - 逻辑与
- `or` 或 `||` - 逻辑或
- `not` 或 `!` - 逻辑非
- 使用括号`()`分组表达式

```bash
# 捕获从192.168.1.1到192.168.1.2的TCP流量
tcpdump tcp and src host 192.168.1.1 and dst host 192.168.1.2

# 捕获80或443端口的流量
tcpdump port 80 or port 443

# 捕获除192.168.1.1外的所有主机的流量
tcpdump not host 192.168.1.1
```

## 输出格式

tcpdump默认输出包含时间戳、源和目的地址/端口、协议以及其他相关信息。

### 输出示例和解读

```
08:41:13.729687 IP 192.168.1.2.36786 > 93.184.216.34.443: Flags [S], seq 1902801202, win 64240, options [mss 1460,sackOK,TS val 3606567156 ecr 0,nop,wscale 7], length 0
```

解读：
- `08:41:13.729687` - 时间戳
- `IP` - 协议(IPv4)
- `192.168.1.2.36786` - 源IP和端口
- `93.184.216.34.443` - 目的IP和端口
- `Flags [S]` - TCP标志(SYN包)
- `seq 1902801202` - 序列号
- `win 64240` - 窗口大小
- `length 0` - 数据长度

### 自定义输出格式

```bash
# 使用详细输出
tcpdump -v

# 更详细的输出
tcpdump -vv

# 最详细的输出
tcpdump -vvv

# 十六进制和ASCII输出
tcpdump -X

# 十六进制和ASCII输出(包括链路层头部)
tcpdump -XX

# 可读时间戳格式
tcpdump -tttt
```

## 高级用法

### 保存和读取捕获文件

```bash
# 保存捕获到文件
tcpdump -i eth0 -w capture.pcap

# 从文件读取捕获
tcpdump -r capture.pcap

# 读取文件时应用过滤器
tcpdump -r capture.pcap 'tcp port 80'

# 保存文件并同时显示
tcpdump -i eth0 -w capture.pcap -U | tee output.txt
```

### 高级过滤技术

#### 分组大小过滤

```bash
# 捕获大于128字节的数据包
tcpdump greater 128

# 捕获小于32字节的数据包
tcpdump less 32
```

#### 特定标志过滤

```bash
# 捕获SYN数据包
tcpdump 'tcp[tcpflags] & tcp-syn != 0'

# 捕获SYN-ACK数据包
tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)'

# 捕获所有RST数据包
tcpdump 'tcp[tcpflags] & tcp-rst != 0'

# 捕获所有FIN数据包
tcpdump 'tcp[tcpflags] & tcp-fin != 0'
```

#### 基于包内容过滤

```bash
# 捕获包含"GET"的HTTP请求
tcpdump -A -s 1500 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' | grep "GET"
```

## 实用示例

### 网络故障排查

```bash
# 检测DNS查询问题
tcpdump -i any port 53

# 监控网络延迟
tcpdump -i eth0 icmp

# 检测丢包和重传
tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0'
```

### 安全分析

```bash
# 检测SYN洪水攻击
tcpdump -nn 'tcp[tcpflags] & tcp-syn != 0 and not tcp[tcpflags] & tcp-ack != 0'

# 检测异常大量的ICMP流量
tcpdump -i eth0 icmp and greater 100

# 检测可能的端口扫描
tcpdump -nn 'tcp[tcpflags] == tcp-syn and not src net localnet'
```

### 性能分析

```bash
# 监控高流量主机
tcpdump -i eth0 -nn -c 1000 | awk '{print $3}' | sort | uniq -c | sort -nr | head

# 识别占用带宽最多的会话
tcpdump -nn -v ip | awk '{print $3">"$5}' | sort | uniq -c | sort -nr | head
```

## 技巧与窍门

### 高效用法

1. **使用具体的过滤器** - 减轻CPU负载和减少输出噪音
2. **设置合理的捕获大小** - `tcpdump -s 96` 只捕获头部
3. **避免主机名解析** - 使用 `-n` 和 `-nn` 减少DNS查询延迟
4. **分析特定的数据包部分** - 使用偏移和位操作精确定位
5. **与其他工具结合** - 配合grep, awk, sort等工具处理输出

### 与其他工具结合

```bash
# 使用grep过滤输出
tcpdump -i eth0 -n | grep "192.168.1.1"

# 使用wc计算数据包数量
tcpdump -i eth0 -c 1000 tcp | wc -l

# 使用awk提取IP统计
tcpdump -i eth0 -nn -c 1000 | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -nr
```

## 常见问题

### 权限问题

需要root权限或特定组权限才能捕获网络数据包：

```bash
# 临时使用sudo运行
sudo tcpdump -i eth0

# 永久解决方案(添加用户到pcap组)
sudo usermod -a -G pcap $USER
```

### 性能考虑

1. **过滤器复杂度** - 复杂的BPF表达式会增加CPU负担
2. **磁盘IO** - 将捕获写入文件时注意磁盘性能
3. **高速网络** - 在千兆或万兆网络上可能会丢包

### 特殊接口处理

```bash
# 监听回环接口
tcpdump -i lo

# 监听所有接口
tcpdump -i any

# 监听特定VLAN
tcpdump -i eth0 vlan 100
```

## 参考资源

### 官方文档

- [tcpdump 手册页](https://www.tcpdump.org/manpages/tcpdump.1.html)
- [libpcap 文档](https://www.tcpdump.org/manpages/pcap.3pcap.html)

### 学习资源

- [tcpdump 过滤器速查表](https://packetlife.net/media/library/12/tcpdump.pdf)
- [SANS - tcpdump网络分析](https://www.sans.org/security-resources/tcpip.pdf)

### 工具和相关项目

- [libpcap](https://www.tcpdump.org/) - tcpdump使用的数据包捕获库
- [Wireshark](https://www.wireshark.org/) - 图形化数据包分析器
- [tshark](https://www.wireshark.org/docs/wsug_html_chunked/AppToolstshark.html) - Wireshark的命令行版本 