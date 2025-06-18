# NetworkMiner 网络取证分析工具

<div align="center">
  <img src="../../assets/networkminer-logo.png" alt="NetworkMiner Logo" width="200">
</div>

> NetworkMiner是一款高级网络取证分析工具(NFAT)，专注于从网络流量中提取文件、图片、凭证和其他关键信息，并提供直观的网络情报分析界面。

## 目录

- [简介](#简介)
- [版本与许可](#版本与许可)
- [安装配置](#安装配置)
- [基本功能](#基本功能)
- [高级功能](#高级功能)
- [取证分析](#取证分析)
- [案例分析](#案例分析)
- [最佳实践](#最佳实践)
- [常见问题](#常见问题)
- [参考资源](#参考资源)

## 简介

NetworkMiner是一款网络取证和流量分析工具，它采用被动分析方法，专注于从网络流量中提取各种应用层的信息。不同于Wireshark等工具主要关注数据包层面，NetworkMiner自动重组会话内容，提取文件、图像、消息和凭据，为分析师提供更高层次的网络情报视图。

### 主要特点

- **被动OS指纹识别** - 识别网络中的设备操作系统
- **自动文件提取** - 从捕获的流量中重建和提取传输的文件
- **强大的主机分析** - 详细显示每台主机的会话、连接和参数
- **凭据提取** - 识别并收集传输的用户名和密码
- **跨平台支持** - 可在Windows、Linux和macOS上运行
- **多种格式支持** - 处理PCAP、PCAPNG等多种网络捕获格式
- **会话重构** - 重构和显示HTTP、DNS、FTP等各种协议的会话内容
- **元数据分析** - 提取和显示通信模式和关联

### 与其他工具对比

| 功能 | NetworkMiner | Wireshark | tcpdump |
|------|-------------|-----------|---------|
| 主要用途 | 网络取证、数据提取 | 深度数据包分析 | 数据包捕获 |
| 界面类型 | 图形界面 | 图形界面 | 命令行 |
| 数据提取 | 自动化、面向内容 | 手动、需要过滤器 | 有限 |
| 文件重组 | 自动化、集成 | 需要手动导出 | 不支持 |
| OS指纹识别 | 内置、被动式 | 需插件 | 不支持 |
| 易用性 | 高（面向结果） | 中（需要专业知识） | 低（需要命令行经验） |
| 实时分析 | 支持但非专长 | 非常强大 | 强大 |
| 离线分析 | 专长 | 支持 | 支持 |
| 资源占用 | 中等 | 高 | 低 |

## 版本与许可

NetworkMiner提供两个版本：

### 免费版(开源)

- 基础取证功能
- 基本协议支持
- GPLv2许可
- 社区支持

### 专业版(商业)

- 增强的取证功能
- 扩展的协议支持
- 通过信用卡或发票购买许可证
- 商业支持
- 更快的解析速度
- 额外的案例管理功能
- PCAP分割与合并功能
- 地理位置映射

## 安装配置

### 系统需求

- **.NET Framework**：4.7或更高版本(Windows)
- **Mono**：适用于Linux和macOS(开源版本)
- **内存**：至少2GB RAM，推荐4GB以上
- **磁盘空间**：程序占用约100MB，但需要足够空间存储分析数据
- **处理器**：推荐多核处理器以提高大型捕获文件的分析速度

### Windows安装

1. 从[官方网站](https://www.netresec.com/?page=NetworkMiner)下载最新版本
2. 解压ZIP文件到所需位置(无需安装)
3. 运行NetworkMiner.exe

### Linux安装

```bash
# 安装依赖项
sudo apt update
sudo apt install mono-complete

# 下载并解压NetworkMiner
wget https://www.netresec.com/?download=NetworkMiner -O NetworkMiner.zip
unzip NetworkMiner.zip -d NetworkMiner
cd NetworkMiner

# 设置权限
chmod +x NetworkMiner.exe
chmod -R +r *

# 运行NetworkMiner
mono NetworkMiner.exe
```

### macOS安装

```bash
# 安装Homebrew(如果尚未安装)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"

# 安装Mono
brew install mono

# 下载并解压NetworkMiner
curl -L https://www.netresec.com/?download=NetworkMiner -o NetworkMiner.zip
unzip NetworkMiner.zip -d NetworkMiner
cd NetworkMiner

# 设置权限
chmod +x NetworkMiner.exe
chmod -R +r *

# 运行NetworkMiner
mono NetworkMiner.exe
```

## 基本功能

### 界面布局

NetworkMiner的界面由几个关键部分组成：

1. **主菜单** - 文件操作、设置和帮助选项
2. **选项卡面板** - 不同类型的提取数据视图
3. **主机面板** - 发现的主机列表
4. **案例面板** - 当前案例信息和状态

### 主要选项卡

- **主机** - 发现主机的详细信息
- **浏览器** - 浏览活动和会话
- **文件** - 提取的文件和元数据
- **图片** - 重构的图像
- **消息** - 电子邮件和聊天消息
- **凭据** - 用户名和密码
- **会话** - 重建的通信会话
- **DNS** - 域名查询和响应
- **参数** - HTTP参数和表单数据
- **关键字** - 检测到的关键字匹配

### 基本操作

#### 打开捕获文件

1. 点击"File" > "Open"
2. 选择PCAP/PCAPNG文件
3. 等待分析完成

#### 实时捕获

1. 点击"File" > "New"
2. 选择"Live Capture"选项
3. 选择网络接口
4. 点击"Start"开始捕获

#### 浏览结果

1. 在左侧主机面板中选择主机
2. 使用选项卡查看该主机相关的各类信息
3. 使用过滤器或排序选项找到感兴趣的信息

#### 导出提取的文件

1. 在"Files"选项卡中选择文件
2. 右键点击，选择"Save selected files"
3. 选择保存位置

## 高级功能

### 过滤器和搜索

- **主机过滤** - 基于IP、MAC地址或主机名过滤
- **时间过滤** - 基于时间范围过滤
- **协议过滤** - 仅显示特定协议的数据
- **关键字搜索** - 在所有提取的文本中搜索
- **正则表达式** - 使用高级模式匹配搜索

### 自定义指纹识别

1. 导航到"Tools" > "OS Fingerprinting"
2. 添加或编辑自定义指纹
3. 设置匹配规则和描述

### 案例管理

*专业版功能*

1. 创建新案例：File > New > Case
2. 添加多个PCAP文件到同一案例
3. 添加案例笔记和元数据
4. 导出整个案例报告

### 脚本和自动化

1. 使用命令行参数批量处理
   ```
   NetworkMiner.exe -r capture.pcap -w output_dir
   ```

2. 编写脚本集成NetworkMiner与其他工具

## 取证分析

### 主机分析

1. **OS识别** - 被动确定主机操作系统
2. **设备类型** - 确定网络设备类型
3. **开放端口** - 识别主机开放的端口
4. **MAC地址** - 显示物理地址和制造商
5. **主机名** - 从DHCP、NBNS等提取的主机名
6. **TTL分析** - 帮助确定网络跳数和可能的欺骗

### 网络行为分析

1. **会话分析** - 查看完整通信流程
2. **协议使用** - 识别使用的协议和服务
3. **数据传输** - 分析传输模式和数据量
4. **通信关系** - 建立网络通信图

### 内容分析

1. **文件提取** - 根据文件签名自动提取文件
2. **文件时间线** - 显示文件传输的时间线
3. **媒体分析** - 提取和分析图片、视频
4. **文本提取** - 从各协议提取文本内容
5. **元数据分析** - 分析文件和通信元数据

### 证据提取

1. **用户凭据** - 提取明文密码和哈希值
2. **Cookie分析** - 提取和分析网络Cookie
3. **会话令牌** - 识别认证令牌
4. **表单数据** - 提取HTTP表单提交数据
5. **证据标记** - 标记重要发现

## 案例分析

### 恶意软件分析

1. **检测异常连接** - 识别潜在的C&C通信
2. **文件提取** - 提取和分析传输的可疑文件
3. **协议异常** - 识别不规范的协议使用
4. **加密分析** - 识别可疑的加密通信模式

### 数据泄露调查

1. **敏感文件识别** - 检测和提取敏感文档
2. **凭据暴露** - 识别明文传输的凭据
3. **数据外流** - 分析大量外发数据传输
4. **时间线分析** - 建立事件时间线

### 网络取证实践

1. **捕获管理** - 有效处理大型捕获文件
2. **证据保存** - 保存和记录所有提取的数据
3. **报告生成** - 创建详细的调查报告
4. **链式证据** - 维护证据的完整链条

## 最佳实践

### 高效使用技巧

1. **使用正确的捕获设置** - 确保使用完整捕获而非截断包
2. **分割大型捕获文件** - 处理超大型文件时分割为多个文件
3. **使用时间过滤** - 缩小分析范围到相关时间段
4. **重点关注关键主机** - 优先分析可疑或关键主机
5. **结合其他工具** - 与Wireshark等工具配合使用

### 性能优化

1. **增加内存分配** - 调整JVM内存设置
2. **使用SSD** - 将临时文件和输出目录设置在SSD上
3. **合理过滤** - 在分析前应用BPF过滤器减少数据量
4. **关闭不必要选项卡** - 禁用当前不需要的分析模块

## 常见问题

### 性能问题

- **问题**：处理大型PCAP文件时非常慢
- **解决方案**：
  - 增加分配给应用的内存
  - 使用专业版(速度更快)
  - 分割捕获文件后分开分析
  - 关闭不需要的提取功能

### 提取失败

- **问题**：某些文件或数据未被提取
- **解决方案**：
  - 检查捕获是否完整(没有丢包)
  - 更新到最新版本
  - 检查文件是否使用了不支持的加密
  - 尝试使用专业版(支持更多协议)

### 操作系统识别不准确

- **问题**：OS指纹识别结果不匹配已知操作系统
- **解决方案**：
  - 更新指纹数据库
  - 确保有足够的数据包用于分析
  - 手动添加自定义指纹

## 参考资源

### 官方资源

- [NetworkMiner官网](https://www.netresec.com/?page=NetworkMiner)
- [NETRESEC博客](https://www.netresec.com/index.ashx?page=Blog)
- [NetworkMiner文档](https://www.netresec.com/?page=NetworkMinerDocumentation)

### 学习资源

- [网络取证指南](https://www.sans.org/reading-room/whitepapers/forensics/)
- [PCAP分析最佳实践](https://isc.sans.edu/diary/packet+capture/8337)

### 社区资源

- [SANS取证社区](https://digital-forensics.sans.org/)
- [网络安全堆栈交换](https://security.stackexchange.com/)

### 相关工具

- [Wireshark](https://www.wireshark.org/)
- [tcpdump](https://www.tcpdump.org/)
- [Tshark](https://www.wireshark.org/docs/man-pages/tshark.html)
- [Caploader](https://www.netresec.com/?page=CapLoader) 