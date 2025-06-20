# Redis 安装与配置

Redis 的安装与配置相对简单，但为了充分发挥其性能并确保安全性，需要掌握适当的安装方法和关键配置选项。本文将详细介绍在各种环境下安装 Redis，以及基础和高级配置选项。

## 目录

- [在不同平台上安装 Redis](#在不同平台上安装-redis)
- [基本配置选项](#基本配置选项)
- [网络配置](#网络配置)
- [内存管理配置](#内存管理配置)
- [持久化配置](#持久化配置)
- [安全配置](#安全配置)
- [线程与性能配置](#线程与性能配置)
- [使用 Docker 部署 Redis](#使用-docker-部署-redis)
- [Redis 配置最佳实践](#redis-配置最佳实践)

## 在不同平台上安装 Redis

### Linux 系统安装

Linux 是 Redis 的推荐运行平台，提供了最佳性能和稳定性。

#### Ubuntu/Debian 系统

```bash
# 更新软件包列表
sudo apt update

# 安装 Redis
sudo apt install redis-server

# 启动 Redis 服务
sudo systemctl start redis-server

# 设置开机自启
sudo systemctl enable redis-server

# 检查 Redis 状态
sudo systemctl status redis-server
```

#### CentOS/RHEL/Fedora 系统

```bash
# 安装 EPEL 仓库（如果尚未安装）
sudo yum install epel-release

# 安装 Redis
sudo yum install redis

# 启动 Redis 服务
sudo systemctl start redis

# 设置开机自启
sudo systemctl enable redis

# 检查 Redis 状态
sudo systemctl status redis
```

#### 源码编译安装（适用于所有 Linux 发行版）

源码编译提供了最大的灵活性和最新功能：

```bash
# 安装编译依赖
sudo apt install build-essential tcl # Ubuntu/Debian
# 或
sudo yum groupinstall "Development Tools" # CentOS/RHEL
sudo yum install tcl # CentOS/RHEL

# 下载并解压 Redis 源码
wget https://download.redis.io/releases/redis-7.0.5.tar.gz
tar xzf redis-7.0.5.tar.gz
cd redis-7.0.5

# 编译 Redis
make

# 运行测试（可选）
make test

# 安装 Redis
sudo make install

# 创建配置目录
sudo mkdir -p /etc/redis
sudo mkdir -p /var/redis

# 复制配置文件
sudo cp redis.conf /etc/redis/redis.conf
```

### macOS 系统安装

#### 使用 Homebrew 安装

```bash
# 安装 Homebrew（如果尚未安装）
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 安装 Redis
brew install redis

# 启动 Redis 服务
brew services start redis

# 检查 Redis 状态
brew services list | grep redis
```

### Windows 系统安装

虽然 Redis 官方不直接支持 Windows，但有几种在 Windows 上运行 Redis 的方法：

#### 使用 WSL (Windows Subsystem for Linux)

最推荐的方式是使用 WSL，这样可以获得原生 Linux 环境的性能：

1. 启用 WSL 和安装 Ubuntu：
   ```powershell
   # 以管理员身份运行 PowerShell
   dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
   dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
   # 重启计算机
   # 安装 WSL 2
   wsl --set-default-version 2
   # 从 Microsoft Store 安装 Ubuntu
   ```

2. 在 Ubuntu WSL 中安装 Redis：
   ```bash
   sudo apt update
   sudo apt install redis-server
   ```

#### 使用 Redis for Windows

Tporadim 提供的非官方 Windows 版本：

1. 访问 [https://github.com/tporadowski/redis/releases](https://github.com/tporadowski/redis/releases)
2. 下载最新的 msi 安装包
3. 运行安装程序，按照向导完成安装
4. 通过 Windows 服务控制面板或命令行启动 Redis 服务

#### 使用 Docker 在 Windows 上运行 Redis

```powershell
# 拉取 Redis 镜像
docker pull redis

# 运行 Redis 容器
docker run --name my-redis -p 6379:6379 -d redis
```

## 基本配置选项

Redis 的配置文件通常位于 `/etc/redis/redis.conf`（Linux）或安装目录下的 `redis.conf`。以下是一些基本配置选项：

### 守护进程模式

```conf
# 以后台守护进程方式运行
daemonize yes
```

### 进程 ID 文件

```conf
# PID 文件路径
pidfile /var/run/redis/redis-server.pid
```

### 日志配置

```conf
# 日志级别：debug, verbose, notice, warning
loglevel notice

# 日志文件路径
logfile /var/log/redis/redis-server.log
```

### 数据库数量

```conf
# Redis 默认有 16 个数据库（0-15），可以根据需要增减
databases 16
```

## 网络配置

### 绑定地址

```conf
# 默认只监听本地回环接口，若要允许远程连接，修改为服务器 IP 或 0.0.0.0
bind 127.0.0.1

# Redis 6.0+ 可以绑定多个地址，并为每个地址设置不同的 ACL 规则
bind 127.0.0.1 192.168.1.100
```

### 端口设置

```conf
# Redis 默认端口
port 6379
```

### 最大连接数

```conf
# 最大客户端连接数
maxclients 10000
```

### 超时配置

```conf
# 客户端空闲超时时间（秒）
timeout 0  # 0 表示禁用超时
```

### TLS/SSL 配置 (Redis 6.0+)

```conf
# 启用 TLS
tls-port 6380
tls-cert-file /path/to/redis.crt
tls-key-file /path/to/redis.key
tls-ca-cert-file /path/to/ca.crt
tls-auth-clients yes
```

## 内存管理配置

### 内存限制

```conf
# 设置 Redis 最大内存限制（字节）
maxmemory 2gb
```

### 内存策略

当达到最大内存限制时，Redis 如何选择要删除的键：

```conf
# 可选策略:
# noeviction - 当内存限制达到时返回错误（默认）
# allkeys-lru - 移除最近最少使用的键
# volatile-lru - 移除有过期时间的最近最少使用的键
# allkeys-random - 随机移除键
# volatile-random - 随机移除有过期时间的键
# volatile-ttl - 移除最接近过期时间的键
# volatile-lfu - 移除使用频率最少的带过期时间的键（Redis 4.0+）
# allkeys-lfu - 移除使用频率最少的键（Redis 4.0+）
maxmemory-policy allkeys-lru
```

### LRU 和 LFU 采样参数

```conf
# LRU、LFU 和最小 TTL 算法的样本大小
maxmemory-samples 5
```

## 持久化配置

### RDB 持久化配置

```conf
# 在 900 秒（15分钟）内至少有 1 个 key 值变化时，自动进行数据库持久化操作
save 900 1

# 在 300 秒（5分钟）内至少有 10 个 key 值变化时，自动进行数据库持久化操作
save 300 10

# 在 60 秒内至少有 10000 个 key 值变化时，自动进行数据库持久化操作
save 60 10000

# 持久化文件名
dbfilename dump.rdb

# 持久化文件目录
dir /var/lib/redis

# 当 RDB 持久化出现错误时，是否停止写入操作
stop-writes-on-bgsave-error yes

# 是否压缩 RDB 文件
rdbcompression yes

# 是否校验 RDB 文件
rdbchecksum yes
```

### AOF 持久化配置

```conf
# 是否启用 AOF 持久化
appendonly yes

# AOF 文件名
appendfilename "appendonly.aof"

# 同步策略:
# always - 每个写命令都会同步写入磁盘（最安全，性能最低）
# everysec - 每秒执行一次同步（折中方案）
# no - 由操作系统决定何时同步（性能最高，安全性最低）
appendfsync everysec

# 在 AOF 重写期间是否同步
no-appendfsync-on-rewrite no

# AOF 重写触发条件：文件大小超过上次重写大小的百分比
auto-aof-rewrite-percentage 100

# AOF 重写触发条件：文件大小最小值
auto-aof-rewrite-min-size 64mb
```

### 混合持久化配置 (Redis 4.0+)

```conf
# 启用混合持久化（AOF 文件中包含 RDB 文件头）
aof-use-rdb-preamble yes
```

## 安全配置

### 访问密码设置

```conf
# 设置 Redis 密码
requirepass your_strong_password_here
```

### ACL 配置 (Redis 6.0+)

```conf
# 定义用户权限
user default on >your_strong_password_here ~* +@all

# 创建只读用户
user readonly on >readonly_password +@read ~*
```

### 重命名危险命令

```conf
# 禁用 FLUSHALL 命令（通过重命名为空字符串）
rename-command FLUSHALL ""

# 重命名 CONFIG 命令
rename-command CONFIG "b840fc02d524045429941cc15f59e41cb7be6c52"
```

## 线程与性能配置

### I/O 线程配置 (Redis 6.0+)

```conf
# I/O 线程数（默认为 4）
io-threads 4

# 启用 I/O 线程处理写操作
io-threads-do-reads no
```

### 延迟监控

```conf
# 启用延迟监控
latency-monitor-threshold 100
```

### 慢日志配置

```conf
# 记录执行时间超过指定微秒数的查询（此处为 10 毫秒）
slowlog-log-slower-than 10000

# 慢日志最大长度
slowlog-max-len 128
```

## 使用 Docker 部署 Redis

Docker 提供了一种简单、一致的方式来部署 Redis，无需担心依赖和环境配置：

### 基本 Docker 部署

```bash
# 拉取官方 Redis 镜像
docker pull redis

# 运行 Redis 容器
docker run --name my-redis -p 6379:6379 -d redis

# 使用自定义配置文件
docker run --name my-redis -v /path/to/redis.conf:/usr/local/etc/redis/redis.conf \
  -p 6379:6379 -d redis redis-server /usr/local/etc/redis/redis.conf
```

### 使用 Docker Compose

创建 `docker-compose.yml` 文件：

```yaml
version: '3'

services:
  redis:
    image: redis:latest
    container_name: my-redis
    ports:
      - "6379:6379"
    volumes:
      - ./redis.conf:/usr/local/etc/redis/redis.conf
      - ./data:/data
    command: redis-server /usr/local/etc/redis/redis.conf
    restart: always
```

启动 Redis：

```bash
docker-compose up -d
```

## Redis 配置最佳实践

### 生产环境配置建议

1. **内存设置**：
   - 将 `maxmemory` 设置为系统总内存的 50-70%
   - 使用 `allkeys-lru` 或 `volatile-lru` 作为内存策略

2. **持久化设置**：
   - 对于高可用性需求，启用混合持久化（Redis 4.0+）
   - 对于高性能需求，考虑仅使用 RDB 持久化
   - 避免在高负载时进行 BGSAVE 或 AOF 重写

3. **网络设置**：
   - 将 Redis 部署在专用服务器/实例上
   - 使用适当的 TCP 内核参数优化网络
   - 在可能的情况下，使用 Unix 域套接字减少网络开销

4. **安全设置**：
   - 始终设置强密码
   - 使用 `bind` 限制访问
   - 使用 Redis 6.0+ 的 ACL 功能进行细粒度权限控制
   - 禁用或重命名危险命令

### 常见配置示例

#### 小型缓存服务器

```conf
daemonize yes
bind 127.0.0.1
protected-mode yes
port 6379
maxmemory 1gb
maxmemory-policy allkeys-lru
appendonly no
save 900 1
save 300 10
```

#### 持久化存储服务器

```conf
daemonize yes
bind 127.0.0.1
protected-mode yes
port 6379
maxmemory 4gb
maxmemory-policy noeviction
appendonly yes
appendfsync everysec
aof-use-rdb-preamble yes
save 900 1
save 300 10
save 60 10000
```

#### 高性能会话存储

```conf
daemonize yes
bind 127.0.0.1
protected-mode yes
port 6379
maxmemory 2gb
maxmemory-policy volatile-lru
appendonly no
save ""  # 禁用 RDB 持久化
```

## 验证安装与配置

安装和配置完成后，可以通过以下命令验证 Redis 是否正常工作：

```bash
# 连接到 Redis
redis-cli

# 如果设置了密码，需要先验证
auth your_password

# 测试连接
ping
# 应该返回 PONG

# 设置一个键值对
set mykey "Hello Redis"

# 获取键值
get mykey

# 查看 Redis 信息
info

# 查看内存使用情况
info memory

# 退出
exit
```

## 小结

成功安装和适当配置 Redis 是充分利用其性能和功能的基础。根据您的具体用例和环境需求，选择合适的安装方法和配置选项。随着对 Redis 理解的深入，您可以进一步优化配置以满足特定性能和安全需求。

在下一章中，我们将深入探讨 Redis 的架构，以帮助您更好地理解其内部工作原理，从而做出更明智的配置决策。
