# Wireshark 进阶技术

<div align="center">
  <img src="../../assets/wireshark-logo.png" alt="Wireshark Logo" width="200">
</div>

> 本文档介绍Wireshark的进阶使用技巧，包括高级过滤语法、深度协议分析、性能优化和专业故障排查技术。

## 目录

1. [高级捕获过滤器](#高级捕获过滤器)
   - [BPF语法详解](#BPF语法详解)
   - [复杂条件组合](#复杂条件组合)
   - [性能优化策略](#性能优化策略)
   - [过滤器管理](#过滤器管理)
2. [显示过滤器精通](#显示过滤器精通)
   - [语法进阶](#语法进阶)
   - [逻辑运算符应用](#逻辑运算符应用)
   - [正则表达式](#正则表达式)
   - [实用过滤表达式](#实用过滤表达式)
3. [数据包分析技术](#数据包分析技术)
   - [会话重组](#会话重组)
   - [字段提取与分析](#字段提取与分析)
   - [多层协议解析](#多层协议解析)
   - [异常检测](#异常检测)
4. [分析特定协议](#分析特定协议)
   - [HTTP/HTTPS分析](#HTTPHTTPS分析)
   - [DNS分析与故障排查](#DNS分析与故障排查)
   - [TCP性能分析](#TCP性能分析)
   - [VoIP通信分析](#VoIP通信分析)
   - [无线网络分析](#无线网络分析)
5. [统计与可视化分析](#统计与可视化分析)
   - [流量统计图表](#流量统计图表)
   - [端点统计](#端点统计)
   - [协议层级统计](#协议层级统计)
   - [服务响应时间](#服务响应时间)
   - [自定义统计报告](#自定义统计报告)
6. [性能优化](#性能优化)
   - [大型捕获文件处理](#大型捕获文件处理)
   - [资源使用优化](#资源使用优化)
   - [多文件分析](#多文件分析)
7. [集成外部工具](#集成外部工具)
   - [GeoIP映射](#GeoIP映射)
   - [外部解析器](#外部解析器)
   - [命令行工具链接](#命令行工具链接)

## 高级捕获过滤器

捕获过滤器在数据包被捕获前应用，可以显著减少捕获的数据量，提高性能。掌握高级捕获过滤器技术对于分析大型网络或高流量环境至关重要。

### BPF语法详解

Berkeley Packet Filter (BPF)是Wireshark捕获过滤器使用的语法，具有强大的表达能力和高效的执行特性。

#### 基本语法结构
```
[协议] [方向] [主机/网络] [值]
```

例如：
```
ip host 192.168.1.1             # 捕获与特定IP相关的流量
tcp dst port 80                 # 捕获目的端口为80的TCP流量
not icmp                        # 捕获非ICMP流量
```

#### 原语(Primitives)类型

1. **类型原语**
   ```
   ether/fddi/ip/arp/rarp/decnet/tcp/udp/icmp
   ```

2. **方向原语**
   ```
   src/dst
   ```
   
3. **主机标识符**
   ```
   host/net/port/portrange
   ```

#### 复杂表达式
```
# 捕获从192.168.1.10到TCP端口80或443的流量
ip src host 192.168.1.10 and tcp dst portrange 80-443

# 捕获特定子网的非ICMP流量
net 192.168.0.0/24 and not icmp

# 捕获特定MAC地址的ARP流量
ether host 00:11:22:33:44:55 and arp
```

### 复杂条件组合

高级场景需要组合多个条件创建精确的捕获过滤器。

#### 逻辑运算符

- `and` / `&&`: 逻辑与
- `or` / `||`: 逻辑或
- `not` / `!`: 逻辑非
- 使用括号`()`分组表达式

#### 复杂过滤示例

1. **特定主机与多个服务之间的通信**
   ```
   host 192.168.1.100 and (tcp port 80 or tcp port 443 or udp port 53)
   ```

2. **排除特定子网的广播流量**
   ```
   not (net 192.168.0.0/24 and ether broadcast)
   ```

3. **捕获包含特定大小的TCP数据包**
   ```
   tcp and greater 1000 and less 1500
   ```

4. **捕获TCP连接建立过程**
   ```
   tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0
   ```

5. **捕获特定VLAN内的流量**
   ```
   vlan 100 and ip
   ```

### 性能优化策略

精心设计的捕获过滤器可以显著提升Wireshark的性能和有效性。

#### 优化技巧

1. **减少捕获量**
   - 仅选择必需的协议: `tcp or udp` 而非全部流量
   - 限制特定主机或网络: `host 192.168.1.1` 而非整个网络

2. **避免复杂计算**
   - 当过滤表达式过于复杂时，可能导致CPU负载高
   - 拆分复杂过滤器为多次捕获会更高效

3. **使用偏移和位掩码优化**
   ```
   # 优化版本: 直接检查TCP标志位字节
   tcp[13] & 0x02 != 0   # 比 "tcp[tcpflags] & tcp-syn != 0" 更高效
   ```

4. **数据包大小过滤**
   - 过滤小数据包减少噪音: `greater 128`
   - 或专注于大数据包: `greater 1400`

### 过滤器管理

有效管理和组织过滤器可以提高工作效率。

#### 创建过滤器库

1. 在Wireshark中保存常用过滤器:
   - 捕获 > 捕获过滤器 > "+"按钮添加
   - 为过滤器提供描述性名称

2. 导出和导入过滤器配置:
   ```
   # 导出过滤器到文件
   # 位置: ~/.wireshark/cfilters 或 %APPDATA%\Wireshark\cfilters
   ```

3. 创建过滤器层级:
   - 基础过滤器: `host 192.168.1.1`
   - 附加条件: `host 192.168.1.1 and tcp port 80`

#### 协作共享过滤器

团队环境中共享有效的过滤器表达式:
1. 建立过滤器库文档
2. 为特定类型分析创建标准过滤器
3. 使用版本控制系统管理过滤器文件

## 显示过滤器精通

与捕获过滤器不同，显示过滤器应用于已捕获的数据包，允许精确定位特定数据包。显示过滤器语法更强大，可以访问协议的任何字段。

### 语法进阶

显示过滤器语法比捕获过滤器更灵活和强大，支持完整的协议解析和字段访问。

#### 基本语法

```
[协议].[字段] [比较运算符] [值]
```

示例:
```
ip.addr == 192.168.1.1    # IP地址匹配
tcp.port == 443           # TCP端口匹配
http.request.method == "GET"  # HTTP方法匹配
```

#### 比较运算符

- 相等: `==`, `eq`
- 不等: `!=`, `ne`
- 大于: `>`, `gt`
- 小于: `<`, `lt`
- 大于等于: `>=`, `ge`
- 小于等于: `<=`, `le`
- 包含: `contains`
- 匹配正则表达式: `matches`, `~`

#### 存在性判断

```
http.request              # 存在HTTP请求
!tcp.analysis.retransmission  # 不是TCP重传包
```

#### 集合操作

```
tcp.port in {80 443 8080}   # TCP端口在集合中
!(udp.port in {53 5353})    # UDP端口不在集合中
```

### 逻辑运算符应用

复杂分析场景需要组合多个过滤条件。

#### 可用运算符

- 与: `and`, `&&`
- 或: `or`, `||`
- 非: `not`, `!`
- 分组: `()`

#### 实际应用示例

1. **识别特定会话**
   ```
   (ip.src == 192.168.1.10 and ip.dst == 8.8.8.8) or (ip.src == 8.8.8.8 and ip.dst == 192.168.1.10)
   
   # 更简洁的表达方式
   ip.addr == 192.168.1.10 and ip.addr == 8.8.8.8
   ```

2. **查找异常HTTP响应**
   ```
   http.response and http.response.code != 200
   ```

3. **过滤排除常见噪声**
   ```
   not (arp or icmp or dns)
   ```

4. **特定应用程序流量分析**
   ```
   (tcp.port == 80 or tcp.port == 443) and (http or tls)
   ```

### 正则表达式

Wireshark支持在显示过滤器中使用Perl兼容正则表达式(PCRE)。

#### 基本语法
```
[字段] matches "[正则表达式]"
```

或使用简写符号:
```
[字段] ~ "[正则表达式]"
```

#### 实用示例

1. **查找特定URL路径**
   ```
   http.request.uri matches "login|auth|admin"
   ```

2. **查找特定HTTP用户代理**
   ```
   http.user_agent ~ "Mozilla/5\.0.*Chrome"
   ```

3. **查找特定格式邮件地址**
   ```
   smtp.data.line matches "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
   ```

4. **查找IP地址范围**
   ```
   ip.dst ~ "^192\.168\.1\.(1[0-9]|2[0-5])$"
   ```

### 实用过滤表达式

以下是一些实用的显示过滤器表达式，可直接应用于常见分析场景。

#### 网络故障排查
```
# TCP重传，窗口满和窗口更新
tcp.analysis.flags && !tcp.analysis.window_update

# TCP零窗口
tcp.analysis.zero_window

# 检测TCP连接重置
tcp.flags.reset == 1

# 显示所有TCP排序问题
tcp.analysis.out_of_order or tcp.analysis.retransmission

# 显示网络延迟问题(RTT值大)
tcp.analysis.ack_rtt > 0.5
```

#### 安全分析
```
# 检测端口扫描(目标主机为192.168.1.1)
ip.dst==192.168.1.1 and tcp.flags.syn==1 and tcp.flags.ack==0

# SMB身份验证失败
smb.status == 0xc000006d

# HTTP错误响应
http.response.code >= 400

# TLS告警消息
tls.alert_message.desc != 0

# DNS异常响应
dns.flags.rcode != 0
```

#### 应用性能分析
```
# HTTP慢响应(超过1秒)
http.time > 1

# DNS解析时间超过100毫秒
dns.time > 0.1

# 数据库查询时间超过200毫秒
mysql.time > 0.2

# 检测HTTP内容编码
http.content_encoding

# 检测HTTPS证书问题
ssl.handshake.certificate and (ssl.handshake.type == 11)
```

#### 复杂过滤示例

1. **显示TCP握手和挥手**
   ```
   tcp.flags.syn==1 or tcp.flags.fin==1 or tcp.flags.reset==1
   ```

2. **各协议分析**
   ```
   # HTTP POST请求带JSON内容
   http.request.method == "POST" and http.content_type contains "application/json"
   
   # 检测DNS域名查询
   dns.qry.name contains "example.com"
   
   # 检测特定长度的TLS记录
   tls.record.length > 1000
   ```

## 数据包分析技术

### 会话重组

Wireshark能够重组构成完整会话的多个数据包，使分析复杂协议交互更加容易。

#### TCP流重组

1. **查看TCP流**
   - 选择数据包 > 右键 > "追踪流" > "TCP流"
   - 快捷键: Ctrl+Alt+Shift+T (Windows/Linux) 或 Cmd+Alt+Shift+T (macOS)

2. **重组设置**
   - 首选项 > 协议 > TCP > 允许子协议处理重组TCP流
   - 调整"重组缓冲区大小"和"重组超时"参数

3. **处理乱序数据包**
   - 首选项 > 协议 > TCP > 尝试解析非可靠流中的非最后一个段
   - 对分析重传和丢包场景有用

#### HTTP/2多路复用会话

HTTP/2允许在单个TCP连接上进行多个并行请求和响应。

1. **查看HTTP/2流**
   - 选择HTTP/2数据包 > 右键 > "HTTP/2" > "查看HTTP/2流"

2. **分析HTTP/2帧**
   - 检查HEADERS、DATA、SETTINGS、WINDOW_UPDATE等帧
   - 关联不同流标识符

#### 其他协议重组

1. **UDP流重组**
   - 在某些协议中可用(DNS, QUIC等)
   - 选择数据包 > 右键 > "追踪流" > "UDP流"

2. **SSL/TLS会话重组**
   - 需要提供会话密钥(后续部分详述)
   - 解密后可查看应用层协议内容

### 字段提取与分析

从数据包中提取特定字段进行深度分析。

#### 字段提取方法

1. **使用"数据包字段"功能**
   - 视图 > 内部 > 数据包字段
   - 显示当前选中数据包的所有字段值

2. **使用"导出数据包解析结果"**
   - 文件 > 导出数据包解析结果
   - 可导出为CSV、JSON、YAML等格式

3. **字段计算器**
   - 分析 > 字段计算器
   - 计算特定字段的统计信息

4. **提取特定字段到列**
   - 右键点击感兴趣字段 > "应用为列"

#### 字段统计分析

1. **创建字段出现频率统计**
   ```
   # 统计HTTP用户代理
   统计 > HTTP > 用户代理
   
   # 统计HTTP服务器类型
   统计 > HTTP > 数据包计数器 > 服务器
   ```

2. **自定义字段统计**
   - 统计 > 自定义
   - 选择要统计的字段(如ip.src)
   - 设置统计参数

### 多层协议解析

复杂网络流量通常包含多层协议封装，Wireshark提供强大的多层解析能力。

#### 隧道协议分析

1. **分析VPN流量**
   - IPsec, OpenVPN, PPTP等隧道协议
   - 需要配置相应解析器和密钥

2. **VLAN标签和QinQ**
   ```
   # 过滤特定VLAN
   vlan.id == 100
   
   # 过滤QinQ(双层VLAN)
   vlan.id == 100 && vlan.id == 200
   ```

3. **GRE隧道**
   ```
   # 过滤GRE封装流量
   gre
   
   # 分析GRE内部协议
   gre.proto == 0x0800  # IP over GRE
   ```

### 异常检测

Wireshark提供多种方式识别网络中的异常行为和问题。

#### 专家信息系统

专家信息系统自动分析流量并标记潜在问题。

1. **访问专家信息**
   - 分析 > 专家信息
   - 快捷键: Ctrl+E (Windows/Linux) 或 Cmd+E (macOS)

2. **严重级别**
   - 聊天: 常规信息
   - 注释: 值得注意的事件
   - 警告: 可能的问题
   - 错误: 严重问题
   - 致命: 导致系统崩溃的问题

3. **常见专家项目**
   ```
   # TCP重传
   tcp.analysis.retransmission
   
   # TCP零窗口
   tcp.analysis.zero_window
   
   # TCP窗口满
   tcp.analysis.window_full
   
   # TCP保持活动
   tcp.analysis.keep_alive
   ```

#### 自定义异常检测

1. **设置告警**
   - 可以配置特定条件触发的告警
   - 基于数据包内容、计时或序列创建告警

2. **创建触发条件**
   ```
   # 检测特定错误码
   http.response.code == 500
   
   # 检测异常长度数据包
   frame.len > 9000
   
   # 检测可疑SSL证书
   ssl.handshake.certificate and ssl.handshake.certificate.length < 300
   ```

3. **异常活动检测**
   ```
   # 检测大量SYN包(可能是DDoS尝试)
   tcp.flags.syn == 1 and tcp.flags.ack == 0
   
   # 检测DNS放大攻击
   dns.flags.response == 1 and dns.qry.name.len > 50
   ```

#### 性能异常检测

1. **延迟分析**
   - 使用时间戳差值检测高延迟
   - 关注TCP重传和超时

2. **吞吐量分析**
   - 统计 > 会话 > TCP图表
   - 识别吞吐量突然下降

3. **服务质量问题**
   ```
   # 抖动检测(VoIP)
   rtp.stats.delta > 30
   
   # 高丢包率
   rtp.stats.lost > 5
   ```

## 分析特定协议

### HTTP/HTTPS分析

HTTP(S)是现代互联网的基础协议，Wireshark提供了强大的分析功能。

#### HTTP流量分析

1. **过滤HTTP流量**
   ```
   # 显示所有HTTP流量
   http
   
   # 显示特定HTTP方法
   http.request.method == "POST"
   ```

2. **提取HTTP对象**
   - 文件 > 导出对象 > HTTP
   - 保存网页、图片、视频等内容

3. **分析HTTP性能**
   ```
   # 分析HTTP请求-响应延迟
   http.time > 0.5
   
   # 分析HTTP状态码
   http.response.code >= 400
   ```

4. **检测异常HTTP行为**
   ```
   # 异常长URI
   http.request.uri.length > 200
   
   # 大量重定向
   http.response.code == 302
   
   # 特定用户代理
   http.user_agent contains "scanner"
   ```

#### HTTPS / TLS分析

1. **解密HTTPS流量**
   
   **使用预主密钥日志(推荐)**
   - 设置SSLKEYLOGFILE环境变量指向日志文件
   - 首选项 > 协议 > TLS > (Pre)-Master-Secret日志文件名
   
   **使用私钥(服务器端)**
   - 首选项 > 协议 > TLS > RSA密钥列表
   - 添加服务器IP、端口、协议、密钥文件路径

2. **分析TLS握手**
   ```
   # 查看TLS握手消息
   ssl.handshake.type
   
   # 分析密码套件
   ssl.handshake.ciphersuite
   ```

3. **检查证书**
   ```
   # 显示证书详情
   ssl.handshake.certificate
   
   # 检查证书有效性
   ssl.alert_message.desc == 42  # 证书过期
   ssl.alert_message.desc == 48  # 未知CA
   ```

4. **TLS版本和安全性分析**
   ```
   # 检测弱TLS版本
   ssl.record.version <= 0x0301  # TLS 1.0或更低
   
   # 检测弱密码套件
   ssl.handshake.ciphersuite in {0x0005 0x0004}  # RC4
   ```

### DNS分析与故障排查

DNS是互联网基础设施的关键组件，Wireshark可以深度分析DNS问题。

#### 基本DNS分析

1. **过滤DNS流量**
   ```
   # 所有DNS流量
   dns
   
   # 仅DNS查询
   dns.flags.response == 0
   
   # 仅DNS响应
   dns.flags.response == 1
   ```

2. **域名查询分析**
   ```
   # 特定域名查询
   dns.qry.name contains "example.com"
   
   # 特定类型查询
   dns.qry.type == 1  # A记录
   dns.qry.type == 28  # AAAA记录
   dns.qry.type == 15  # MX记录
   dns.qry.type == 16  # TXT记录
   ```

3. **DNS响应类型**
   ```
   # 成功响应
   dns.flags.rcode == 0
   
   # 域名不存在
   dns.flags.rcode == 3  # NXDOMAIN
   
   # 服务器失败
   dns.flags.rcode == 2  # SERVFAIL
   ```

#### 高级DNS问题排查

1. **DNS延迟分析**
   ```
   # 高延迟DNS响应
   dns.time > 0.1
   ```

2. **DNS缓存分析**
   ```
   # 检查TTL值
   dns.resp.ttl < 60  # 短TTL可能表示CDN或负载均衡
   ```

3. **DNS放大攻击检测**
   ```
   # 大型DNS响应(可能用于放大攻击)
   dns.flags.response == 1 and dns.resp.len > 512
   ```

4. **递归查询跟踪**
   ```
   # DNS递归查询
   dns.flags.recdesired == 1
   ```

5. **异常DNS行为**
   ```
   # DNS隧道检测(大量TXT记录)
   dns.resp.type == 16 and dns.resp.len > 200
   
   # 可疑域名(长度异常)
   dns.qry.name.len > 50
   ```

### TCP性能分析

TCP是互联网最重要的传输层协议，Wireshark提供全面的性能分析工具。

#### 基本TCP会话分析

1. **TCP会话建立与终止**
   ```
   # 三次握手
   tcp.flags.syn == 1
   
   # 四次挥手
   tcp.flags.fin == 1
   
   # 连接重置
   tcp.flags.reset == 1
   ```

2. **TCP窗口分析**
   ```
   # 窗口大小调整
   tcp.window_size_value
   
   # 窗口缩放因子
   tcp.window_size_scalefactor
   
   # 零窗口(流量控制)
   tcp.analysis.zero_window
   ```

3. **TCP序列号分析**
   ```
   # 序列号跟踪
   tcp.seq
   
   # 确认号跟踪
   tcp.ack
   ```

#### 高级TCP性能故障排查

1. **重传分析**
   ```
   # 查找所有重传
   tcp.analysis.retransmission
   
   # 快速重传
   tcp.analysis.fast_retransmission
   
   # 重复确认
   tcp.analysis.duplicate_ack
   ```

2. **延迟分析**
   ```
   # 往返时间(RTT)
   tcp.analysis.ack_rtt > 0.5  # RTT大于500毫秒
   ```

3. **TCP拥塞控制分析**
   ```
   # 拥塞窗口减小
   tcp.analysis.congestion_window_decreased
   ```

4. **TCP选项分析**
   ```
   # 最大报文段大小
   tcp.options.mss_val
   
   # 选择性确认
   tcp.options.sack
   
   # 时间戳选项
   tcp.options.timestamp
   ```

5. **吞吐量分析**
   - 统计 > 会话 > TCP流图表 > 时序图
   - 显示吞吐量随时间的变化

### VoIP通信分析

Wireshark提供丰富的VoIP协议分析功能，对SIP、RTP、RTCP等协议提供全面支持。

#### SIP协议分析

1. **过滤SIP消息**
   ```
   # 所有SIP消息
   sip
   
   # SIP请求
   sip.Request-Line
   
   # SIP响应
   sip.Status-Line
   
   # 特定SIP方法
   sip.Method == "INVITE"
   ```

2. **SIP呼叫跟踪**
   ```
   # 跟踪特定呼叫
   sip.Call-ID == "a84b4c76e66710@192.168.1.1"
   
   # 跟踪特定用户的呼叫
   sip.from.user == "alice" or sip.to.user == "alice"
   ```

3. **SIP信令分析**
   ```
   # 呼叫建立失败
   sip.Status-Code >= 400
   
   # 注册失败
   sip.Method == "REGISTER" and sip.Status-Code >= 400
   ```

#### RTP媒体分析

1. **RTP流过滤**
   ```
   # 所有RTP流量
   rtp
   
   # 特定SSRC的RTP流
   rtp.ssrc == 0x3A12F65B
   ```

2. **提取与播放音频**
   - 电话 > VoIP通话
   - 找到感兴趣的呼叫后点击"播放"
   - 支持保存为WAV文件

3. **RTP流质量分析**
   ```
   # 检测丢包
   rtp.marker == 1
   
   # 序列号跳跃
   rtp.analysis.sequence_numbercase
   
   # 过大抖动
   rtp.analysis.jitter > 30
   ```

#### 高级VoIP故障排查

1. **呼叫质量问题**
   ```
   # RTP丢包统计
   rtp.analysis.lost_packet
   
   # MOS分数评估(通过插件)
   voip.analysis.mos < 3.5
   ```

2. **媒体与信令关联**
   - 电话 > VoIP通话 > 流分析
   - 查看端到端延迟和信令时间

3. **编解码器分析**
   ```
   # 识别所用编解码器
   rtp.p_type
   ```

4. **多方通话分析**
   - 使用流图显示通话各方之间的关系
   - 电话 > VoIP通话 > 流序列 > 流图

### 无线网络分析

Wireshark提供强大的无线网络(Wi-Fi)分析能力，但需要特定硬件支持。

#### 采集无线流量

1. **监听模式设置**
   - 需要支持监听模式的无线网卡
   - 在Linux上: `airmon-ng start wlan0`
   - 在macOS上通过内置工具支持
   - 在Windows上需要特殊驱动和AirPcap适配器

2. **捕获设置**
   - 设置捕获特定信道或频率
   - 添加dot11控制帧过滤器减少噪声

#### 802.11帧分析

1. **过滤特定帧类型**
   ```
   # 管理帧
   wlan.fc.type == 0
   
   # 控制帧
   wlan.fc.type == 1
   
   # 数据帧
   wlan.fc.type == 2
   ```

2. **信标帧分析**
   ```
   # 所有信标帧
   wlan.fc.type_subtype == 0x08
   
   # 特定SSID的信标
   wlan.fc.type_subtype == 0x08 and wlan.ssid == "MyNetwork"
   ```

3. **身份验证与关联分析**
   ```
   # 身份验证帧
   wlan.fc.type_subtype == 0x0B
   
   # 关联请求
   wlan.fc.type_subtype == 0x00
   
   # 关联响应
   wlan.fc.type_subtype == 0x01
   ```

#### 无线网络安全分析

1. **加密类型识别**
   ```
   # WEP加密
   wlan.wep.iv
   
   # WPA/WPA2
   wlan.rsn.akms
   
   # 开放网络
   wlan.fc.protected == 0 and wlan.fc.type == 2
   ```

2. **解密无线流量**
   - 首选项 > 协议 > IEEE 802.11
   - 添加解密密钥或密码短语
   - 设置相应的SSID关联

3. **无线攻击检测**
   ```
   # 解除认证帧洪水(DoS)
   wlan.fc.type_subtype == 0x0C
   
   # Evil Twin检测(同名SSID异常信标)
   wlan.fc.type_subtype == 0x08 and wlan.ssid == "CorporateWiFi"
   ```

#### 性能与覆盖分析

1. **信号强度分析**
   ```
   # 按信号强度过滤
   radiotap.dbm_antsignal > -60
   ```

2. **通道利用率分析**
   - 无线 > WLAN流量
   - 按通道与时间查看流量统计

3. **重传率分析**
   ```
   # 802.11重传分析
   wlan.fc.retry == 1
   ```

## 统计与可视化分析

Wireshark提供丰富的统计和可视化功能，有助于理解网络流量模式和性能特征。

### 流量统计图表

Wireshark提供多种流量可视化视图，帮助分析流量趋势和模式。

#### I/O图表

I/O图表显示流量随时间的变化趋势。

1. **访问I/O图表**
   - 统计 > I/O图表
   - 快捷键: Ctrl+I (Windows/Linux) 或 Cmd+I (macOS)

2. **自定义图表**
   - Y轴单位: 数据包/秒、字节/秒、比特/秒
   - 间隔设置: 1ms到1分钟
   - 多个图形叠加显示

3. **高级过滤应用**
   ```
   # 显示TCP流量时间分布
   tcp
   
   # 显示HTTP错误响应时间分布
   http.response.code >= 400
   
   # 比较上行/下行流量
   ip.src == 192.168.1.100  # 一条线
   ip.dst == 192.168.1.100  # 另一条线
   ```

#### 流图和时间序列图

1. **TCP流图**
   - 统计 > TCP流图 > 时序图
   - 显示TCP会话中的数据传输时序

2. **流量序列图**
   - 统计 > 流序列
   - 简化理解复杂协议交互

3. **往返时间图**
   - 统计 > TCP流图 > 往返时间图
   - 识别网络延迟异常

### 端点统计

端点统计提供网络中各设备的流量汇总信息。

#### 基本端点统计

1. **访问端点统计**
   - 统计 > 端点
   - 可按不同协议层查看(以太网、IPv4/v6、TCP、UDP等)

2. **端点过滤**
   - 使用显示过滤器预过滤端点
   - 端点列表中的列筛选功能

3. **端点信息排序**
   - 按流量大小排序
   - 按数据包数量排序
   - 按活动时长排序

#### 高级端点分析

1. **地理位置映射**
   - 需启用GeoIP数据库
   - 端点统计中的"地图"功能

2. **IP解析**
   - 启用名称解析
   - 将IP地址解析为主机名

3. **过滤端点流量**
   - 右键选择端点 > "将过滤器应用到选择项"
   - 快速分析特定主机流量

### 协议层级统计

协议层级统计展示网络流量中各协议的分布情况。

#### 访问协议层级统计

- 统计 > 协议层级统计
- 显示捕获中各协议占比

#### 协议层级分析

1. **识别主要协议**
   - 按数据包数量或字节数排序
   - 确定网络主要应用

2. **异常检测**
   - 识别不应出现的协议
   - 检测异常流量占比

3. **按时间分段分析**
   - 捕获 > 自动停止 > 间隔停止
   - 比较不同时间段的协议分布

### 服务响应时间

分析各种网络服务的响应时间可以帮助定位性能瓶颈。

#### 基本响应时间分析

1. **HTTP响应时间**
   - 统计 > 服务响应时间 > HTTP
   - 分析请求-响应延迟

2. **DNS响应时间**
   - 统计 > 服务响应时间 > DNS
   - 分析域名解析延迟

3. **TCP连接建立时间**
   ```
   # 过滤TCP握手
   tcp.flags.syn == 1
   
   # 连接建立时间统计
   tcp.time_delta > 0.1
   ```

#### 高级响应时间分析

1. **导出响应时间数据**
   - 导出为CSV格式
   - 使用外部工具进一步分析

2. **创建自定义响应时间图表**
   - 统计 > I/O图表
   - Y轴: 高级设置中使用时间字段

3. **按目标服务器分组**
   - 按IP或主机名分组响应时间
   - 识别性能不佳的服务器

### 自定义统计报告

Wireshark允许创建自定义统计报告，满足特定分析需求。

#### Lua脚本定制统计

1. **安装Lua插件**
   - 帮助 > 关于Wireshark > 文件夹 > 个人Lua插件
   - 添加自定义.lua脚本

2. **编写基本统计脚本**
   ```lua
   -- 基本计数器示例
   local my_tap = register_tap("frame")
   local counter = 0
   
   function remove()
       counter = 0
   end
   
   function packet(pinfo, tvb, tapdata)
       counter = counter + 1
   end
   
   function draw()
       print("总数据包数: " .. counter)
   end
   ```

3. **高级统计功能**
   - 时间序列数据收集
   - 协议字段分析
   - 复杂关联分析

#### 使用tshark生成报告

1. **基本统计提取**
   ```bash
   # 提取协议分布
   tshark -r capture.pcap -qz io,stat,30
   
   # 提取HTTP响应码分布
   tshark -r capture.pcap -T fields -e http.response.code | sort | uniq -c
   ```

2. **自定义字段统计**
   ```bash
   # 提取TCP重传率
   tshark -r capture.pcap -T fields -e frame.number -e tcp.analysis.retransmission
   ```

3. **输出格式化**
   ```bash
   # JSON格式输出
   tshark -r capture.pcap -T json -e ip.src -e ip.dst -e frame.time
   
   # CSV格式输出
   tshark -r capture.pcap -T fields -e frame.time -e ip.src -e ip.dst -E header=y -E separator=, > output.csv
   ```

## 性能优化

### 大型捕获文件处理

处理大型捕获文件(几GB或更大)需要特殊技巧以维持Wireshark性能。

#### 优化捕获文件加载

1. **文件分段**
   ```bash
   # 使用editcap分割大文件
   editcap -c 1000000 large_capture.pcapng split_file.pcapng
   # 每100万个数据包生成一个新文件
   ```

2. **建立索引**
   - 首选项 > 名称解析 > 最大未解析地址
   - 减少文件加载时的名称解析

3. **限制协议解析**
   - 首选项 > 协议
   - 禁用不需要的协议解析器

#### 内存管理技术

1. **增加内存限制**
   - 首选项 > 高级 > 内存行为
   - 调整"而提前显示数据包的最大数量"

2. **使用临时文件**
   - 捕获 > 选项 > 输出
   - "使用环形缓冲区"选项

3. **64位Wireshark**
   - 使用64位版本处理大文件
   - 为Wireshark分配足够物理内存

### 资源使用优化

优化Wireshark的CPU和内存使用以提高性能。

#### CPU优化

1. **减少实时显示**
   - 捕获时不自动滚动
   - 捕获 > 选项 > "更新数据包列表"取消勾选

2. **减少解析深度**
   - 首选项 > 协议 > 设置最大显示深度
   - 禁用不需要的协议解析

3. **使用捕获过滤器**
   - 优先使用捕获过滤器而非显示过滤器
   - 减少需要处理的数据包数量

#### 内存使用优化

1. **控制数据包缓冲**
   - 捕获 > 选项 > "显示选项"选项卡
   - 设置合理的缓冲区大小

2. **定期保存捕获**
   - 启用自动保存功能
   - 捕获 > 选项 > 输出 > "创建新文件"选项

3. **使用命令行工具预处理**
   ```bash
   # 提取感兴趣流量
   tshark -r large_file.pcapng -w filtered.pcapng -Y "http"
   
   # 在Wireshark中打开处理后的文件
   wireshark filtered.pcapng
   ```

### 多文件分析

有时需要同时分析多个捕获文件，Wireshark提供几种方法。

#### 文件合并

1. **使用GUI合并**
   - 文件 > 合并
   - 选择要合并的文件和排序方法

2. **使用命令行合并**
   ```bash
   # 合并多个捕获文件
   mergecap -w merged.pcapng file1.pcapng file2.pcapng file3.pcapng
   
   # 按时间戳排序
   mergecap -w merged.pcapng -a file1.pcapng file2.pcapng
   ```

#### 比较捕获文件

1. **使用mergecap和标记**
   ```bash
   # 为不同文件添加不同标记
   editcap -a "file1" capture1.pcapng marked1.pcapng
   editcap -a "file2" capture2.pcapng marked2.pcapng
   
   # 合并并使用标记区分
   mergecap -w merged.pcapng marked1.pcapng marked2.pcapng
   
   # 在Wireshark中创建新列显示标记
   ```

2. **使用比较器功能**
   - 工具 > 比较器
   - 支持二进制、文本和协议比较

## 集成外部工具

### GeoIP映射

集成GeoIP数据库可以将IP地址映射到地理位置。

#### 安装GeoIP数据库

1. **下载MaxMind GeoLite2数据库**
   - 访问MaxMind网站注册免费账户
   - 下载GeoLite2 City和Country数据库

2. **配置Wireshark**
   - 首选项 > 名称解析 > GeoIP数据库目录
   - 设置为MaxMind数据库位置

3. **应用地理信息**
   - 统计 > 端点 > IPv4 > 地图
   - 在统计列表中添加Country和City列

#### 使用地理信息分析

1. **按国家过滤流量**
   ```
   # 过滤特定国家流量
   ip.geoip.country == "China"
   
   # 排除特定国家流量
   !(ip.geoip.country == "United States")
   ```

2. **创建地理流量图**
   - 使用第三方可视化工具
   - 从Wireshark导出地理数据

### 外部解析器

Wireshark支持与外部协议解析器集成，扩展其协议支持能力。

#### 配置外部解析器

1. **集成Transum性能分析器**
   - 下载Transum插件
   - 安装到Wireshark插件文件夹

2. **集成协议解码器**
   ```bash
   # 设置外部协议解析器
   export WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1
   export WIRESHARK_EXTCAP_DIR=/path/to/extcap
   ```

3. **构建自定义解析器**
   - 使用Wireshark API
   - 为专有协议创建解析插件

### 命令行工具链接

Wireshark生态系统包含多个命令行工具，可以集成到自动化工作流程中。

#### tshark高级应用

1. **自动化捕获**
   ```bash
   # 定时捕获
   tshark -i eth0 -w capture-%Y%m%d-%H%M%S.pcapng -b duration:3600
   
   # 条件触发捕获
   tshark -i eth0 -w triggered.pcapng -c 1000 -f "tcp port 80 and host 192.168.1.1"
   ```

2. **高级过滤**
   ```bash
   # 复杂条件过滤
   tshark -r capture.pcapng -Y "(http.request or http.response) and ip.addr==10.0.0.1" -w filtered.pcapng
   ```

3. **提取字段**
   ```bash
   # 提取特定字段
   tshark -r capture.pcapng -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e http.request.method -e http.request.uri
   
   # 格式化输出
   tshark -r capture.pcapng -T ek > elastic_output.json  # Elasticsearch格式
   ```

#### 与脚本集成

1. **通过Python调用**
   ```python
   import subprocess
   
   # 调用tshark并获取输出
   output = subprocess.check_output([
       'tshark', '-r', 'capture.pcapng', 
       '-T', 'fields', '-e', 'ip.src'
   ]).decode('utf-8')
   
   # 处理输出
   ip_list = output.strip().split('\n')
   ```

2. **shell脚本自动化**
   ```bash
   #!/bin/bash
   
   # 自动捕获和分析
   for i in {1..24}; do
     tshark -i eth0 -w capture-$i.pcapng -a duration:3600
     tshark -r capture-$i.pcapng -q -z io,stat,300 > stats-$i.txt
   done
   ```

3. **集成监控系统**
   - 提取关键指标到Prometheus/Grafana
   - 发送警报到Nagios/Zabbix