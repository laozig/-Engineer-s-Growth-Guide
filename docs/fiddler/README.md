# Fiddler 网络调试代理

<div align="center">
  <img src="../../assets/fiddler-logo.png" alt="Fiddler Logo" width="200">
</div>

> Fiddler是一款强大的网络调试代理工具，专注于HTTP/HTTPS流量的捕获、检查和调试，是Web开发、测试和安全分析的利器。

## 目录

- [简介](#简介)
- [安装与配置](#安装与配置)
- [基本功能](#基本功能)
- [高级功能](#高级功能)
- [Fiddler扩展](#fiddler扩展)
- [移动设备调试](#移动设备调试)
- [自动化和脚本](#自动化和脚本)
- [最佳实践](#最佳实践)
- [常见问题](#常见问题)
- [参考资源](#参考资源)

## 简介

Fiddler是一款HTTP调试代理工具，它能够记录计算机和互联网之间的所有HTTP/HTTPS流量，让您检查、分析、修改请求和响应。作为中间人，Fiddler可以拦截、检查、修改和重放Web流量，极大地简化了Web应用程序的故障排除和调试过程。

### 主要特点

- **HTTP(S)流量捕获** - 记录客户端和服务器之间的所有HTTP/HTTPS通信
- **实时流量检查** - 查看请求/响应头和内容
- **流量修改** - 篡改请求和响应内容
- **断点功能** - 在请求发送前或接收响应前暂停和修改
- **自动响应** - 根据规则自动返回预定义的响应
- **性能分析** - 网络延迟和性能统计
- **移动设备支持** - 捕获iOS和Android设备的流量
- **可扩展性** - 通过FiddlerScript或.NET扩展增强功能

### 适用场景

- **Web开发** - API调试，解决Ajax请求问题
- **网络测试** - 验证请求/响应格式，模拟不同网络环境
- **安全分析** - 检查Web应用安全性，查找潜在漏洞
- **性能评估** - 分析网站加载性能，优化请求
- **移动应用调试** - 拦截和分析移动应用的网络流量
- **反向工程** - 研究Web API和服务

## 安装与配置

### 系统需求

- **Windows**：Windows 7/8/10/11
- **.NET Framework**：.NET Framework 4.6或更高版本
- **磁盘空间**：至少50MB可用空间
- **权限**：管理员权限（用于证书安装）

### 下载安装

1. 访问[官方网站](https://www.telerik.com/fiddler)下载最新版Fiddler
2. 运行安装程序并按照向导完成安装
3. 首次运行时，配置HTTPS解密和信任证书

```powershell
# Windows可以使用Chocolatey安装
choco install fiddler
```

### 初始设置

#### HTTPS配置

1. 打开Fiddler
2. 点击 **Tools > Options > HTTPS**
3. 勾选 **Decrypt HTTPS Traffic**
4. 点击 **Actions > Trust Root Certificate**
5. 确认安装Fiddler的根证书

#### 基本配置选项

1. **General** - 启动选项和界面选择
2. **HTTPS** - HTTPS解密设置
3. **Gateway** - 上游代理设置
4. **Connections** - 端口和允许远程连接选项
5. **Appearance** - 界面外观定制

## 基本功能

### 界面布局

Fiddler的界面分为几个主要部分：

1. **会话列表** - 显示已捕获的HTTP(S)会话
2. **标签式检查器** - 查看会话详情的多个标签
3. **状态栏** - 显示捕获状态和统计信息
4. **工具栏** - 常用功能按钮
5. **过滤器工具** - 用于筛选会话列表

### 捕获HTTP流量

1. **开始/停止捕获**：按F12或点击右下角的Capturing按钮
2. **清除会话列表**：按Ctrl+X或点击工具栏中的X按钮
3. **保存会话**：File > Save > Sessions

### 会话分析

1. **检查请求/响应头**：点击会话，查看右侧标签中的Headers
2. **查看请求/响应内容**：点击WebForms、JSON或Raw等标签
3. **查看时间线**：Timeline标签显示请求时间线和耗时
4. **性能统计**：Statistics标签显示性能数据

### 过滤会话

1. **使用过滤器栏**：在顶部的过滤器栏输入条件
    - `host:example.com` - 只显示特定主机
    - `status:404` - 只显示特定状态码
    - `mime:image` - 只显示特定MIME类型

2. **使用QuickFilters**：点击工具栏上的Filters按钮
    - 按主机过滤
    - 按内容类型过滤
    - 按状态码过滤

## 高级功能

### 流量篡改

#### 请求断点

1. 点击Rules > Automatic Breakpoints > Before Requests
2. 发送请求时会暂停，让您编辑请求头和内容
3. 点击Run to Completion继续

#### 响应断点

1. 点击Rules > Automatic Breakpoints > Before Responses
2. 接收响应时会暂停，让您编辑响应头和内容
3. 点击Run to Completion继续

#### 自定义规则

1. 右键点击会话
2. 选择Break on XXX选项为特定条件设置断点

### AutoResponder功能

AutoResponder允许您为特定请求提供本地或自定义响应：

1. 切换到AutoResponder标签
2. 启用Enable rules和Unmatched requests passthrough
3. 添加规则：
   - 将会话从左侧拖到规则列表
   - 点击Add Rule手动添加
4. 设置匹配模式和响应操作
   - 返回本地文件
   - 返回自定义字符串
   - 重定向到其他URL
   - 返回特定HTTP状态码

### 流量比较

1. 按住Ctrl键选择多个会话
2. 右键点击，选择Compare
3. 比较请求或响应之间的差异

### 性能分析

使用Statistics面板分析性能：

1. 点击Statistics标签
2. 查看会话的时间分布
3. 分析DNS解析、连接建立、TTFB等指标
4. 生成HAR格式性能报告

## Fiddler扩展

### 常用插件

1. **FiddlerCap** - 简化的Fiddler版本，用于非技术人员捕获流量
2. **CertMaker** - 改进的证书生成器
3. **Request to Code** - 将HTTP请求转换为代码
4. **Inspector2** - 增强的检查器界面

### 安装扩展

1. 下载扩展的DLL文件
2. 将DLL复制到Fiddler的Scripts文件夹
3. 重启Fiddler

### 开发自定义扩展

1. 使用C#创建Fiddler扩展
2. 实现IFiddlerExtension接口
3. 编译为DLL并放入Scripts文件夹

## 移动设备调试

### iOS设备配置

1. 在Fiddler中：
   - Tools > Options > Connections
   - 勾选Allow remote computers to connect
   - 重启Fiddler

2. 在iOS设备上：
   - 设置 > Wi-Fi > 选择当前网络
   - 配置代理 > 手动
   - 输入计算机IP和端口(默认8888)
   - 访问http://ipv4.fiddler:8888下载并安装证书

### Android设备配置

1. 在Fiddler中设置允许远程连接（同上）

2. 在Android设备上：
   - 设置 > Wi-Fi > 长按当前网络
   - 修改网络 > 高级选项
   - 代理 > 手动
   - 输入主机名和端口
   - 访问http://ipv4.fiddler:8888下载并安装证书

### 模拟器调试

- **iOS模拟器**：自动配置为使用主机代理
- **Android模拟器**：
  ```
  emulator -avd [avd_name] -http-proxy http://127.0.0.1:8888
  ```

## 自动化和脚本

### FiddlerScript基础

Fiddler使用JScript.NET脚本语言进行自动化：

1. 打开Rules > Customize Rules
2. 编辑脚本以添加自定义功能
3. 保存脚本，Fiddler会自动重新加载

### 常用脚本示例

```javascript
// 标记慢速响应
if (oSession.TimeTaken > 500) {
    oSession["ui-color"] = "red";
}

// 修改请求头
oSession.oRequest["User-Agent"] = "Custom User Agent";

// 阻止特定资源加载
if (oSession.uriContains(".ads.")) {
    oSession["ui-color"] = "magenta";
    oSession.oRequest.FailSession(404, "Blocked", "Advertising blocked");
}
```

### 自动化测试集成

1. **命令行使用**：
   ```
   fiddler.exe -port 8877 -urlecm http://example.com
   ```

2. **与测试框架集成**：
   - 使用FiddlerCore库
   - 在自动化测试中编程控制捕获和分析

## 最佳实践

### 高效使用技巧

1. **使用快捷键**：
   - F12: 开始/停止捕获
   - Ctrl+X: 清除所有会话
   - F9: 重新发送请求
   - Alt+Q: 快速筛选

2. **保存常用过滤器**：创建和保存经常使用的过滤设置

3. **使用会话标记**：使用不同颜色标记重要会话

### 性能优化

1. **限制捕获大小**：
   - Rules > Performance > Disable Caching
   - Rules > Performance > Ignore Server Caching

2. **定期清除会话列表**：避免内存占用过大

3. **选择性捕获**：使用过滤器减少不必要的会话捕获

## 常见问题

### 无法捕获HTTPS流量

- 确保已安装和信任Fiddler证书
- 检查HTTPS解密选项是否启用
- 尝试重新安装证书：Tools > Options > HTTPS > Actions > Reset Certificates

### 性能问题

- 减少捕获的会话数量
- 禁用不必要的检查器
- 定期清除会话列表
- 检查是否有资源消耗大的扩展

### 远程设备连接问题

- 确认计算机和设备在同一网络
- 检查防火墙是否阻止8888端口
- 确认已启用"Allow remote computers to connect"
- 尝试禁用系统代理设置

## 参考资源

### 官方文档

- [Fiddler官网](https://www.telerik.com/fiddler)
- [Fiddler文档](https://docs.telerik.com/fiddler/configure-fiddler/tasks/configurefiddler)
- [FiddlerScript参考](https://docs.telerik.com/fiddler/knowledge-base/fiddlerscript/modifyrequestorresponse)

### 学习资源

- [Fiddler教程](https://www.telerik.com/videos/fiddler)
- [FiddlerCap指南](https://docs.telerik.com/fiddler/Configure-Fiddler/Tasks/UseFiddlerCap)

### 社区支持

- [Fiddler论坛](https://community.telerik.com/forums/fiddler)
- [Stack Overflow上的Fiddler话题](https://stackoverflow.com/questions/tagged/fiddler) 