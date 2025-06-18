# Frida 快速入门指南

本文档旨在帮助您快速上手使用Frida工具，提供基础知识和入门级示例。

## 目录

- [Frida 基本概念](#frida-基本概念)
- [第一个Frida脚本](#第一个frida脚本)
- [使用Frida CLI工具](#使用frida-cli工具)
- [Frida与Python结合](#frida与python结合)
- [常见应用场景](#常见应用场景)

## Frida 基本概念

Frida是一个动态代码插桩工具包，允许您将自定义代码注入到正在运行的应用程序中。以下是一些关键概念：

- **代码插桩**：在不修改原始源代码的情况下，动态修改或监控应用程序的行为
- **JavaScript引擎**：Frida使用JavaScript作为脚本语言，通过V8引擎执行
- **Hook**：拦截函数调用，修改参数、返回值或完全替换实现
- **Stalker**：跟踪程序执行流程，分析代码覆盖率等
- **Frida-server**：运行在目标设备上的守护进程，负责执行Frida操作
- **Frida-tools**：在主机上运行的CLI工具集，用于控制操作

## 第一个Frida脚本

让我们从一个简单的例子开始，创建一个基本的Frida脚本来Hook一个Android应用中的函数：

1. 创建一个名为`hello.js`的文件，内容如下：

```javascript
console.log("[*] Frida脚本已加载");

// 当Java环境准备就绪后执行
Java.perform(function() {
    console.log("[*] Java环境已准备就绪");
    
    // 查找目标类
    var MainActivity = Java.use("com.example.app.MainActivity");
    
    // Hook目标方法
    MainActivity.isUserLoggedIn.implementation = function() {
        console.log("[*] isUserLoggedIn方法被调用");
        
        // 打印原始返回值
        var originalReturn = this.isUserLoggedIn();
        console.log("[*] 原始返回值: " + originalReturn);
        
        // 修改返回值为true，绕过登录检查
        console.log("[*] 修改返回值为: true");
        return true;
    };
    
    console.log("[*] Hook设置完成");
});
```

2. 使用以下命令运行脚本（假设应用包名为com.example.app）：

```bash
frida -U -l hello.js com.example.app
```

## 使用Frida CLI工具

Frida提供了几个CLI工具，以下是常用的几个：

### frida-ps

列出正在运行的进程：

```bash
# 列出本地进程
frida-ps

# 列出USB连接设备上的进程
frida-ps -U

# 列出远程设备上的进程
frida-ps -H 192.168.1.100
```

### frida-trace

快速跟踪函数调用：

```bash
# 跟踪libc的open函数
frida-trace -i "open" process_name

# 跟踪多个函数
frida-trace -i "open" -i "close" process_name

# 跟踪Java方法
frida-trace -U -f com.example.app -m "*Activity.onCreate*"
```

### frida-discover

发现可能感兴趣的函数：

```bash
frida-discover -U com.example.app
```

### frida-ls-devices

列出连接的设备：

```bash
frida-ls-devices
```

## Frida与Python结合

Frida提供Python绑定，可以在Python脚本中使用Frida API进行更复杂的操作：

```python
import frida
import sys

# JavaScript代码
jscode = """
Java.perform(function () {
    var MainActivity = Java.use('com.example.app.MainActivity');
    MainActivity.isUserLoggedIn.implementation = function () {
        console.log('[*] isUserLoggedIn方法被调用');
        return true;
    };
});
"""

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] 收到消息: %s" % message['payload'])
    elif message['type'] == 'error':
        print("[!] 发生错误: %s" % message['stack'])

# 连接到USB设备
device = frida.get_usb_device()

# 附加到目标进程（按包名）
process = device.get_process("com.example.app")
session = device.attach(process.pid)

# 创建脚本并加载
script = session.create_script(jscode)
script.on('message', on_message)
script.load()

# 等待用户中断
sys.stdin.read()
```

## 常见应用场景

### 绕过证书固定

```javascript
Java.perform(function() {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    
    // 创建一个自定义TrustManager
    var TrustManager = Java.registerClass({
        name: 'com.example.FridaTrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() {
                return [];
            }
        }
    });
    
    // 替换默认的SSLContext
    var SSLContext_init = SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;', 
        '[Ljavax.net.ssl.TrustManager;', 
        'java.security.SecureRandom'
    );
    
    SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
        var trustManagers = Java.array('javax.net.ssl.TrustManager', [TrustManager.$new()]);
        SSLContext_init.call(this, keyManager, trustManagers, secureRandom);
    };
    
    console.log('[+] 证书固定已绕过');
});
```

### 提取加密密钥

```javascript
Java.perform(function() {
    var secretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    secretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(keyBytes, algorithm) {
        console.log('[+] 捕获到加密密钥:');
        console.log('算法: ' + algorithm);
        console.log('密钥: ' + Java.use('java.util.Arrays').toString(keyBytes));
        return this.$init(keyBytes, algorithm);
    };
});
```

### 修改应用行为

```javascript
Java.perform(function() {
    var BuildConfig = Java.use('com.example.app.BuildConfig');
    
    // 修改布尔常量
    BuildConfig.DEBUG.value = true;
    
    // 修改字符串常量
    BuildConfig.API_ENDPOINT.value = "https://test-api.example.com";
    
    console.log('[+] 应用配置已修改');
});
```

## 后续学习

一旦您熟悉了基本概念，可以参考以下资源进行深入学习：

- [基本使用](basic-usage.md) - 更详细的使用说明
- [高级功能](advanced-features.md) - 高级Frida功能探索
- [API参考](api-reference.md) - 完整的API文档
- [示例代码](../examples/) - 各种场景的实用示例

---

现在您已经了解了Frida的基本使用方法，可以开始探索更多高级功能和应用场景了！ 