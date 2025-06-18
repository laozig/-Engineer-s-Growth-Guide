# Frida 示例代码

本目录包含了Frida的各种实用示例代码，适用于不同场景和平台。这些示例旨在帮助您快速上手和理解如何在实际项目中使用Frida。

## 示例列表

### 基础示例

- [hello-world.js](hello-world.js) - 最基本的Frida脚本示例
- [module-enumeration.js](module-enumeration.js) - 演示如何枚举和分析模块
- [function-hooking.js](function-hooking.js) - 基本的函数Hook示例

### Android平台

- [android-basic.js](android/basic.js) - Android平台的基础Hook示例
- [android-ssl-pinning.js](android/ssl-pinning.js) - 绕过Android SSL证书固定
- [android-root-detection.js](android/root-detection.js) - 绕过root检测
- [android-ui-interaction.js](android/ui-interaction.js) - 与Android UI元素交互

### iOS平台

- [ios-basic.js](ios/basic.js) - iOS平台的基础Hook示例
- [ios-jailbreak-detection.js](ios/jailbreak-detection.js) - 绕过越狱检测
- [ios-keychain-access.js](ios/keychain-access.js) - 监控和操作钥匙链
- [ios-method-swizzling.js](ios/method-swizzling.js) - 方法替换示例

### Windows平台

- [windows-api-hooking.js](windows/api-hooking.js) - Windows API Hook示例
- [windows-com-objects.js](windows/com-objects.js) - COM对象操作示例
- [windows-dll-injection.js](windows/dll-injection.js) - DLL注入相关示例

### 高级技术

- [memory-scanning.js](advanced/memory-scanning.js) - 内存扫描和修改示例
- [stalker-tracing.js](advanced/stalker-tracing.js) - 使用Stalker进行执行流程跟踪
- [native-callbacks.js](advanced/native-callbacks.js) - 创建和使用本地回调
- [code-instrumentation.js](advanced/code-instrumentation.js) - 代码插桩技术
- [remote-debugging.js](advanced/remote-debugging.js) - 远程调试技术

### 实用工具

- [crypto-monitor.js](utils/crypto-monitor.js) - 监控加密操作
- [network-monitor.js](utils/network-monitor.js) - 网络流量监控
- [logger.js](utils/logger.js) - 通用日志工具
- [persistence.js](utils/persistence.js) - 持久化Hook示例

## 使用方法

大多数脚本可以通过以下方式运行：

```bash
# 使用USB设备
frida -U -l script.js target_app

# 或者使用设备ID
frida -D <device_id> -l script.js target_app

# 或者使用进程名/PID
frida -F -l script.js process_name_or_pid
```

每个脚本文件顶部都有详细的使用说明注释。

## 贡献指南

如果您想贡献您自己的示例：

1. 确保您的脚本开头有清晰的注释，说明：
   - 脚本的用途
   - 使用方法
   - 适用平台和环境
   - 必要的权限和前提条件

2. 遵循本项目的代码风格:
   - 使用清晰的变量和函数名
   - 添加足够的注释
   - 处理可能的错误情况

3. 提交拉取请求，我们将审核并合并有价值的示例

## 免责声明

这些示例仅供学习和研究目的。请遵守相关法律法规，不要用于任何非法活动。使用这些脚本可能违反应用程序的使用条款，请自行承担风险。 