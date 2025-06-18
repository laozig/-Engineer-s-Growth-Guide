# Frida 基本使用指南

本文档详细介绍了Frida工具的基本使用方法，包括核心概念、常用API以及实用示例。

## 目录

- [基础架构](#基础架构)
- [附加到进程](#附加到进程)
- [JavaScript API](#javascript-api)
- [Hook 函数](#hook-函数)
- [拦截和修改函数](#拦截和修改函数)
- [内存操作](#内存操作)
- [RPC导出](#rpc导出)

## 基础架构

Frida的工作原理基于客户端-服务器模型：

1. **frida-server**：运行在目标设备上（如Android、iOS设备）
2. **frida-client**：运行在您的计算机上
3. **注入器**：负责将JavaScript代码动态注入到目标进程
4. **运行时**：运行在目标进程中，执行您的JavaScript代码

通常情况下，工作流程如下：

1. 在目标设备上启动frida-server
2. 使用Frida客户端工具（Python、CLI等）附加到目标进程
3. 注入并执行JavaScript代码
4. 通过双向通信获取结果

## 附加到进程

### 通过进程名称或ID附加

使用CLI工具附加到进程：

```bash
# 通过名称附加
frida Notepad

# 通过ID附加
frida 1234
```

使用Python API附加：

```python
import frida

# 通过名称附加
session = frida.attach("Notepad")

# 通过ID附加
session = frida.attach(1234)
```

### 产生并附加到进程

如果您想启动一个新进程并立即附加，可以使用：

```bash
# CLI方式
frida -f com.example.app --no-pause

# 添加-U参数连接USB设备
frida -U -f com.example.app --no-pause
```

Python代码：

```python
import frida

# 本地应用
pid = frida.spawn("calc.exe")
session = frida.attach(pid)
frida.resume(pid)

# 通过USB连接的设备
device = frida.get_usb_device()
pid = device.spawn(["com.example.app"])
session = device.attach(pid)
device.resume(pid)
```

## JavaScript API

Frida JavaScript API是您编写注入脚本的主要工具。以下是一些核心模块：

### Process 模块

访问进程相关信息：

```javascript
// 获取进程架构
console.log("进程架构: " + Process.arch);

// 获取当前线程ID
console.log("当前线程ID: " + Process.getCurrentThreadId());

// 枚举所有模块
Process.enumerateModules().forEach(function(module) {
    console.log("模块名: " + module.name + ", 基地址: " + module.base);
});
```

### Module 模块

操作加载的模块（DLL/SO文件）：

```javascript
// 获取模块信息
var mainModule = Process.getModuleByName("example.dll");
console.log("模块基地址: " + mainModule.base);
console.log("模块大小: " + mainModule.size);
console.log("模块路径: " + mainModule.path);

// 查找导出函数
var exportedFunctions = mainModule.enumerateExports();
exportedFunctions.forEach(function(exp) {
    console.log("导出函数: " + exp.name + " at " + exp.address);
});

// 查找符号
var symbols = mainModule.enumerateSymbols();
symbols.forEach(function(sym) {
    console.log("符号: " + sym.name + " at " + sym.address);
});
```

### Memory 模块

操作进程内存：

```javascript
// 分配内存
var pointer = Memory.alloc(1024);
console.log("分配的内存地址: " + pointer);

// 写入内存
Memory.writeByteArray(pointer, [0x13, 0x37, 0x42]);

// 读取内存
var bytes = Memory.readByteArray(pointer, 3);
console.log("读取的字节: " + bytes);

// 保护内存
Memory.protect(pointer, 1024, "rwx");

// 扫描内存
Memory.scan(ptr("0x10000000"), 0x10000000, "12 34 ?? 78", {
    onMatch: function(address, size) {
        console.log("找到匹配: " + address);
    },
    onComplete: function() {
        console.log("扫描完成");
    }
});
```

## Hook 函数

### Native函数Hook

Hook C/C++函数：

```javascript
// 通过模块和函数名获取函数
var openPtr = Module.getExportByName("libc.so", "open");
console.log("open函数地址: " + openPtr);

// 使用Interceptor Hook函数
Interceptor.attach(openPtr, {
    onEnter: function(args) {
        // 在函数进入时执行
        this.filePath = args[0].readUtf8String();
        this.flags = args[1].toInt32();
        console.log("正在打开文件: " + this.filePath);
    },
    onLeave: function(retval) {
        // 在函数返回时执行
        console.log("打开文件结果: " + retval);
        
        // 可以修改返回值
        if (this.filePath.indexOf("private") >= 0) {
            console.log("拦截对私有文件的访问");
            retval.replace(-1); // 返回错误代码
        }
    }
});
```

### Java方法Hook（Android）

Hook Java方法：

```javascript
// 需要在Java.perform中执行
Java.perform(function() {
    // 获取类引用
    var Activity = Java.use("android.app.Activity");
    
    // Hook方法
    Activity.onCreate.overload("android.os.Bundle").implementation = function(bundle) {
        console.log("Activity.onCreate被调用");
        
        // 调用原始方法
        this.onCreate(bundle);
        
        // 访问Java对象字段
        console.log("Activity title: " + this.getTitle());
    };
    
    // 查找类中的所有方法
    var methods = Activity.class.getDeclaredMethods();
    methods.forEach(function(method) {
        console.log("方法: " + method.toString());
    });
    
    // 获取当前Activity实例
    Java.choose("android.app.Activity", {
        onMatch: function(instance) {
            console.log("找到Activity实例: " + instance);
            console.log("其标题为: " + instance.getTitle());
        },
        onComplete: function() {
            console.log("实例搜索完成");
        }
    });
});
```

### Objective-C方法Hook（iOS）

Hook Objective-C方法：

```javascript
// 需要在ObjC.available判断后执行
if (ObjC.available) {
    // 获取类引用
    var UIAlertView = ObjC.classes.UIAlertView;
    
    // Hook方法
    Interceptor.attach(UIAlertView["- initWithTitle:message:delegate:cancelButtonTitle:otherButtonTitles:"].implementation, {
        onEnter: function(args) {
            // args[0]是self
            // args[1]是selector
            // args[2]开始是实际参数
            
            var title = ObjC.Object(args[2]).toString();
            var message = ObjC.Object(args[3]).toString();
            
            console.log("UIAlertView标题: " + title);
            console.log("UIAlertView消息: " + message);
            
            // 修改参数
            args[2] = ObjC.classes.NSString.stringWithString_("修改后的标题");
        }
    });
    
    // 查找所有UIAlertView实例
    ObjC.choose(ObjC.classes.UIAlertView, {
        onMatch: function(instance) {
            console.log("找到UIAlertView实例: " + instance);
            console.log("其标题为: " + instance.title());
        },
        onComplete: function() {
            console.log("实例搜索完成");
        }
    });
}
```

## 拦截和修改函数

### 替换函数实现

使用`NativeFunction`创建替代函数：

```javascript
// 原始函数的地址
var openPtr = Module.getExportByName("libc.so", "open");

// 创建一个新的本地函数
var originalOpen = new NativeFunction(openPtr, 'int', ['pointer', 'int']);

// 替换原始实现
Interceptor.replace(openPtr, new NativeCallback(function(pathPtr, flags) {
    var path = pathPtr.readUtf8String();
    console.log("拦截到open调用: " + path);
    
    if (path.indexOf("sensitive") >= 0) {
        console.log("阻止访问敏感文件");
        return -1;
    }
    
    // 调用原始函数
    return originalOpen(pathPtr, flags);
}, 'int', ['pointer', 'int']));
```

### 在特定地址注入代码

在任意内存地址注入代码：

```javascript
// 在特定地址处Hook
var targetAddr = ptr("0x12345678");

Interceptor.attach(targetAddr, {
    onEnter: function(args) {
        console.log("执行到指定地址");
        console.log("寄存器状态:");
        console.log("R0: " + this.context.r0);
        console.log("R1: " + this.context.r1);
        
        // 可以修改寄存器状态
        this.context.r0 = ptr("0x1000");
    }
});
```

## 内存操作

### 内存扫描和修补

扫描并修改内存中的特定模式：

```javascript
// 在主模块中查找特定字节模式
var pattern = "11 22 ?? 44";

Memory.scan(Process.getModuleByName("target.exe").base, 
    Process.getModuleByName("target.exe").size, 
    pattern, {
        onMatch: function(address, size) {
            console.log("找到匹配: " + address);
            
            // 修改内存
            Memory.patchCode(address, 4, function(code) {
                var writer = new X86Writer(code, { pc: address });
                writer.putNop();
                writer.putNop();
                writer.putNop();
                writer.putNop();
                writer.flush();
            });
            
            console.log("内存已修补");
        },
        onComplete: function() {
            console.log("扫描完成");
        }
    }
);
```

### 内存转储

将特定区域的内存保存到文件：

```javascript
// 导出内存区域到文件
var targetModule = Process.getModuleByName("target.dll");
var memoryData = Memory.readByteArray(targetModule.base, targetModule.size);

// 使用rpc导出数据到文件
send({
    type: "memory-dump",
    name: "target.dll.bin",
    data: memoryData
});

// 在Python端接收和保存
"""
def on_message(message, data):
    if message["payload"]["type"] == "memory-dump":
        with open(message["payload"]["name"], "wb") as f:
            f.write(data)
        print("内存已转储到文件: " + message["payload"]["name"])
"""
```

## RPC导出

Frida允许您从JavaScript导出函数到主机端，使得主机程序可以调用目标进程中的函数：

```javascript
// JavaScript端导出函数
rpc.exports = {
    // 导出一个函数来获取进程内存信息
    getMemoryInfo: function() {
        var result = {};
        Process.enumerateRanges('r--').forEach(function(range) {
            result[range.base] = range.size;
        });
        return result;
    },
    
    // 调用特定函数并返回结果
    callTargetFunction: function(arg1, arg2) {
        var targetFunction = new NativeFunction(
            Module.getExportByName('target.dll', 'TargetFunction'),
            'int', ['int', 'int']
        );
        
        return targetFunction(arg1, arg2);
    }
};

// 在Python端调用这些函数
"""
# 加载脚本
script = session.create_script(jscode)
script.load()

# 调用导出的函数
memory_info = script.exports.get_memory_info()
print(memory_info)

result = script.exports.call_target_function(10, 20)
print("函数返回结果:", result)
"""
```

## 实用技巧

### 持久化Hook

您可以创建一个加载器脚本，使Hook在目标应用重启后仍然有效：

```javascript
// 持久化加载器
function loadPersistentAgent() {
    Java.perform(function() {
        // 在应用初始化时Hook
        var ActivityThread = Java.use('android.app.ActivityThread');
        ActivityThread.systemMain.implementation = function() {
            var result = this.systemMain();
            
            // 加载我们的Hook脚本
            try {
                console.log("加载持久化Hook...");
                // 这里加载您的主要Hook脚本
                // ...
            } catch(e) {
                console.log("加载失败: " + e);
            }
            
            return result;
        };
    });
}

loadPersistentAgent();
```

### 调试技巧

如果您的脚本不能正常工作，可以使用以下技巧进行调试：

```javascript
// 使用try-catch捕获错误
try {
    // 您的代码
    hookComplexFunction();
} catch(e) {
    console.log("错误: " + e.message);
    console.log("堆栈: " + e.stack);
}

// 显示详细的对象信息
function dumpObject(obj) {
    console.log("对象类型: " + Object.prototype.toString.call(obj));
    
    for (var prop in obj) {
        try {
            console.log("属性: " + prop + " = " + obj[prop]);
        } catch(e) {
            console.log("属性: " + prop + " (无法访问)");
        }
    }
}

// 使用断点进行调试
function debugFunction() {
    // 使用console.log输出调试信息
    console.log("断点1");
    
    // 使用send发送详细调试信息
    send({
        type: "debug",
        message: "执行到此处",
        data: { value: someValue }
    });
    
    console.log("断点2");
}
```

---

本指南介绍了Frida的基本使用方法。更高级的功能，如NativePointer操作、汇编级别的指令检测和修改、Stalker API等，请参考[高级功能](advanced-features.md)文档。 