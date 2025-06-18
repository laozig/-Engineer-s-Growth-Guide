# Frida API参考

本文档提供了Frida主要API的详细参考，方便您在编写脚本时查阅。

## 目录

- [JavaScript API概述](#javascript-api概述)
- [核心模块](#核心模块)
- [Process模块](#process模块)
- [Module模块](#module模块)
- [Memory模块](#memory模块)
- [Thread模块](#thread模块)
- [Interceptor模块](#interceptor模块)
- [Stalker模块](#stalker模块)
- [NativeFunction](#nativefunction)
- [NativeCallback](#nativecallback)
- [File模块](#file模块)
- [Socket模块](#socket模块)
- [Database模块](#database模块)
- [Java模块](#java模块)
- [ObjC模块](#objc模块)
- [类型参考](#类型参考)

## JavaScript API概述

Frida的JavaScript API允许您与目标进程交互，主要分为以下几类：

- **进程和线程操作**：访问和控制进程和线程
- **内存操作**：读取、写入和扫描进程内存
- **模块操作**：枚举、加载和访问已加载的模块
- **函数拦截**：拦截和Hook函数调用
- **指令级跟踪**：在指令级别跟踪代码执行
- **语言绑定**：与Java、Objective-C等平台特定语言交互

## 核心模块

### 全局函数

| 函数 | 描述 |
|------|------|
| `ptr(address)` | 创建一个NativePointer对象指向给定地址 |
| `setTimeout(callback, delay)` | 设置延时执行 |
| `clearTimeout(id)` | 清除延时 |
| `setInterval(callback, interval)` | 设置定时重复执行 |
| `clearInterval(id)` | 清除定时器 |
| `send(message[, data])` | 向主机发送消息 |
| `recv(type, callback)` | 接收来自主机的消息 |

### 全局对象

| 对象 | 描述 |
|------|------|
| `console` | 日志输出对象 |
| `rpc` | 远程过程调用对象 |
| `hexdump(target[, options])` | 创建内存区域的十六进制转储 |

## Process模块

### 属性

| 属性 | 类型 | 描述 |
|------|------|------|
| `Process.arch` | String | 进程的架构 (如'ia32', 'x64', 'arm') |
| `Process.platform` | String | 操作系统平台 (如'windows', 'darwin', 'linux') |
| `Process.pageSize` | Number | 内存页大小，通常为4096 |
| `Process.pointerSize` | Number | 指针大小(4或8) |
| `Process.id` | Number | 当前进程ID |
| `Process.codeSigningPolicy` | String | 代码签名策略 |

### 方法

| 方法 | 描述 |
|------|------|
| `Process.enumerateModules()` | 枚举所有已加载模块 |
| `Process.findModuleByAddress(address)` | 通过地址查找模块 |
| `Process.findModuleByName(name)` | 通过名称查找模块 |
| `Process.enumerateRanges(protection)` | 枚举内存区域 |
| `Process.findRangeByAddress(address)` | 通过地址查找内存区域 |
| `Process.enumerateThreads()` | 枚举所有线程 |
| `Process.getCurrentThreadId()` | 获取当前线程ID |
| `Process.setExceptionHandler(callback)` | 设置异常处理器 |

### 示例

```javascript
// 获取进程信息
console.log("架构: " + Process.arch);
console.log("平台: " + Process.platform);
console.log("指针大小: " + Process.pointerSize + " 字节");

// 枚举已加载模块
Process.enumerateModules().forEach(function(module) {
    console.log("模块名: " + module.name + ", 基地址: " + module.base);
});

// 获取当前线程ID
var threadId = Process.getCurrentThreadId();
console.log("当前线程ID: " + threadId);

// 设置异常处理器
Process.setExceptionHandler(function(details) {
    console.log("捕获到异常: " + details.type + " at " + details.address);
    return false; // 返回true则消耗异常，返回false则传递给系统
});
```

## Module模块

### 方法

| 方法 | 描述 |
|------|------|
| `Module.getExportByName(moduleName, exportName)` | 获取导出函数地址 |
| `Module.findExportByName(moduleName, exportName)` | 查找导出函数地址 |
| `Module.enumerateExports(moduleName)` | 枚举模块的所有导出 |
| `Module.enumerateImports(moduleName)` | 枚举模块的所有导入 |
| `Module.enumerateSymbols(moduleName)` | 枚举模块的所有符号 |
| `Module.enumerateRanges(moduleName[, protection])` | 枚举模块的内存区域 |
| `Module.findBaseAddress(moduleName)` | 查找模块基地址 |
| `Module.load(path)` | 加载动态库 |

### Module对象属性

| 属性 | 类型 | 描述 |
|------|------|------|
| `name` | String | 模块名称 |
| `base` | NativePointer | 模块基地址 |
| `size` | Number | 模块大小 |
| `path` | String | 模块文件路径 |

### 示例

```javascript
// 获取函数地址
var openPtr = Module.getExportByName(null, "open");
console.log("open函数地址: " + openPtr);

// 枚举模块导出
var libcModule = Process.findModuleByName("libc.so");
Module.enumerateExports(libcModule.name).forEach(function(exp) {
    if (exp.type === "function") {
        console.log("导出函数: " + exp.name);
    }
});

// 查找特定模块的符号
Module.enumerateSymbols("libc.so").forEach(function(sym) {
    if (sym.name.indexOf("malloc") !== -1) {
        console.log("发现malloc相关符号: " + sym.name + " at " + sym.address);
    }
});

// 加载动态库
try {
    Module.load("/path/to/library.so");
    console.log("库加载成功");
} catch (e) {
    console.log("库加载失败: " + e);
}
```

## Memory模块

### 方法

| 方法 | 描述 |
|------|------|
| `Memory.scan(address, size, pattern, callbacks)` | 扫描内存中的模式 |
| `Memory.alloc(size[, options])` | 分配内存 |
| `Memory.copy(dst, src, size)` | 复制内存 |
| `Memory.protect(address, size, protection)` | 修改内存保护 |
| `Memory.patchCode(address, size, apply)` | 修改代码内存 |

### 读写方法

| 方法 | 描述 |
|------|------|
| `Memory.readPointer(address)` | 读取指针 |
| `Memory.readS8/readU8(address)` | 读取8位有符号/无符号整数 |
| `Memory.readS16/readU16(address)` | 读取16位有符号/无符号整数 |
| `Memory.readS32/readU32(address)` | 读取32位有符号/无符号整数 |
| `Memory.readS64/readU64(address)` | 读取64位有符号/无符号整数 |
| `Memory.readFloat/readDouble(address)` | 读取浮点/双精度浮点数 |
| `Memory.readByteArray(address, length)` | 读取字节数组 |
| `Memory.readUtf8String/readUtf16String(address)` | 读取UTF-8/UTF-16字符串 |
| `Memory.writePointer(address, value)` | 写入指针 |
| `Memory.writeS8/writeU8(address, value)` | 写入8位有符号/无符号整数 |
| `Memory.writeS16/writeU16(address, value)` | 写入16位有符号/无符号整数 |
| `Memory.writeS32/writeU32(address, value)` | 写入32位有符号/无符号整数 |
| `Memory.writeS64/writeU64(address, value)` | 写入64位有符号/无符号整数 |
| `Memory.writeFloat/writeDouble(address, value)` | 写入浮点/双精度浮点数 |
| `Memory.writeByteArray(address, bytes)` | 写入字节数组 |
| `Memory.writeUtf8String/writeUtf16String(address, string)` | 写入UTF-8/UTF-16字符串 |

### 示例

```javascript
// 分配内存
var buf = Memory.alloc(1024);
console.log("分配的内存地址: " + buf);

// 写入数据
Memory.writeUtf8String(buf, "Hello Frida!");
Memory.writeS32(buf.add(16), 12345);

// 读取数据
var str = Memory.readUtf8String(buf);
var num = Memory.readS32(buf.add(16));
console.log("读取的字符串: " + str);
console.log("读取的整数: " + num);

// 扫描内存
Memory.scan(Process.getModuleByName("target.dll").base, 
    Process.getModuleByName("target.dll").size, 
    "12 34 ?? 78", {
        onMatch: function(address, size) {
            console.log("找到匹配: " + address);
        },
        onComplete: function() {
            console.log("扫描完成");
        }
    }
);

// 修改内存保护
Memory.protect(ptr("0x12345678"), 1024, "rwx");

// 修补代码
Memory.patchCode(ptr("0x12345678"), 4, function(code) {
    code.writeByteArray([0x90, 0x90, 0x90, 0x90]); // 写入NOP指令
});
```

## Thread模块

### 方法

| 方法 | 描述 |
|------|------|
| `Thread.backtrace([context, backtracer])` | 获取调用堆栈 |
| `Thread.sleep(delay)` | 使当前线程休眠 |

### 示例

```javascript
// 获取调用堆栈
var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);
console.log("调用堆栈:");
backtrace.forEach(function(address) {
    console.log("\t" + DebugSymbol.fromAddress(address));
});

// 休眠当前线程
console.log("休眠前");
Thread.sleep(1); // 休眠1秒
console.log("休眠后");
```

## Interceptor模块

### 方法

| 方法 | 描述 |
|------|------|
| `Interceptor.attach(target, callbacks)` | 附加到函数开始处 |
| `Interceptor.replace(target, replacement)` | 替换函数实现 |
| `Interceptor.revert(target)` | 恢复原始函数实现 |

### 回调对象

在`attach`方法中使用的callbacks对象可以包含以下回调：

| 回调 | 描述 |
|------|------|
| `onEnter(args)` | 函数进入时调用 |
| `onLeave(retval)` | 函数返回时调用 |

### 示例

```javascript
// 附加到函数
var openPtr = Module.getExportByName(null, "open");
var open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);

Interceptor.attach(openPtr, {
    onEnter: function(args) {
        var path = args[0].readUtf8String();
        this.path = path;
        console.log("open(" + path + ")");
    },
    onLeave: function(retval) {
        console.log("open返回: " + retval + " 对于路径: " + this.path);
    }
});

// 替换函数
Interceptor.replace(openPtr, new NativeCallback(function(pathPtr, flags) {
    var path = pathPtr.readUtf8String();
    console.log("拦截调用: open(" + path + ")");
    
    // 可以决定是否调用原始函数
    return open(pathPtr, flags);
}, 'int', ['pointer', 'int']));

// 恢复原始函数
setTimeout(function() {
    Interceptor.revert(openPtr);
    console.log("已恢复原始open函数");
}, 10000);
```

## Stalker模块

### 方法

| 方法 | 描述 |
|------|------|
| `Stalker.follow([threadId, options])` | 跟踪线程 |
| `Stalker.unfollow([threadId])` | 停止跟踪线程 |
| `Stalker.garbageCollect()` | 释放未使用的资源 |
| `Stalker.parse(events, callbacks)` | 解析事件流 |
| `Stalker.flush()` | 刷新事件队列 |
| `Stalker.trustThreshold` | 设置信任阈值 |
| `Stalker.queueDrainInterval` | 设置队列排空间隔 |
| `Stalker.queueCapacity` | 设置队列容量 |

### 跟踪选项

跟踪选项可包含以下属性：

| 选项 | 描述 |
|------|------|
| `events` | 要生成事件的对象 |
| `onReceive` | 接收事件的回调 |
| `onCallSummary` | 接收调用摘要的回调 |
| `transform` | 代码转换回调 |

### 示例

```javascript
// 基本跟踪
Stalker.follow(Process.getCurrentThreadId(), {
    events: {
        call: true,  // 跟踪函数调用
        ret: true    // 跟踪函数返回
    },
    onReceive: function(events) {
        // 解析事件
        Stalker.parse(events, {
            onCall: function(call) {
                console.log("调用: " + call.target);
            },
            onRet: function(ret) {
                console.log("返回: " + ret.target);
            }
        });
    }
});

// 一段时间后停止跟踪
setTimeout(function() {
    Stalker.unfollow(Process.getCurrentThreadId());
    Stalker.garbageCollect();
}, 5000);

// 使用transform转换代码
Stalker.follow(Process.getCurrentThreadId(), {
    transform: function(iterator) {
        var instruction;
        
        while ((instruction = iterator.next()) !== null) {
            if (instruction.mnemonic === "call") {
                console.log("转换call指令: " + instruction.address);
            }
            
            iterator.keep();
        }
    }
});
```

## NativeFunction

NativeFunction用于调用本机函数。

### 构造函数

| 方法 | 描述 |
|------|------|
| `new NativeFunction(address, returnType, argTypes, abi)` | 创建新的NativeFunction对象 |

### 参数

| 参数 | 描述 |
|------|------|
| `address` | 函数地址 |
| `returnType` | 返回类型字符串('void', 'int', 'pointer'等) |
| `argTypes` | 参数类型字符串数组 |
| `abi` | 调用约定(可选，如'stdcall', 'thiscall'等) |

### 示例

```javascript
// 创建printf函数
var printfPtr = Module.getExportByName(null, "printf");
var printf = new NativeFunction(printfPtr, 'int', ['pointer', '...']);

// 调用printf
var message = Memory.allocUtf8String("Hello from Frida, number: %d\n");
printf(message, 42);

// 指定调用约定的函数
var winAPI = new NativeFunction(
    Module.getExportByName("user32.dll", "MessageBoxW"),
    'int', ['pointer', 'pointer', 'pointer', 'uint'],
    'stdcall' // 指定调用约定
);
```

## NativeCallback

NativeCallback用于创建可从本机代码调用的回调函数。

### 构造函数

| 方法 | 描述 |
|------|------|
| `new NativeCallback(func, returnType, argTypes, abi)` | 创建新的NativeCallback对象 |

### 参数

| 参数 | 描述 |
|------|------|
| `func` | JavaScript回调函数 |
| `returnType` | 返回类型字符串('void', 'int', 'pointer'等) |
| `argTypes` | 参数类型字符串数组 |
| `abi` | 调用约定(可选，如'stdcall', 'thiscall'等) |

### 示例

```javascript
// 创建回调函数
var callback = new NativeCallback(function(a, b) {
    console.log("回调被调用: " + a + ", " + b);
    return a + b;
}, 'int', ['int', 'int']);

// 使用回调
var performOperation = new NativeFunction(
    Module.getExportByName("target.dll", "PerformOperation"),
    'int', ['pointer', 'int', 'int']
);

var result = performOperation(callback, 3, 4);
console.log("操作结果: " + result);
```

## Java模块

### 方法

| 方法 | 描述 |
|------|------|
| `Java.perform(fn)` | 在Java VM中执行操作 |
| `Java.use(className)` | 获取类包装器 |
| `Java.choose(className, callbacks)` | 查找类的实例 |
| `Java.enumerateLoadedClasses(callbacks)` | 枚举已加载的类 |
| `Java.scheduleOnMainThread(fn)` | 在主线程上调度任务 |
| `Java.registerClass(spec)` | 注册新的Java类 |

### 示例

```javascript
Java.perform(function() {
    // 获取类引用
    var Activity = Java.use("android.app.Activity");
    
    // Hook方法
    Activity.onCreate.overload("android.os.Bundle").implementation = function(bundle) {
        console.log("Activity.onCreate被调用");
        this.onCreate(bundle);
    };
    
    // 查找实例
    Java.choose("android.app.Activity", {
        onMatch: function(instance) {
            console.log("找到Activity实例: " + instance);
        },
        onComplete: function() {
            console.log("查找完成");
        }
    });
    
    // 枚举已加载的类
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.indexOf("com.target.app") !== -1) {
                console.log("目标应用类: " + className);
            }
        },
        onComplete: function() {}
    });
    
    // 在主线程执行
    Java.scheduleOnMainThread(function() {
        console.log("在主线程上执行");
    });
    
    // 注册新类
    var MyClass = Java.registerClass({
        name: "com.frida.MyClass",
        superClass: Java.use("java.lang.Object"),
        fields: {
            counter: "int"
        },
        methods: {
            add: [{
                returnType: "int",
                argumentTypes: ["int", "int"],
                implementation: function(a, b) {
                    return a + b;
                }
            }]
        }
    });
    
    // 使用新类
    var instance = MyClass.$new();
    console.log("1 + 2 = " + instance.add(1, 2));
});
```

## ObjC模块

### 方法

| 方法 | 描述 |
|------|------|
| `ObjC.available` | 检查ObjC运行时是否可用 |
| `ObjC.classes` | 获取所有类的字典 |
| `ObjC.protocols` | 获取所有协议的字典 |
| `ObjC.mainQueue` | 获取主队列 |
| `ObjC.schedule(queue, work)` | 在指定队列上调度工作 |
| `ObjC.choose(specifier, callbacks)` | 查找对象实例 |

### 示例

```javascript
if (ObjC.available) {
    // 获取类
    var UIAlertView = ObjC.classes.UIAlertView;
    
    // Hook方法
    Interceptor.attach(UIAlertView["- initWithTitle:message:delegate:cancelButtonTitle:otherButtonTitles:"].implementation, {
        onEnter: function(args) {
            var title = ObjC.Object(args[2]).toString();
            var message = ObjC.Object(args[3]).toString();
            console.log("UIAlertView: " + title + " - " + message);
        }
    });
    
    // 查找对象实例
    ObjC.choose({
        className: "UIViewController",
        onMatch: function(instance) {
            console.log("找到UIViewController: " + instance);
        },
        onComplete: function() {
            console.log("查找完成");
        }
    });
    
    // 在主队列上执行
    ObjC.schedule(ObjC.mainQueue, function() {
        console.log("在主队列上执行");
    });
}
```

## 类型参考

### 基本类型

| 类型 | 描述 |
|------|------|
| `void` | 无返回值 |
| `pointer` | 指针 |
| `int` | 有符号32位整数 |
| `uint` | 无符号32位整数 |
| `long` | 有符号长整数(根据平台32或64位) |
| `ulong` | 无符号长整数(根据平台32或64位) |
| `char` | 有符号8位整数 |
| `uchar` | 无符号8位整数 |
| `float` | 单精度浮点数 |
| `double` | 双精度浮点数 |
| `int8`, `uint8` | 8位整数 |
| `int16`, `uint16` | 16位整数 |
| `int32`, `uint32` | 32位整数 |
| `int64`, `uint64` | 64位整数 |

### 特殊类型

| 类型 | 描述 |
|------|------|
| `...` | 可变参数(仅用于NativeFunction) |
| `*` | 指针类型(如'char *'表示字符指针) |
| `[]` | 数组类型(如'char[]'表示字符数组) |

---

本文档提供了Frida主要API的概述，更多详细信息和最新更新请参考[Frida官方API文档](https://frida.re/docs/javascript-api/)。 