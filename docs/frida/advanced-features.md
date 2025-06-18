# Frida 高级功能指南

本文档介绍Frida的高级功能，适合已掌握基础使用方法的用户。

## 目录

- [指令级跟踪](#指令级跟踪)
- [自定义脚本加载器](#自定义脚本加载器)
- [汇编代码操作](#汇编代码操作)
- [调用约定处理](#调用约定处理)
- [性能优化技巧](#性能优化技巧)
- [进程通信](#进程通信)
- [调试器集成](#调试器集成)
- [自定义扩展](#自定义扩展)

## 指令级跟踪

Frida的Stalker API允许您在指令级别跟踪进程执行流程，对于深入分析程序行为非常有用。

### 基本使用

```javascript
// 设置跟踪回调
var mainModule = Process.getModuleByName("target.exe");

Stalker.follow(Process.getCurrentThreadId(), {
    events: {
        call: true,      // 拦截函数调用
        ret: true,       // 拦截函数返回
        exec: false,     // 拦截所有执行指令
        block: false,    // 拦截基本块
        compile: false   // 拦截JIT编译
    },
    
    // 事件回调
    onReceive: function(events) {
        var count = Stalker.parse(events, {
            onCallSummary: function(summary) {
                // summary是一个包含调用地址和次数的对象
                console.log("调用摘要:");
                for (var address in summary) {
                    console.log(ptr(address) + ": " + summary[address]);
                }
            }
        });
    }
});

// 运行一段时间后停止跟踪
setTimeout(function() {
    Stalker.unfollow(Process.getCurrentThreadId());
    Stalker.garbageCollect();
}, 5000);
```

### 高级跟踪

通过自定义transformer可以实现更精细的控制：

```javascript
Stalker.follow(Process.getCurrentThreadId(), {
    transform: function(iterator) {
        var instruction;
        
        while ((instruction = iterator.next()) !== null) {
            // 分析每条指令
            console.log("指令: " + instruction.address + " -> " + instruction.mnemonic);
            
            // 当遇到特定指令时插入自定义代码
            if (instruction.mnemonic === "call") {
                iterator.putCallout(function(context) {
                    // 调用前执行
                    console.log("即将调用: " + context.pc);
                    
                    // 可以修改上下文
                    // context.rax = ptr("0x1234");
                });
            }
            
            // 保持原始指令
            iterator.keep();
        }
    }
});
```

### 代码覆盖率分析

使用Stalker进行代码覆盖率分析：

```javascript
// 保存已执行的基本块
var executedBlocks = {};
var moduleBase = Process.getModuleByName("target.dll").base;
var moduleSize = Process.getModuleByName("target.dll").size;

Stalker.follow(Process.getCurrentThreadId(), {
    events: {
        compile: true
    },
    
    onReceive: function(events) {
        Stalker.parse(events, {
            onCompile: function(begin, end) {
                // 每个基本块被执行时
                var blockSize = end.sub(begin);
                var offset = begin.sub(moduleBase);
                
                // 记录已执行块
                if (begin.compare(moduleBase) >= 0 &&
                    end.compare(moduleBase.add(moduleSize)) <= 0) {
                    executedBlocks[offset] = blockSize;
                }
            }
        });
    }
});

// 一段时间后导出覆盖率信息
setTimeout(function() {
    Stalker.unfollow(Process.getCurrentThreadId());
    
    // 计算覆盖率
    var executedBytes = 0;
    for (var offset in executedBlocks) {
        executedBytes += parseInt(executedBlocks[offset]);
    }
    
    var coveragePercentage = (executedBytes / moduleSize) * 100;
    console.log("代码覆盖率: " + coveragePercentage.toFixed(2) + "%");
    
    // 导出覆盖率数据
    send({
        type: "coverage",
        data: executedBlocks,
        moduleBase: moduleBase.toString(),
        moduleSize: moduleSize
    });
}, 10000);
```

## 自定义脚本加载器

### 创建动态脚本加载系统

在复杂应用中，您可能需要一个脚本管理系统来动态加载和卸载不同的Frida脚本：

```javascript
// 主框架脚本
(function() {
    var scriptRegistry = {};
    
    // 消息处理器
    function onMessage(message) {
        if (message.type === "load") {
            loadScript(message.name, message.script);
        } else if (message.type === "unload") {
            unloadScript(message.name);
        } else if (message.type === "call") {
            callScriptMethod(message.script, message.method, message.args);
        }
    }
    
    // 加载脚本
    function loadScript(name, scriptCode) {
        try {
            // 创建沙盒环境
            var scriptGlobal = {
                console: console,
                Process: Process,
                Module: Module,
                Memory: Memory,
                Interceptor: Interceptor,
                Stalker: Stalker,
                ptr: ptr,
                // 添加自定义API
                sendToHost: function(data) {
                    send({
                        type: "script-message",
                        from: name,
                        data: data
                    });
                }
            };
            
            // 创建执行脚本的函数
            var scriptFunction = new Function("env", 
                "with(env) { " + scriptCode + " }");
            
            // 执行脚本
            scriptFunction(scriptGlobal);
            
            // 存储脚本环境以供后续调用
            scriptRegistry[name] = scriptGlobal;
            
            send({
                type: "script-loaded",
                name: name
            });
        } catch (e) {
            send({
                type: "script-error",
                name: name,
                error: e.toString()
            });
        }
    }
    
    // 卸载脚本
    function unloadScript(name) {
        if (scriptRegistry[name]) {
            // 如果脚本有清理方法则调用
            if (scriptRegistry[name].cleanup) {
                try {
                    scriptRegistry[name].cleanup();
                } catch (e) {
                    console.log("脚本清理错误: " + e);
                }
            }
            
            delete scriptRegistry[name];
            send({
                type: "script-unloaded",
                name: name
            });
        }
    }
    
    // 调用脚本方法
    function callScriptMethod(scriptName, methodName, args) {
        if (scriptRegistry[scriptName] && scriptRegistry[scriptName][methodName]) {
            try {
                var result = scriptRegistry[scriptName][methodName].apply(null, args || []);
                send({
                    type: "method-result",
                    script: scriptName,
                    method: methodName,
                    result: result
                });
            } catch (e) {
                send({
                    type: "method-error",
                    script: scriptName,
                    method: methodName,
                    error: e.toString()
                });
            }
        } else {
            send({
                type: "method-not-found",
                script: scriptName,
                method: methodName
            });
        }
    }
    
    // 接收消息
    recv("message", onMessage);
    
    send({
        type: "loader-ready"
    });
})();
```

### Python端的脚本管理

配合上面的加载器使用：

```python
import frida
import json

class FridaScriptManager:
    def __init__(self, target):
        self.device = frida.get_usb_device()
        self.session = self.device.attach(target)
        
        # 加载主框架脚本
        with open("loader.js", "r") as f:
            loader_js = f.read()
        
        self.script = self.session.create_script(loader_js)
        self.script.on("message", self._on_message)
        self.script.load()
        
        # 等待加载器就绪
        self.loader_ready = False
        while not self.loader_ready:
            pass
    
    def _on_message(self, message, data):
        if message["type"] == "send":
            payload = message["payload"]
            
            if payload["type"] == "loader-ready":
                self.loader_ready = True
            
            elif payload["type"] == "script-message":
                print(f"[{payload['from']}]: {payload['data']}")
            
            # 处理其他消息...
    
    def load_script(self, name, script_path):
        with open(script_path, "r") as f:
            script_code = f.read()
        
        self.script.post({
            "type": "load",
            "name": name,
            "script": script_code
        })
    
    def unload_script(self, name):
        self.script.post({
            "type": "unload",
            "name": name
        })
    
    def call_method(self, script, method, args=None):
        self.script.post({
            "type": "call",
            "script": script,
            "method": method,
            "args": args or []
        })

# 使用示例
manager = FridaScriptManager("com.example.app")
manager.load_script("ssl-pinning", "scripts/ssl-pinning.js")
manager.load_script("crypto-monitor", "scripts/crypto-monitor.js")
# 调用脚本方法
manager.call_method("ssl-pinning", "disable")
```

## 汇编代码操作

### 使用汇编写入器

Frida提供了不同架构的汇编写入器，您可以用它们在运行时修改代码：

```javascript
// 找到目标函数
var targetFunction = Module.getExportByName("target.dll", "CheckLicense");

// 创建一个总是返回true的补丁
Memory.patchCode(targetFunction, 16, function(code) {
    var writer = null;
    
    // 根据架构选择写入器
    if (Process.arch === "x64") {
        writer = new X86Writer(code, { pc: targetFunction });
        // mov eax, 1
        writer.putMovRegU32("eax", 1);
        // ret
        writer.putRet();
    } 
    else if (Process.arch === "arm64") {
        writer = new Arm64Writer(code, { pc: targetFunction });
        // mov x0, 1
        writer.putMovRegU64("x0", 1);
        // ret
        writer.putRet();
    }
    else if (Process.arch === "arm") {
        writer = new ArmWriter(code, { pc: targetFunction });
        // mov r0, #1
        writer.putMovRegU32("r0", 1);
        // bx lr
        writer.putBxReg("lr");
    }
    
    writer.flush();
});

console.log("函数已被修补为始终返回true");
```

### 读取和分析汇编代码

除了写入汇编外，您还可以读取和分析现有代码：

```javascript
// 找到目标函数
var targetFunction = Module.getExportByName("target.dll", "TargetFunction");

// 读取并反汇编前100字节的代码
var instructions = Instruction.parse(targetFunction, 100);

console.log("函数反汇编:");
instructions.forEach(function(instruction) {
    console.log(instruction.address + ": " + instruction.mnemonic + " " + instruction.opStr);
});

// 分析控制流
console.log("控制流分析:");
instructions.forEach(function(instruction) {
    if (instruction.groups.indexOf("jump") !== -1 || 
        instruction.groups.indexOf("call") !== -1 || 
        instruction.groups.indexOf("ret") !== -1) {
        console.log("控制转移: " + instruction.address + " -> " + instruction.mnemonic);
        
        // 分析跳转目标
        if (instruction.operands.length > 0 && 
            instruction.operands[0].type === "imm") {
            console.log("跳转目标: " + instruction.operands[0].value);
        }
    }
});
```

## 调用约定处理

### 不同调用约定的处理

在跨平台或者和不同编译器交互时，正确处理调用约定非常重要：

```javascript
// stdcall约定的函数(Win32 API常见)
var MessageBoxW = new NativeFunction(
    Module.getExportByName("user32.dll", "MessageBoxW"),
    'int', ['pointer', 'pointer', 'pointer', 'uint32'],
    'stdcall' // 指定调用约定
);

// cdecl约定的函数(默认约定)
var printf = new NativeFunction(
    Module.getExportByName("msvcrt.dll", "printf"),
    'int', ['pointer', '...'],
    'cdecl'
);

// 使用自定义调用约定(例如thiscall)
var someMethod = new NativeFunction(
    ptr("0x12345678"),
    'int', ['pointer', 'int', 'int'],
    {
        abi: 'thiscall',    // 调用约定
        scheduling: 'exclusive',  // 独占调度
        exceptions: 'propagate'   // 异常传播
    }
);
```

### 创建和调用虚表函数

处理C++对象和虚函数：

```javascript
// 假设我们有一个C++对象的地址
var objectPtr = ptr("0x12345678");

// 读取vtable指针(通常是对象的前4或8个字节)
var vtablePtr = Memory.readPointer(objectPtr);
console.log("VTable地址: " + vtablePtr);

// 读取vtable中的第3个函数(索引2)
var vtableFuncPtr = Memory.readPointer(vtablePtr.add(2 * Process.pointerSize));
console.log("虚函数地址: " + vtableFuncPtr);

// 创建一个NativeFunction来调用该函数
var virtualMethod = new NativeFunction(vtableFuncPtr, 'int', ['pointer', 'int'], 'thiscall');

// 调用虚函数，第一个参数是this指针
var result = virtualMethod(objectPtr, 42);
console.log("虚函数返回: " + result);
```

## 性能优化技巧

### 性能注意事项

Frida hook可以显著影响目标进程的性能，特别是对于频繁调用的函数。以下是一些优化技巧：

```javascript
// 1. 使用选择性的hook而不是Hook所有调用
// 不好的做法: Hook所有函数
var allFunctions = Process.getModuleByName("target.dll").enumerateExports();
allFunctions.forEach(function(func) {
    Interceptor.attach(func.address, { /* ... */ });
});

// 更好的做法: 只Hook关键函数
var keyFunctions = ["Connect", "Authenticate", "ProcessData"];
keyFunctions.forEach(function(name) {
    var address = Module.getExportByName("target.dll", name);
    Interceptor.attach(address, { /* ... */ });
});

// 2. 限制收集的数据
// 不好的做法: 记录每次调用的完整堆栈和参数
Interceptor.attach(targetFunc, {
    onEnter: function(args) {
        console.log("调用参数: " + args[0] + ", " + args[1]);
        console.log("调用堆栈: " + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\n"));
    }
});

// 更好的做法: 只在特定条件下记录
Interceptor.attach(targetFunc, {
    onEnter: function(args) {
        var firstArg = args[0].toInt32();
        if (firstArg === 0x1234) { // 只关注特定值
            console.log("发现目标调用!");
            // 只在此条件下记录堆栈
            this.shouldLog = true;
        }
    },
    onLeave: function(retval) {
        if (this.shouldLog) {
            console.log("返回值: " + retval);
        }
    }
});

// 3. 使用批处理处理数据
var batchSize = 100;
var callCounter = 0;
var batchData = [];

Interceptor.attach(targetFunc, {
    onEnter: function(args) {
        // 收集数据
        batchData.push({
            counter: callCounter++,
            arg0: args[0].toInt32()
        });
        
        // 当达到批处理大小时，一次性发送
        if (batchData.length >= batchSize) {
            send({type: "batch-data", data: batchData});
            batchData = [];
        }
    }
});

// 4. 使用内联hook过滤
Interceptor.attach(targetFunc, {
    onEnter: function(args) {
        this.shouldLog = (args[0].toInt32() === 0x1234);
    },
    onLeave: function(retval) {
        if (this.shouldLog) {
            // 只有onEnter标记的调用才会执行这里
            console.log("目标调用返回值: " + retval);
        }
    }
});
```

### 使用NativeCallback优化

```javascript
// 为频繁调用的回调创建常驻的NativeCallback
var callback = new NativeCallback(function(a, b) {
    return a + b;
}, 'int', ['int', 'int']);

// 使用常驻回调替换目标函数
Interceptor.replace(targetFunctionPtr, callback);

// 在多处复用同一个回调
var cryptoCallbacks = {
    encrypt: new NativeCallback(function(data, len, key) {
        // 处理加密回调
        return originalEncrypt(data, len, key);
    }, 'pointer', ['pointer', 'int', 'pointer']),
    
    decrypt: new NativeCallback(function(data, len, key) {
        // 处理解密回调
        return originalDecrypt(data, len, key);
    }, 'pointer', ['pointer', 'int', 'pointer'])
};

Interceptor.replace(encryptFuncPtr, cryptoCallbacks.encrypt);
Interceptor.replace(decryptFuncPtr, cryptoCallbacks.decrypt);
```

## 进程通信

### 使用RPC进行双向通信

```javascript
// JavaScript端
rpc.exports = {
    // 简单导出函数
    getProcessInfo: function() {
        return {
            pid: Process.id,
            arch: Process.arch,
            platform: Process.platform,
            pageSize: Process.pageSize,
            pointerSize: Process.pointerSize
        };
    },
    
    // 接受参数并返回结果
    findModule: function(moduleName) {
        try {
            var module = Process.getModuleByName(moduleName);
            return {
                name: module.name,
                base: module.base.toString(),
                size: module.size,
                path: module.path
            };
        } catch (e) {
            throw new Error("模块未找到: " + moduleName);
        }
    },
    
    // 执行复杂操作并返回结果
    scanMemory: function(pattern, moduleNames) {
        var results = [];
        var modules = [];
        
        if (moduleNames && moduleNames.length > 0) {
            moduleNames.forEach(function(name) {
                try {
                    modules.push(Process.getModuleByName(name));
                } catch (e) {
                    console.log("模块不存在: " + name);
                }
            });
        } else {
            modules = Process.enumerateModules();
        }
        
        modules.forEach(function(module) {
            Memory.scan(module.base, module.size, pattern, {
                onMatch: function(address, size) {
                    results.push({
                        address: address.toString(),
                        module: module.name,
                        offset: address.sub(module.base).toString()
                    });
                },
                onComplete: function() {}
            });
        });
        
        return results;
    }
};

// 从JavaScript调用Python的RPC方法
console.log("调用Python RPC方法...");
var result = new Promise(function(resolve, reject) {
    send({
        type: "rpc-call",
        method: "getSystemInfo",
        args: []
    }, function(response) {
        if (response.type === "rpc-result") {
            resolve(response.result);
        } else {
            reject(new Error(response.error));
        }
    });
});

// 在Python中处理这个调用
"""
def on_message(message, data):
    if message["type"] == "send":
        payload = message["payload"]
        if payload["type"] == "rpc-call":
            method = payload["method"]
            args = payload["args"]
            
            try:
                if method == "getSystemInfo":
                    import platform
                    result = {
                        "system": platform.system(),
                        "version": platform.version(),
                        "python": platform.python_version()
                    }
                    script.post({"type": "rpc-result", "result": result})
                else:
                    script.post({"type": "rpc-error", "error": "方法未找到"})
            except Exception as e:
                script.post({"type": "rpc-error", "error": str(e)})
"""
```

## 调试器集成

### 集成GDB/LLDB

Frida可以与GDB或LLDB等调试器集成，提供高级调试能力：

```javascript
// 在关键点生成断点
Interceptor.attach(targetFunctionPtr, {
    onEnter: function(args) {
        if (args[0].toInt32() === 0x1234) {
            // 发现感兴趣的调用，生成断点
            var debug = new DebugSymbol.fromAddress(this.returnAddress);
            console.log("请在此处设置断点: " + debug.toString());
            console.log("gdb命令: break *" + this.returnAddress);
            
            // 可选: 触发一个陷阱指令，让附加的调试器捕获
            // 注意: 使用前请确保已附加调试器，否则可能崩溃
            // Thread.sleep(1); // 给时间附加调试器
            // Memory.patchCode(this.returnAddress, 4, function(code) {
            //     code.writeByteArray([0xCC]); // x86平台的int 3断点指令
            // });
        }
    }
});
```

### 生成调试脚本

自动生成调试脚本以供调试器使用：

```javascript
// 生成LLDB脚本来监控关键数据结构
function generateDebuggerScript() {
    var script = "";
    
    // 遍历关键数据结构
    var structures = [
        {name: "UserInfo", address: userInfoPtr},
        {name: "SessionData", address: sessionDataPtr},
        {name: "CryptoContext", address: cryptoContextPtr}
    ];
    
    script += "# 自动生成的LLDB脚本\n";
    
    structures.forEach(function(struct) {
        script += "# 监控" + struct.name + "\n";
        script += "memory read --size 16 --format x --count 8 " + struct.address + "\n\n";
    });
    
    // 添加关键函数的断点
    script += "# 设置重要函数的断点\n";
    [
        Module.getExportByName("target.dll", "Authenticate"),
        Module.getExportByName("target.dll", "ProcessData"),
        Module.getExportByName("target.dll", "Encrypt")
    ].forEach(function(address) {
        script += "breakpoint set --address " + address + "\n";
    });
    
    // 发送回主机进行保存
    send({
        type: "debugger-script",
        script: script,
        platform: Process.platform
    });
}

generateDebuggerScript();
```

## 自定义扩展

### 创建Frida扩展

您可以创建自己的Frida扩展来添加新功能：

```javascript
// 创建自定义工具库
(function() {
    // 定义全局命名空间
    var FridaExt = {};
    
    // 添加高级内存扫描功能
    FridaExt.advancedMemoryScan = function(pattern, options) {
        options = options || {};
        var ranges = options.ranges || Process.enumerateRanges('r-x');
        var results = [];
        
        ranges.forEach(function(range) {
            if (options.progress) {
                options.progress(range.base, range.size);
            }
            
            Memory.scan(range.base, range.size, pattern, {
                onMatch: function(address, size) {
                    var context = {};
                    
                    // 收集上下文
                    if (options.contextBytes) {
                        var before = options.contextBytes.before || 16;
                        var after = options.contextBytes.after || 16;
                        
                        try {
                            context.before = Memory.readByteArray(address.sub(before), before);
                            context.after = Memory.readByteArray(address.add(size), after);
                            context.matchedBytes = Memory.readByteArray(address, size);
                        } catch(e) {
                            context.error = e.toString();
                        }
                    }
                    
                    // 符号信息
                    if (options.resolveSymbols) {
                        try {
                            context.symbol = DebugSymbol.fromAddress(address);
                        } catch(e) {}
                    }
                    
                    var result = {
                        address: address,
                        size: size,
                        context: context
                    };
                    
                    results.push(result);
                    
                    if (options.onMatch) {
                        options.onMatch(result);
                    }
                },
                onComplete: function() {
                    if (options.onComplete) {
                        options.onComplete(results);
                    }
                }
            });
        });
        
        return results;
    };
    
    // 添加访问监控功能
    FridaExt.watchMemory = function(address, size, options) {
        options = options || {};
        var accessCount = 0;
        var writeCount = 0;
        var execCount = 0;
        var watchId = null;
        
        function onAccess(details) {
            accessCount++;
            
            var info = {
                operation: details.operation,
                from: details.from,
                address: details.address,
                rangeIndex: details.rangeIndex,
                accessCount: accessCount,
                writeCount: writeCount,
                execCount: execCount,
                timestamp: new Date()
            };
            
            if (details.operation === 'write') {
                writeCount++;
            } else if (details.operation === 'execute') {
                execCount++;
            }
            
            if (options.onAccess) {
                options.onAccess(info);
            }
        }
        
        watchId = Memory.protect(address, size, options.protection || 'r-x');
        
        return {
            stop: function() {
                if (watchId !== null) {
                    MemoryAccessMonitor.disable(watchId);
                    watchId = null;
                }
                
                return {
                    accessCount: accessCount,
                    writeCount: writeCount,
                    execCount: execCount
                };
            }
        };
    };
    
    // 注入到全局命名空间
    Object.defineProperty(globalThis, 'FridaExt', {
        value: FridaExt,
        writable: false,
        enumerable: true,
        configurable: false
    });
})();

// 使用扩展的示例
FridaExt.advancedMemoryScan("12 34 ?? AB", {
    contextBytes: {before: 32, after: 32},
    resolveSymbols: true,
    onMatch: function(result) {
        console.log("找到匹配: " + result.address);
    }
});

var watcher = FridaExt.watchMemory(ptr("0x12345678"), 1024, {
    onAccess: function(info) {
        console.log(info.operation + " 操作从 " + info.from);
    }
});

// 一段时间后停止监控
setTimeout(function() {
    var stats = watcher.stop();
    console.log("总访问次数: " + stats.accessCount);
}, 10000);
```

---

这些高级功能使Frida成为一个强大的动态分析和逆向工程工具。结合基本使用指南中的功能，您可以构建复杂的自动化分析系统和定制的安全测试工具。 