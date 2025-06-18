/**
 * Frida Hello World 示例
 * 
 * 这是一个最基本的Frida脚本示例，展示如何在目标进程中执行简单的操作。
 * 
 * 使用方法:
 * frida -U -l hello-world.js <目标进程名或PID>
 * 
 * 功能:
 * - 打印进程基本信息
 * - 枚举已加载模块
 * - Hook简单的函数调用(以libc的open函数为例)
 */

console.log("===============================");
console.log("[*] Frida Hello World 示例脚本已加载");

// 打印进程基本信息
console.log("[*] 进程信息:");
console.log("    PID: " + Process.id);
console.log("    架构: " + Process.arch);
console.log("    平台: " + Process.platform);

// 枚举前5个已加载模块
console.log("\n[*] 已加载模块 (前5个):");
var modules = Process.enumerateModules();
for (var i = 0; i < Math.min(modules.length, 5); i++) {
    var module = modules[i];
    console.log("    " + module.name + " - " + module.base + " - " + module.path);
}

// 根据平台执行不同的Hook操作
setTimeout(function() {
    try {
        // 准备Hook不同平台下的常用函数
        if (Process.platform === "linux" || Process.platform === "darwin") {
            // 在Linux/Android/iOS/macOS上Hook open函数
            hookOpenFunction();
        } else if (Process.platform === "windows") {
            // 在Windows上Hook CreateFileW函数
            hookCreateFileFunction();
        }
        console.log("\n[*] Hook安装完毕，等待触发...");
    } catch (e) {
        console.log("\n[-] Hook安装失败: " + e);
    }
}, 500);

// Hook Linux/Unix平台的open函数
function hookOpenFunction() {
    console.log("\n[*] 尝试Hook open函数...");
    
    var openPtr = Module.findExportByName(null, "open");
    if (openPtr == null) {
        console.log("[-] 未找到open函数");
        return;
    }
    
    Interceptor.attach(openPtr, {
        onEnter: function(args) {
            var path = Memory.readUtf8String(args[0]);
            this.path = path;
            
            console.log("[+] open(" + path + ") 被调用");
        },
        onLeave: function(retval) {
            console.log("[+] open(\"" + this.path + "\") 返回: " + retval);
        }
    });
    
    console.log("[*] open函数已Hook");
}

// Hook Windows平台的CreateFileW函数
function hookCreateFileFunction() {
    console.log("\n[*] 尝试Hook CreateFileW函数...");
    
    var createFilePtr = Module.findExportByName("kernel32.dll", "CreateFileW");
    if (createFilePtr == null) {
        console.log("[-] 未找到CreateFileW函数");
        return;
    }
    
    Interceptor.attach(createFilePtr, {
        onEnter: function(args) {
            var path = Memory.readUtf16String(args[0]);
            this.path = path;
            
            console.log("[+] CreateFileW(\"" + path + "\") 被调用");
        },
        onLeave: function(retval) {
            console.log("[+] CreateFileW(\"" + this.path + "\") 返回: " + retval);
        }
    });
    
    console.log("[*] CreateFileW函数已Hook");
}

// 使用Java API (适用于Android)
setTimeout(function() {
    if (Java.available) {
        console.log("\n[*] Java环境可用，尝试使用Java API");
        
        Java.perform(function() {
            try {
                console.log("[*] 尝试列出已加载的Java类...");
                let count = 0;
                const loadedClasses = [];
                
                Java.enumerateLoadedClasses({
                    onMatch: function(className) {
                        if (count < 5 && className.includes("android")) {
                            loadedClasses.push(className);
                            count++;
                        }
                    },
                    onComplete: function() {
                        console.log("[+] 已加载Java类示例:");
                        loadedClasses.forEach(function(className) {
                            console.log("    " + className);
                        });
                        console.log("[*] 仅显示前5个包含'android'的类");
                    }
                });
                
                // 尝试Hook Activity.onCreate方法
                try {
                    var Activity = Java.use("android.app.Activity");
                    Activity.onCreate.overload("android.os.Bundle").implementation = function(bundle) {
                        console.log("[+] Activity.onCreate() 被调用");
                        this.onCreate(bundle);
                        console.log("[+] Activity.onCreate() 原始方法已执行");
                    };
                    console.log("[*] 已Hook Activity.onCreate方法");
                } catch (e) {
                    console.log("[-] Hook Activity失败: " + e);
                }
                
            } catch (e) {
                console.log("[-] Java操作失败: " + e);
            }
        });
    }
}, 1000);

// 使用ObjC API (适用于iOS)
setTimeout(function() {
    if (ObjC && ObjC.available) {
        console.log("\n[*] Objective-C环境可用，尝试使用ObjC API");
        
        try {
            const classes = ObjC.classes;
            const classNames = Object.keys(classes);
            console.log("[+] 已加载Objective-C类示例:");
            for (let i = 0; i < Math.min(classNames.length, 5); i++) {
                console.log("    " + classNames[i]);
            }
            console.log("[*] 仅显示前5个类");
            
            // 尝试Hook NSLog函数
            try {
                const NSLog = new NativeFunction(
                    Module.findExportByName("Foundation", "NSLog"),
                    'void',
                    ['pointer', '...']
                );
                
                Interceptor.replace(NSLog, new NativeCallback(function(format, args) {
                    const message = ObjC.Object(args[0]).toString();
                    console.log("[+] NSLog: " + message);
                    NSLog(format, args);
                }, 'void', ['pointer', 'pointer']));
                
                console.log("[*] 已Hook NSLog函数");
            } catch (e) {
                console.log("[-] Hook NSLog失败: " + e);
            }
            
        } catch (e) {
            console.log("[-] Objective-C操作失败: " + e);
        }
    }
}, 1500);

console.log("[*] 脚本设置完成");
console.log("===============================");

// 保持脚本运行
setInterval(function() {}, 1000); 