# FileManager

FileManager 是 iOS 中用于与文件系统交互的核心类，提供了创建、读取、移动、复制和删除文件与目录的功能。本文档将介绍 FileManager 的基本使用方法。

## 目录

- [基本概念](#基本概念)
- [常用操作](#常用操作)
- [沙盒目录](#沙盒目录)
- [最佳实践](#最佳实践)

## 基本概念

FileManager 提供了一套用于管理文件系统的接口，主要功能包括：

- 获取和设置文件/目录属性
- 创建、复制、移动和删除文件/目录
- 遍历目录内容
- 获取系统路径和卷信息

```swift
// 获取默认 FileManager 实例
let fileManager = FileManager.default
```

## 常用操作

### 检查文件是否存在

```swift
let path = documentsDirectory.appendingPathComponent("file.txt").path
if fileManager.fileExists(atPath: path) {
    print("文件存在")
} else {
    print("文件不存在")
}

// 检查是文件还是目录
var isDirectory: ObjCBool = false
if fileManager.fileExists(atPath: path, isDirectory: &isDirectory) {
    if isDirectory.boolValue {
        print("这是一个目录")
    } else {
        print("这是一个文件")
    }
}
```

### 创建目录

```swift
let newDirectory = documentsDirectory.appendingPathComponent("NewFolder")

do {
    try fileManager.createDirectory(at: newDirectory, 
                                    withIntermediateDirectories: true, 
                                    attributes: nil)
    print("目录创建成功")
} catch {
    print("创建目录失败: \(error)")
}
```

### 创建文件

```swift
let filePath = documentsDirectory.appendingPathComponent("sample.txt")
let content = "这是一些文本内容"

do {
    try content.write(to: filePath, atomically: true, encoding: .utf8)
    print("文件创建成功")
} catch {
    print("创建文件失败: \(error)")
}
```

### 读取文件

```swift
let filePath = documentsDirectory.appendingPathComponent("sample.txt")

do {
    let content = try String(contentsOf: filePath, encoding: .utf8)
    print("文件内容: \(content)")
} catch {
    print("读取文件失败: \(error)")
}
```

### 复制文件

```swift
let sourcePath = documentsDirectory.appendingPathComponent("sample.txt")
let destinationPath = documentsDirectory.appendingPathComponent("sample_copy.txt")

do {
    try fileManager.copyItem(at: sourcePath, to: destinationPath)
    print("文件复制成功")
} catch {
    print("复制文件失败: \(error)")
}
```

### 移动/重命名文件

```swift
let sourcePath = documentsDirectory.appendingPathComponent("sample.txt")
let destinationPath = documentsDirectory.appendingPathComponent("renamed.txt")

do {
    try fileManager.moveItem(at: sourcePath, to: destinationPath)
    print("文件移动/重命名成功")
} catch {
    print("移动/重命名文件失败: \(error)")
}
```

### 删除文件

```swift
let filePath = documentsDirectory.appendingPathComponent("sample.txt")

do {
    try fileManager.removeItem(at: filePath)
    print("文件删除成功")
} catch {
    print("删除文件失败: \(error)")
}
```

### 列出目录内容

```swift
let directoryPath = documentsDirectory

do {
    let contents = try fileManager.contentsOfDirectory(at: directoryPath, 
                                                     includingPropertiesForKeys: nil, 
                                                     options: [])
    for item in contents {
        print("发现项目: \(item.lastPathComponent)")
    }
} catch {
    print("列出目录内容失败: \(error)")
}
```

## 沙盒目录

iOS 应用在沙盒环境中运行，每个应用只能访问自己的沙盒目录。

### 常用目录

```swift
// 获取 Documents 目录
func getDocumentsDirectory() -> URL {
    return fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0]
}

// 获取 Library/Caches 目录
func getCachesDirectory() -> URL {
    return fileManager.urls(for: .cachesDirectory, in: .userDomainMask)[0]
}

// 获取临时目录
func getTemporaryDirectory() -> URL {
    return fileManager.temporaryDirectory
}
```

### 目录用途

1. **Documents**：用于存储用户生成的文件，会备份到 iCloud
   - 示例：用户创建的文档、图片等

2. **Library/Caches**：缓存数据，不会备份到 iCloud，可能被系统清理
   - 示例：下载的图片缓存、临时文件

3. **tmp**：临时文件，不会备份到 iCloud，可能随时被系统清理
   - 示例：临时下载文件、临时处理数据

## 最佳实践

### 文件管理器封装

```swift
class AppFileManager {
    static let shared = AppFileManager()
    private let fileManager = FileManager.default
    
    lazy var documentsDirectory: URL = {
        return fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }()
    
    lazy var cachesDirectory: URL = {
        return fileManager.urls(for: .cachesDirectory, in: .userDomainMask)[0]
    }()
    
    // 保存文本文件
    func saveTextFile(_ text: String, fileName: String) -> Bool {
        let fileURL = documentsDirectory.appendingPathComponent(fileName)
        do {
            try text.write(to: fileURL, atomically: true, encoding: .utf8)
            return true
        } catch {
            print("保存文件失败: \(error)")
            return false
        }
    }
    
    // 读取文本文件
    func readTextFile(fileName: String) -> String? {
        let fileURL = documentsDirectory.appendingPathComponent(fileName)
        do {
            return try String(contentsOf: fileURL, encoding: .utf8)
        } catch {
            print("读取文件失败: \(error)")
            return nil
        }
    }
    
    // 删除文件
    func deleteFile(fileName: String, from directory: URL? = nil) -> Bool {
        let fileURL = (directory ?? documentsDirectory).appendingPathComponent(fileName)
        if fileManager.fileExists(atPath: fileURL.path) {
            do {
                try fileManager.removeItem(at: fileURL)
                return true
            } catch {
                print("删除文件失败: \(error)")
                return false
            }
        }
        return false
    }
}

// 使用示例
let appFiles = AppFileManager.shared

// 保存文件
appFiles.saveTextFile("重要笔记内容", fileName: "notes.txt")

// 读取文件
if let content = appFiles.readTextFile(fileName: "notes.txt") {
    print("笔记内容: \(content)")
}
```

### 异步文件操作

对于大文件操作，应使用异步方法避免阻塞主线程：

```swift
func saveDataAsync(data: Data, to url: URL, completion: @escaping (Bool) -> Void) {
    DispatchQueue.global(qos: .background).async {
        do {
            try data.write(to: url)
            DispatchQueue.main.async {
                completion(true)
            }
        } catch {
            print("异步保存失败: \(error)")
            DispatchQueue.main.async {
                completion(false)
            }
        }
    }
}
```

### 错误处理

始终使用 `do-catch` 块处理文件操作，避免潜在的运行时错误：

```swift
do {
    try fileManager.removeItem(at: fileURL)
} catch let error as NSError {
    switch error.code {
    case NSFileNoSuchFileError:
        print("文件不存在")
    case NSFileWriteNoPermissionError:
        print("没有写入权限")
    default:
        print("发生错误: \(error.localizedDescription)")
    }
}
```