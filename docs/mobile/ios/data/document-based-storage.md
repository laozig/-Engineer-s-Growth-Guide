# iOS 文档存储

iOS 提供了多种机制来管理文档和文件。本文将介绍 iOS 中的文档存储方案，包括 Document-Based App、文档浏览器、文件协调和版本控制等功能。

## 目录

- [文档存储概述](#文档存储概述)
- [Document-Based App](#document-based-app)
- [UIDocument](#uidocument)
- [文档浏览器](#文档浏览器)
- [文件协调](#文件协调)
- [版本控制](#版本控制)
- [最佳实践](#最佳实践)

## 文档存储概述

文档存储是 iOS 中处理用户创建和编辑的内容（如文本文档、绘图、音频编辑等）的主要方式。相比于一般的持久化，文档存储具有以下特点：

- **用户可见**：文档以文件形式存在，用户能感知到它们的存在
- **可移植**：可以在应用间共享、导入导出
- **版本控制**：支持创建文档的多个版本
- **云同步**：可与 iCloud 集成实现跨设备同步

## Document-Based App

文档驱动型应用是围绕创建、编辑和管理文档构建的应用，类似于桌面平台上的 Word、Excel 等应用。

### 创建文档驱动型应用

1. 在 Xcode 项目设置中，选择 "Document Based App" 选项
2. 设置支持的文档类型（UTIs）

```swift
// 在 Info.plist 中配置文档类型
// CFBundleDocumentTypes 数组中的一个条目示例
<dict>
    <key>CFBundleTypeName</key>
    <string>MyApp Document</string>
    <key>CFBundleTypeRole</key>
    <string>Editor</string>
    <key>LSHandlerRank</key>
    <string>Owner</string>
    <key>LSItemContentTypes</key>
    <array>
        <string>com.example.myapp.document</string>
    </array>
</dict>

// 声明自定义 UTI
<key>UTExportedTypeDeclarations</key>
<array>
    <dict>
        <key>UTTypeConformsTo</key>
        <array>
            <string>public.data</string>
            <string>public.content</string>
        </array>
        <key>UTTypeDescription</key>
        <string>MyApp Document</string>
        <key>UTTypeIdentifier</key>
        <string>com.example.myapp.document</string>
        <key>UTTypeTagSpecification</key>
        <dict>
            <key>public.filename-extension</key>
            <array>
                <string>mydoc</string>
            </array>
            <key>public.mime-type</key>
            <array>
                <string>application/x-mydoc</string>
            </array>
        </dict>
    </dict>
</array>
```

## UIDocument

`UIDocument` 类是 iOS 文档管理的核心，提供了文档读写、自动保存和版本控制等功能。

### 创建自定义文档类

```swift
class TextDocument: UIDocument {
    var text: String = ""
    
    // 读取文档内容
    override func load(fromContents contents: Any, ofType typeName: String?) throws {
        guard let data = contents as? Data,
              let loadedText = String(data: data, encoding: .utf8) else {
            throw NSError(domain: "TextDocumentError", code: 1, userInfo: nil)
        }
        
        text = loadedText
    }
    
    // 保存文档内容
    override func contents(forType typeName: String) throws -> Any {
        guard let data = text.data(using: .utf8) else {
            throw NSError(domain: "TextDocumentError", code: 2, userInfo: nil)
        }
        
        return data
    }
    
    // 自定义自动保存行为
    override func updateChangeCount(_ change: UIDocument.ChangeKind) {
        super.updateChangeCount(change)
        // 可以在这里添加自定义逻辑
    }
    
    // 处理保存冲突
    override func handleError(_ error: Error, userInteractionPermitted: Bool) {
        super.handleError(error, userInteractionPermitted: userInteractionPermitted)
        // 处理错误，例如显示错误提示
    }
}
```

### 使用文档对象

```swift
// 创建文档
let documentURL = documentsDirectory.appendingPathComponent("mydocument.mydoc")
let document = TextDocument(fileURL: documentURL)

// 打开文档
document.open { success in
    if success {
        print("文档打开成功")
        // 可以开始使用文档
    } else {
        print("文档打开失败")
    }
}

// 修改文档
document.text = "新内容"

// 手动保存文档
document.save(to: documentURL, for: .forOverwriting) { success in
    if success {
        print("文档保存成功")
    } else {
        print("文档保存失败")
    }
}

// 关闭文档
document.close { success in
    if success {
        print("文档关闭成功")
    } else {
        print("文档关闭失败")
    }
}

// 自动保存
document.autosave { success in
    print("自动保存\(success ? "成功" : "失败")")
}
```

## 文档浏览器

`UIDocumentBrowserViewController` 是 iOS 提供的文档浏览和管理界面，让用户可以浏览、打开、移动和删除文档。

### 实现文档浏览器

```swift
// 在 AppDelegate 中
func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
    window = UIWindow(frame: UIScreen.main.bounds)
    
    // 创建文档浏览器控制器
    let documentBrowser = UIDocumentBrowserViewController(forOpeningFilesWithContentTypes: ["com.example.myapp.document"])
    documentBrowser.delegate = self
    documentBrowser.allowsDocumentCreation = true
    documentBrowser.allowsPickingMultipleItems = false
    
    window?.rootViewController = documentBrowser
    window?.makeKeyAndVisible()
    
    return true
}

// 实现 UIDocumentBrowserViewControllerDelegate
extension AppDelegate: UIDocumentBrowserViewControllerDelegate {
    // 当用户选择了一个文档
    func documentBrowser(_ controller: UIDocumentBrowserViewController, didPickDocumentsAt documentURLs: [URL]) {
        guard let sourceURL = documentURLs.first else { return }
        
        // 打开文档
        let documentViewController = DocumentViewController()
        documentViewController.document = TextDocument(fileURL: sourceURL)
        
        controller.present(documentViewController, animated: true)
    }
    
    // 当用户创建新文档
    func documentBrowser(_ controller: UIDocumentBrowserViewController, didRequestDocumentCreationWithHandler importHandler: @escaping (URL?, UIDocumentBrowserViewController.ImportMode) -> Void) {
        // 创建模板文档
        let templateURL = Bundle.main.url(forResource: "template", withExtension: "mydoc")!
        
        // 生成唯一文件名
        let uniqueURL = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("新文档.mydoc")
        
        // 复制模板
        try? FileManager.default.copyItem(at: templateURL, to: uniqueURL)
        
        // 导入新文档
        importHandler(uniqueURL, .move)
    }
}
```

### 文档预览

使用 `QLPreviewController` 预览文档：

```swift
import QuickLook

class DocumentListViewController: UIViewController, QLPreviewControllerDataSource {
    var documentURLs: [URL] = []
    
    func previewDocument(at index: Int) {
        let previewController = QLPreviewController()
        previewController.dataSource = self
        previewController.currentPreviewItemIndex = index
        present(previewController, animated: true)
    }
    
    // QLPreviewControllerDataSource
    func numberOfPreviewItems(in controller: QLPreviewController) -> Int {
        return documentURLs.count
    }
    
    func previewController(_ controller: QLPreviewController, previewItemAt index: Int) -> QLPreviewItem {
        return documentURLs[index] as QLPreviewItem
    }
}
```

## 文件协调

`NSFileCoordinator` 和 `NSFilePresenter` 用于协调多个进程（或多个 extension）对同一文件的访问。

### 文件协调读写

```swift
import UIKit

class CoordinatedFileAccess {
    let fileURL: URL
    let fileCoordinator = NSFileCoordinator()
    
    init(fileURL: URL) {
        self.fileURL = fileURL
    }
    
    // 协调读取
    func coordinatedRead(completion: @escaping (String?) -> Void) {
        var error: NSError?
        fileCoordinator.coordinate(readingItemAt: fileURL, options: [], error: &error) { url in
            do {
                let data = try Data(contentsOf: url)
                let content = String(data: data, encoding: .utf8)
                completion(content)
            } catch {
                print("读取错误: \(error)")
                completion(nil)
            }
        }
        
        if let error = error {
            print("协调错误: \(error)")
            completion(nil)
        }
    }
    
    // 协调写入
    func coordinatedWrite(content: String, completion: @escaping (Bool) -> Void) {
        var error: NSError?
        fileCoordinator.coordinate(writingItemAt: fileURL, options: [], error: &error) { url in
            do {
                let data = content.data(using: .utf8)!
                try data.write(to: url)
                completion(true)
            } catch {
                print("写入错误: \(error)")
                completion(false)
            }
        }
        
        if let error = error {
            print("协调错误: \(error)")
            completion(false)
        }
    }
}
```

### 文件呈现者

```swift
class DocumentPresenter: NSObject, NSFilePresenter {
    var presentedItemURL: URL?
    var presentedItemOperationQueue: OperationQueue
    
    init(documentURL: URL) {
        presentedItemURL = documentURL
        presentedItemOperationQueue = OperationQueue()
        super.init()
        
        // 注册为文件呈现者
        NSFileCoordinator.addFilePresenter(self)
    }
    
    deinit {
        NSFileCoordinator.removeFilePresenter(self)
    }
    
    // 当其他进程修改文件时
    func presentedItemDidChange() {
        print("文件被修改了")
        // 重新加载文件内容
    }
    
    // 当文件被移动时
    func presentedItemDidMove(to newURL: URL) {
        print("文件被移动到: \(newURL)")
        presentedItemURL = newURL
    }
    
    // 当文件被删除时
    func accommodatePresentedItemDeletion(completionHandler: @escaping (Error?) -> Void) {
        print("文件被删除")
        presentedItemURL = nil
        completionHandler(nil)
    }
}
```

## 版本控制

iOS 提供了内置的文档版本控制功能，让应用可以保存文档的多个版本。

### 使用文档状态

```swift
// 检查文档状态
if document.documentState.contains(.inConflict) {
    // 处理冲突
    print("文档存在冲突")
}

if document.documentState.contains(.editingDisabled) {
    // 禁用编辑功能
    print("文档禁止编辑")
}

if document.documentState.contains(.savingError) {
    // 处理保存错误
    print("文档保存错误")
}
```

### 创建文档版本

```swift
// 在重要修改前创建版本
NSFileVersion.addVersion(at: document.fileURL, withContentsAt: backupURL)

// 列出所有版本
if let versions = try? NSFileVersion.allVersions(at: document.fileURL) {
    for version in versions {
        print("版本日期: \(version.modificationDate ?? Date())")
        print("是否为当前版本: \(version.isCurrentVersion)")
    }
}

// 恢复到特定版本
if let versions = try? NSFileVersion.allVersions(at: document.fileURL),
   let oldVersion = versions.first(where: { $0.modificationDate?.timeIntervalSinceNow ?? 0 < -3600 }) {
    
    oldVersion.isResolved = false
    try? oldVersion.replaceItem(at: document.fileURL, options: [])
}
```

### 处理冲突

```swift
// 检查是否有冲突
if let versions = try? NSFileVersion.unresolvedConflictVersionsOfItem(at: document.fileURL), !versions.isEmpty {
    print("发现 \(versions.count) 个冲突版本")
    
    // 显示冲突解决 UI
    let conflictVC = ConflictResolutionViewController(versions: versions, documentURL: document.fileURL)
    present(conflictVC, animated: true)
}

// 解决冲突
func resolveConflictWithVersion(_ version: NSFileVersion) {
    do {
        // 使用选择的版本替代当前版本
        try version.replaceItem(at: document.fileURL, options: [])
        
        // 标记所有冲突为已解决
        if let versions = try? NSFileVersion.unresolvedConflictVersionsOfItem(at: document.fileURL) {
            for ver in versions {
                ver.isResolved = true
            }
        }
    } catch {
        print("解决冲突失败: \(error)")
    }
}
```

## 最佳实践

### 文档类型设计

设计良好的文档格式：

```swift
// 使用结构化的文档格式
struct MyDocumentData: Codable {
    var title: String
    var content: String
    var metadata: Metadata
    var lastModified: Date
    
    struct Metadata: Codable {
        var author: String
        var keywords: [String]
        var version: Int
    }
}

class StructuredDocument: UIDocument {
    var documentData = MyDocumentData(
        title: "",
        content: "",
        metadata: MyDocumentData.Metadata(author: "", keywords: [], version: 1),
        lastModified: Date()
    )
    
    override func contents(forType typeName: String) throws -> Any {
        documentData.lastModified = Date()
        return try JSONEncoder().encode(documentData)
    }
    
    override func load(fromContents contents: Any, ofType typeName: String?) throws {
        guard let data = contents as? Data else { throw NSError(domain: "InvalidData", code: 1) }
        documentData = try JSONDecoder().decode(MyDocumentData.self, from: data)
    }
}
```

### 增量保存

```swift
class IncrementalDocument: UIDocument {
    var text = NSMutableAttributedString()
    
    override func contents(forType typeName: String) throws -> Any {
        // 使用 NSFileWrapper 支持增量保存
        let fileWrapper = FileWrapper(directoryWithFileWrappers: [:])
        
        // 保存主要内容
        if let contentData = try? NSKeyedArchiver.archivedData(withRootObject: text, requiringSecureCoding: true) {
            let contentWrapper = FileWrapper(regularFileWithContents: contentData)
            fileWrapper.addFileWrapper(contentWrapper)
        }
        
        return fileWrapper
    }
    
    override func load(fromContents contents: Any, ofType typeName: String?) throws {
        guard let fileWrapper = contents as? FileWrapper,
              let contentWrapper = fileWrapper.fileWrappers?["content"],
              let contentData = contentWrapper.regularFileContents,
              let loadedText = try? NSKeyedUnarchiver.unarchivedObject(ofClass: NSMutableAttributedString.self, from: contentData) else {
            throw NSError(domain: "LoadError", code: 1)
        }
        
        text = loadedText
    }
}
```

### 文档缩略图

生成文档缩略图：

```swift
// 在 UIDocument 子类中
override func fileAttributesToWrite(to url: URL, for saveOperation: UIDocument.SaveOperation) throws -> [AnyHashable : Any] {
    // 获取父类属性
    var attributes = try super.fileAttributesToWrite(to: url, for: saveOperation)
    
    // 生成缩略图
    if let thumbnailImage = generateThumbnail() {
        if let data = thumbnailImage.pngData() {
            let thumbnail = data as NSData
            attributes[URLResourceKey.thumbnailDictionaryKey] = [URLThumbnailDictionaryItem.NSThumbnail1024x1024SizeKey: thumbnail]
        }
    }
    
    return attributes
}

func generateThumbnail() -> UIImage? {
    // 为文档生成缩略图的代码
    let renderer = UIGraphicsImageRenderer(size: CGSize(width: 1024, height: 1024))
    return renderer.image { context in
        // 绘制缩略图内容
        UIColor.white.setFill()
        context.fill(CGRect(origin: .zero, size: CGSize(width: 1024, height: 1024)))
        
        // 示例：绘制文档标题
        let title = documentData.title
        let paragraphStyle = NSMutableParagraphStyle()
        paragraphStyle.alignment = .center
        
        let attributes: [NSAttributedString.Key: Any] = [
            .font: UIFont.systemFont(ofSize: 60, weight: .bold),
            .foregroundColor: UIColor.black,
            .paragraphStyle: paragraphStyle
        ]
        
        title.draw(in: CGRect(x: 100, y: 400, width: 824, height: 200), withAttributes: attributes)
    }
}
```

### 文档复制与导出

```swift
// 复制文档
func duplicateDocument(at sourceURL: URL, completion: @escaping (URL?) -> Void) {
    let fileName = sourceURL.deletingPathExtension().lastPathComponent
    let newFileName = fileName + " 副本"
    let newURL = sourceURL.deletingLastPathComponent().appendingPathComponent(newFileName).appendingPathExtension(sourceURL.pathExtension)
    
    let coordinator = NSFileCoordinator()
    var error: NSError?
    
    coordinator.coordinate(readingItemAt: sourceURL, options: [], writingItemAt: newURL, options: .forMoving, error: &error) { (readURL, writeURL) in
        do {
            try FileManager.default.copyItem(at: readURL, to: writeURL)
            completion(writeURL)
        } catch {
            print("复制文档失败: \(error)")
            completion(nil)
        }
    }
    
    if let error = error {
        print("文件协调失败: \(error)")
        completion(nil)
    }
}

// 导出文档
func exportDocument(_ document: UIDocument, presenter: UIViewController) {
    guard document.documentState.contains(.normal) else {
        print("文档状态异常，无法导出")
        return
    }
    
    let activityVC = UIActivityViewController(activityItems: [document.fileURL], applicationActivities: nil)
    presenter.present(activityVC, animated: true)
}
```

通过合理使用 iOS 的文档 API，可以构建强大的文档驱动型应用，为用户提供类似于桌面应用的文档管理体验。文档系统与 iCloud 深度集成，让用户可以在多设备间无缝使用文档。 