# Flutter Web与桌面 - Web与桌面平台开发

Flutter不仅可以用于移动应用开发，还能够构建Web应用和桌面应用。本文将深入探讨如何使用Flutter进行Web和桌面平台的开发，包括平台特定配置、性能优化和最佳实践。

## 目录

- [平台支持概述](#平台支持概述)
- [Flutter Web](#flutter-web)
  - [Web渲染器](#web渲染器)
  - [Web项目配置](#web项目配置)
  - [Web特定优化](#web特定优化)
  - [Web部署策略](#web部署策略)
- [Flutter桌面](#flutter桌面)
  - [Windows开发](#windows开发)
  - [macOS开发](#macos开发)
  - [Linux开发](#linux开发)
  - [桌面特定功能](#桌面特定功能)
- [跨平台适配](#跨平台适配)
  - [自适应布局](#自适应布局)
  - [平台特定代码](#平台特定代码)
  - [插件适配](#插件适配)
- [性能优化](#性能优化)
- [测试策略](#测试策略)
- [构建与发布](#构建与发布)
- [真实案例分析](#真实案例分析)

## 平台支持概述

Flutter的多平台支持已经成熟，除了iOS和Android外，目前稳定支持的平台包括：

- **Web**：通过HTML、CSS和JavaScript运行Flutter应用
- **Windows**：适用于Windows 7及更高版本
- **macOS**：适用于macOS 10.14 Mojave及更高版本
- **Linux**：支持各种Linux发行版，如Ubuntu、Debian等

多平台支持的开启过程：

```bash
# 检查Flutter版本和支持的平台
flutter --version
flutter devices

# 启用Web支持（较新版本默认已启用）
flutter config --enable-web

# 启用Windows支持
flutter config --enable-windows-desktop

# 启用macOS支持
flutter config --enable-macos-desktop

# 启用Linux支持
flutter config --enable-linux-desktop
```

## Flutter Web

### Web渲染器

Flutter Web支持两种渲染器：

1. **HTML渲染器**：
   - 使用HTML元素、CSS和Canvas API
   - 更好的文本渲染和SEO表现
   - 文件大小更小
   - 适合文字内容丰富的应用

2. **CanvasKit渲染器**：
   - 使用WebGL和Skia（Flutter的渲染引擎）
   - 与移动和桌面版本的渲染行为一致
   - 性能更好，特别是对于复杂动画
   - 适合图形密集型应用

选择渲染器：

```bash
# 使用HTML渲染器运行
flutter run -d chrome --web-renderer html

# 使用CanvasKit渲染器运行
flutter run -d chrome --web-renderer canvaskit

# 使用自动模式（根据设备能力选择）
flutter run -d chrome --web-renderer auto
```

也可以在`web/index.html`中设置默认渲染器：

```html
<script>
  // 设置默认渲染器为HTML
  window.flutterWebRenderer = "html";
  // 或设置为CanvasKit
  // window.flutterWebRenderer = "canvaskit";
</script>
```

### Web项目配置

#### Web入口文件配置

Web版Flutter应用的主要入口是`web/index.html`文件，可以在其中添加Web特定的配置：

```html
<!DOCTYPE html>
<html>
<head>
  <!-- 设置元标签和SEO信息 -->
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Flutter Web应用示例">
  <meta name="keywords" content="Flutter, Web, 应用">
  
  <!-- 添加网站图标 -->
  <link rel="icon" type="image/png" href="favicon.png"/>
  
  <!-- 添加外部CSS -->
  <link rel="stylesheet" type="text/css" href="styles.css">
  
  <title>Flutter Web应用</title>
</head>
<body>
  <!-- 可以在这里添加加载动画 -->
  <div id="loading">
    <div class="spinner"></div>
  </div>
  
  <script>
    // 设置Flutter Web配置
    window.flutterWebRenderer = "auto";
    
    // 添加自定义JavaScript
    window.addEventListener('load', function() {
      document.getElementById('loading').style.display = 'none';
    });
  </script>
  
  <script src="flutter.js" defer></script>
  <script>
    window.addEventListener('load', function() {
      _flutter.loader.loadEntrypoint({
        serviceWorker: {
          serviceWorkerVersion: serviceWorkerVersion,
        },
        onEntrypointLoaded: function(engineInitializer) {
          engineInitializer.initializeEngine().then(function(appRunner) {
            appRunner.runApp();
          });
        }
      });
    });
  </script>
</body>
</html>
```

#### 添加Web资源

在`web/`目录中可以添加各种Web特定资源：

- `web/icons/` - PWA图标
- `web/manifest.json` - PWA配置
- `web/assets/` - Web专用资产

示例`manifest.json`文件：

```json
{
  "name": "Flutter Web应用",
  "short_name": "Flutter",
  "start_url": ".",
  "display": "standalone",
  "background_color": "#0175C2",
  "theme_color": "#0175C2",
  "description": "Flutter Web应用示例",
  "orientation": "portrait-primary",
  "prefer_related_applications": false,
  "icons": [
    {
      "src": "icons/Icon-192.png",
      "sizes": "192x192",
      "type": "image/png"
    },
    {
      "src": "icons/Icon-512.png",
      "sizes": "512x512",
      "type": "image/png"
    },
    {
      "src": "icons/Icon-maskable-192.png",
      "sizes": "192x192",
      "type": "image/png",
      "purpose": "maskable"
    },
    {
      "src": "icons/Icon-maskable-512.png",
      "sizes": "512x512",
      "type": "image/png",
      "purpose": "maskable"
    }
  ]
}
```

### Web特定优化

#### 1. 初始加载优化

Flutter Web应用初始加载时需要下载较大的JavaScript资产，可以通过以下方法优化：

```html
<!-- 在index.html中添加加载提示 -->
<style>
  .loading {
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh;
  }
  .spinner {
    width: 40px;
    height: 40px;
    border: 4px solid #f3f3f3;
    border-top: 4px solid #3498db;
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }
  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }
</style>
<div class="loading">
  <div class="spinner"></div>
</div>
```

#### 2. 代码分割

使用延迟加载减小初始包大小：

```dart
// 延迟加载一个库
import 'package:heavy_library/heavy_library.dart' deferred as heavy;

// 使用时先加载
Future<void> loadLibraryAndUse() async {
  await heavy.loadLibrary();
  heavy.someFunction();
}
```

#### 3. Web路由优化

使用URL策略配置更友好的路由：

```dart
// main.dart
import 'package:flutter_web_plugins/flutter_web_plugins.dart';

void main() {
  // 使用路径URL策略，而不是默认的哈希策略
  setUrlStrategy(PathUrlStrategy());
  runApp(MyApp());
}
```

使用`go_router`实现Web路由：

```dart
import 'package:go_router/go_router.dart';

final router = GoRouter(
  routes: [
    GoRoute(
      path: '/',
      builder: (context, state) => HomePage(),
    ),
    GoRoute(
      path: '/products/:id',
      builder: (context, state) {
        final productId = state.params['id'];
        return ProductPage(id: productId);
      },
    ),
  ],
);

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp.router(
      routerConfig: router,
      title: 'Flutter Web示例',
      // 其他配置...
    );
  }
}
```

#### 4. 浏览器API集成

Flutter Web可以与浏览器API集成：

```dart
import 'dart:html' as html;

void openNewTab(String url) {
  html.window.open(url, '_blank');
}

void copyToClipboard(String text) {
  html.document.execCommand('copy');
  // 或使用较新的剪贴板API
  html.window.navigator.clipboard?.writeText(text);
}

// 检测浏览器
bool isMobileBrowser() {
  final userAgent = html.window.navigator.userAgent.toLowerCase();
  return userAgent.contains('mobile');
}

// 本地存储
void saveToLocalStorage(String key, String value) {
  html.window.localStorage[key] = value;
}

String? getFromLocalStorage(String key) {
  return html.window.localStorage[key];
}
```

#### 5. SEO优化

针对搜索引擎优化Flutter Web应用：

```dart
// 使用js_interop添加动态元数据
import 'dart:js' as js;

void updateMetaTags({required String title, required String description}) {
  js.context.callMethod('updateMetaTags', [title, description]);
}

// 在web/index.html中添加对应的JavaScript函数
```

```html
<!-- 在web/index.html中 -->
<script>
  function updateMetaTags(title, description) {
    document.title = title;
    
    // 更新描述
    let metaDescription = document.querySelector('meta[name="description"]');
    if (!metaDescription) {
      metaDescription = document.createElement('meta');
      metaDescription.name = 'description';
      document.head.appendChild(metaDescription);
    }
    metaDescription.content = description;
  }
</script>
```

### Web部署策略

#### 1. 构建Web应用

```bash
# 使用HTML渲染器构建
flutter build web --web-renderer html

# 使用CanvasKit渲染器构建
flutter build web --web-renderer canvaskit

# 使用自动选择渲染器构建
flutter build web --web-renderer auto

# 压缩级别设置
flutter build web --dart-define=FLUTTER_WEB_USE_SKIA=true --release
```

#### 2. 静态网站托管

构建后的应用位于`build/web/`目录中，可以部署到各种静态托管服务：

- **Firebase Hosting**:
  ```bash
  npm install -g firebase-tools
  firebase login
  firebase init hosting
  firebase deploy
  ```

- **GitHub Pages**:
  ```bash
  # 添加构建文件到git
  git add build/web -f
  git commit -m "Add web build"
  git subtree push --prefix build/web origin gh-pages
  ```

- **Netlify/Vercel**:
  - 将构建命令设置为`flutter build web`
  - 发布目录设置为`build/web`

#### 3. 配置服务器重定向

为了支持Flutter路由，需要配置服务器将所有请求重定向到`index.html`：

- **Apache (.htaccess)**:
  ```
  RewriteEngine On
  RewriteBase /
  RewriteRule ^index\.html$ - [L]
  RewriteCond %{REQUEST_FILENAME} !-f
  RewriteCond %{REQUEST_FILENAME} !-d
  RewriteRule . /index.html [L]
  ```

- **Nginx**:
  ```
  location / {
    try_files $uri $uri/ /index.html;
  }
  ```

- **Firebase Hosting (firebase.json)**:
  ```json
  {
    "hosting": {
      "public": "build/web",
      "rewrites": [
        {
          "source": "**",
          "destination": "/index.html"
        }
      ]
    }
  }
  ```

## Flutter桌面

Flutter支持在Windows、macOS和Linux平台上构建原生桌面应用程序。桌面应用具有与移动应用不同的使用场景和交互模式，需要特别考虑窗口管理、键盘快捷键、文件系统交互等方面。

### Windows开发

#### 环境配置

在Windows上开发Flutter桌面应用需要满足以下要求：

- Windows 10或更高版本（最好是64位）
- Git for Windows
- Flutter SDK
- Visual Studio（包含C++桌面开发工作负载）

启用Windows支持：

```bash
flutter config --enable-windows-desktop
flutter devices  # 应该能看到Windows设备
```

#### 创建和运行Windows应用

```bash
# 创建新项目时启用桌面支持
flutter create --platforms=windows,android,ios my_desktop_app

# 或向现有项目添加Windows平台
cd existing_flutter_project
flutter create --platforms=windows .

# 运行Windows应用
flutter run -d windows
```

#### Windows特定功能

1. **窗口标题栏自定义**

```dart
import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  // 初始化窗口管理器
  await windowManager.ensureInitialized();

  // 设置窗口属性
  WindowOptions windowOptions = WindowOptions(
    size: Size(800, 600),
    center: true,
    backgroundColor: Colors.transparent,
    skipTaskbar: false,
    titleBarStyle: TitleBarStyle.hidden, // 隐藏默认标题栏
  );
  
  windowManager.waitUntilReadyToShow(windowOptions, () async {
    await windowManager.show();
    await windowManager.focus();
  });
  
  runApp(MyApp());
}

// 自定义标题栏组件
class CustomTitleBar extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onPanStart: (_) async {
        await windowManager.startDragging();
      },
      child: Container(
        height: 32,
        color: Colors.blueGrey,
        child: Row(
          children: [
            SizedBox(width: 16),
            Text('我的Flutter桌面应用', style: TextStyle(color: Colors.white)),
            Spacer(),
            IconButton(
              icon: Icon(Icons.minimize, color: Colors.white, size: 16),
              onPressed: () async {
                await windowManager.minimize();
              },
            ),
            IconButton(
              icon: Icon(Icons.crop_square, color: Colors.white, size: 16),
              onPressed: () async {
                if (await windowManager.isMaximized()) {
                  await windowManager.restore();
                } else {
                  await windowManager.maximize();
                }
              },
            ),
            IconButton(
              icon: Icon(Icons.close, color: Colors.white, size: 16),
              onPressed: () async {
                await windowManager.close();
              },
            ),
          ],
        ),
      ),
    );
  }
}
```

2. **文件系统操作**

```dart
import 'package:file_picker/file_picker.dart';
import 'package:path_provider/path_provider.dart';
import 'dart:io';

// 选择文件
Future<void> pickFile() async {
  FilePickerResult? result = await FilePicker.platform.pickFiles();
  
  if (result != null) {
    File file = File(result.files.single.path!);
    // 处理文件...
  }
}

// 保存文件
Future<void> saveFile(String content) async {
  String? outputFile = await FilePicker.platform.saveFile(
    dialogTitle: '保存文件',
    fileName: 'document.txt',
  );
  
  if (outputFile != null) {
    final File file = File(outputFile);
    await file.writeAsString(content);
  }
}

// 访问应用文档目录
Future<Directory> getAppDirectory() async {
  final directory = await getApplicationDocumentsDirectory();
  return directory;
}
```

3. **系统托盘图标**

使用`system_tray`包实现系统托盘功能：

```dart
import 'package:system_tray/system_tray.dart';
import 'package:flutter/services.dart';
import 'dart:io';

Future<void> initSystemTray() async {
  final SystemTray systemTray = SystemTray();
  
  // 设置系统托盘图标
  await systemTray.initSystemTray(
    title: "系统托盘示例",
    iconPath: Platform.isWindows 
        ? 'assets/app_icon.ico' 
        : 'assets/app_icon.png',
  );
  
  // 创建系统托盘菜单
  final Menu menu = Menu();
  await menu.buildFrom([
    MenuItemLabel(label: '显示', onClicked: (menuItem) => windowManager.show()),
    MenuItemLabel(label: '隐藏', onClicked: (menuItem) => windowManager.hide()),
    MenuSeparator(),
    MenuItemLabel(
      label: '退出',
      onClicked: (menuItem) => windowManager.close(),
    ),
  ]);
  
  // 设置托盘菜单
  await systemTray.setContextMenu(menu);
  
  // 注册托盘事件
  systemTray.registerSystemTrayEventHandler((eventName) {
    if (eventName == kSystemTrayEventClick) {
      Platform.isWindows ? windowManager.show() : systemTray.popUpContextMenu();
    } else if (eventName == kSystemTrayEventRightClick) {
      systemTray.popUpContextMenu();
    }
  });
}
```

4. **快捷键支持**

使用`hotkey_manager`包实现全局快捷键：

```dart
import 'package:hotkey_manager/hotkey_manager.dart';

Future<void> setupHotkeys() async {
  await hotKeyManager.unregisterAll();
  
  // 注册Ctrl+Shift+A快捷键
  HotKey showAppHotKey = HotKey(
    key: KeyCode.keyA,
    modifiers: [KeyModifier.control, KeyModifier.shift],
    scope: HotKeyScope.system, // 系统范围内有效
  );
  
  await hotKeyManager.register(
    showAppHotKey,
    keyDownHandler: (hotKey) {
      windowManager.show();
      windowManager.focus();
    },
  );
}
```

#### Windows打包与分发

1. **创建Windows安装包**

```bash
# 构建Windows应用
flutter build windows --release

# 使用InnoSetup创建安装程序
# (安装InnoSetup后) 创建一个脚本文件setup.iss：
```

`setup.iss`示例：

```
[Setup]
AppName=我的Flutter桌面应用
AppVersion=1.0.0
DefaultDirName={pf}\我的Flutter桌面应用
DefaultGroupName=我的Flutter桌面应用
UninstallDisplayIcon={app}\my_desktop_app.exe
OutputDir=installer
OutputBaseFilename=my_desktop_app_setup

[Files]
Source: "build\windows\runner\Release\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs

[Icons]
Name: "{group}\我的Flutter桌面应用"; Filename: "{app}\my_desktop_app.exe"
Name: "{commondesktop}\我的Flutter桌面应用"; Filename: "{app}\my_desktop_app.exe"
```

2. **MSIX打包**

使用`msix`包进行Windows应用商店打包：

```yaml
# pubspec.yaml
dependencies:
  msix: ^3.7.0

# 添加msix配置
msix_config:
  display_name: 我的Flutter桌面应用
  publisher_display_name: 我的公司
  identity_name: company.mydesktopapp
  publisher: CN=ABCDEFG-1234-5678-ABCD-1234ABCD1234
  msix_version: 1.0.0.0
  logo_path: assets/logo.png
  capabilities: internetClient
```

```bash
# 生成MSIX包
flutter pub run msix:create
```

### macOS开发

#### 环境配置

在macOS上开发Flutter桌面应用需要：

- macOS 10.14 Mojave或更高版本
- Xcode 11或更高版本
- CocoaPods
- Flutter SDK

启用macOS支持：

```bash
flutter config --enable-macos-desktop
flutter devices  # 应该能看到macOS设备
```

#### 创建和运行macOS应用

```bash
# 创建新项目时启用桌面支持
flutter create --platforms=macos,android,ios my_desktop_app

# 或向现有项目添加macOS平台
cd existing_flutter_project
flutter create --platforms=macos .

# 运行macOS应用
flutter run -d macos
```

#### macOS特定功能

1. **菜单栏定制**

```dart
import 'package:macos_ui/macos_ui.dart';

void main() {
  runApp(MacosApp(
    theme: MacosThemeData.light(),
    darkTheme: MacosThemeData.dark(),
    themeMode: ThemeMode.system,
    home: MyHomePage(),
  ));
}

class MyHomePage extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MacosWindow(
      sidebar: Sidebar(
        minWidth: 200,
        builder: (context, scrollController) {
          return SidebarItems(
            currentIndex: 0,
            onChanged: (i) => print('选择了: $i'),
            items: [
              SidebarItem(
                leading: MacosIcon(CupertinoIcons.home),
                label: Text('首页'),
              ),
              SidebarItem(
                leading: MacosIcon(CupertinoIcons.settings),
                label: Text('设置'),
              ),
            ],
          );
        },
      ),
      child: MacosScaffold(
        toolBar: ToolBar(
          title: Text('我的macOS应用'),
          actions: [
            ToolBarIconButton(
              label: '添加',
              icon: MacosIcon(CupertinoIcons.add),
              onPressed: () {},
              showLabel: false,
            ),
          ],
        ),
        children: [
          ContentArea(
            builder: (context, scrollController) {
              return Center(child: Text('macOS应用内容'));
            },
          ),
        ],
      ),
    );
  }
}
```

2. **Touch Bar支持**

```dart
import 'package:touchbar/touchbar.dart';

void setupTouchBar() {
  TouchBar touchBar = TouchBar([
    TouchBarLabel('Flutter Touch Bar示例'),
    TouchBarScrubber(
      children: ['选项1', '选项2', '选项3'].map((e) => Text(e)).toList(),
      onSelect: (index) => print('选择了: $index'),
    ),
    TouchBarButton(
      label: '按钮',
      backgroundColor: Colors.blue,
      onPress: () => print('按下Touch Bar按钮'),
    ),
    TouchBarSlider(
      value: 50,
      min: 0,
      max: 100,
      onChange: (value) => print('滑块值: $value'),
    ),
  ]);
  
  setTouchBar(touchBar);
}
```

3. **原生对话框**

```dart
import 'package:native_context_menu/native_context_menu.dart';
import 'package:macos_ui/macos_ui.dart';

// 显示上下文菜单
void showContextMenu(BuildContext context, TapDownDetails details) {
  showContextMenu(
    context: context,
    position: details.globalPosition,
    items: [
      MenuItem(title: '剪切', onSelected: () {}),
      MenuItem(title: '复制', onSelected: () {}),
      MenuItem(title: '粘贴', onSelected: () {}),
      MenuItem.separator(),
      MenuItem(title: '其他操作', onSelected: () {}),
    ],
  );
}

// 显示原生对话框
void showNativeDialog() {
  showMacosAlertDialog(
    context: context,
    builder: (_) => MacosAlertDialog(
      appIcon: FlutterLogo(size: 56),
      title: Text('确认操作'),
      message: Text('您确定要执行此操作吗？'),
      primaryButton: PushButton(
        buttonSize: ButtonSize.large,
        onPressed: () {
          Navigator.of(context).pop();
          // 执行确认操作
        },
        child: Text('确认'),
      ),
      secondaryButton: PushButton(
        buttonSize: ButtonSize.large,
        onPressed: () => Navigator.of(context).pop(),
        child: Text('取消'),
      ),
    ),
  );
}
```

#### macOS打包与分发

1. **创建macOS应用包**

```bash
# 构建macOS应用
flutter build macos --release

# 生成位置: build/macos/Build/Products/Release/my_desktop_app.app
```

2. **创建DMG安装包**

使用`create-dmg`工具：

```bash
# 安装create-dmg
brew install create-dmg

# 创建DMG
create-dmg \
  --volname "我的Flutter桌面应用" \
  --volicon "assets/app_icon.icns" \
  --window-pos 200 120 \
  --window-size 600 400 \
  --icon-size 100 \
  --icon "my_desktop_app.app" 175 190 \
  --app-drop-link 425 190 \
  "我的Flutter桌面应用.dmg" \
  "build/macos/Build/Products/Release/my_desktop_app.app"
```

3. **公证与签名**

```bash
# 签名应用
codesign --deep --force --verify --verbose --sign "Developer ID Application: Your Name (YOUR_ID)" "build/macos/Build/Products/Release/my_desktop_app.app"

# 创建ZIP归档以进行公证
ditto -c -k --keepParent "build/macos/Build/Products/Release/my_desktop_app.app" "my_desktop_app.zip"

# 提交公证
xcrun altool --notarize-app --primary-bundle-id "com.example.myDesktopApp" --username "your.email@example.com" --password "@keychain:AC_PASSWORD" --file "my_desktop_app.zip"

# 查询公证状态
xcrun altool --notarization-info YOUR_REQUEST_ID --username "your.email@example.com" --password "@keychain:AC_PASSWORD"

# 在应用中添加公证标记
xcrun stapler staple "build/macos/Build/Products/Release/my_desktop_app.app"
```

### Linux开发

#### 环境配置

在Linux上开发Flutter桌面应用需要：

- Ubuntu 20.04或更高版本（或其他支持的Linux发行版）
- 必要的库：`libgtk-3-dev`、`ninja-build`等
- Flutter SDK

安装依赖：

```bash
sudo apt-get update
sudo apt-get install clang cmake ninja-build pkg-config libgtk-3-dev liblzma-dev libstdc++-12-dev
```

启用Linux支持：

```bash
flutter config --enable-linux-desktop
flutter devices  # 应该能看到Linux设备
```

#### 创建和运行Linux应用

```bash
# 创建新项目时启用桌面支持
flutter create --platforms=linux,android,ios my_desktop_app

# 或向现有项目添加Linux平台
cd existing_flutter_project
flutter create --platforms=linux .

# 运行Linux应用
flutter run -d linux
```

#### Linux特定功能

1. **GTK集成**

```dart
import 'package:flutter/material.dart';
import 'package:flutter_acrylic/flutter_acrylic.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  // 在Linux上初始化窗口效果
  await Window.initialize();
  await Window.setEffect(effect: WindowEffect.transparent);
  
  runApp(MyApp());
}
```

2. **Linux桌面通知**

```dart
import 'package:desktop_notifications/desktop_notifications.dart';

void showLinuxNotification() {
  final client = NotificationsClient();
  client.notify(
    'Flutter桌面通知',
    body: '这是一条来自Flutter应用的通知',
    icon: 'app_icon',
    appName: '我的Flutter应用',
    actions: [
      NotificationAction('default', '确认'),
      NotificationAction('cancel', '取消'),
    ],
    onActionInvoked: (actionKey) {
      if (actionKey == 'default') {
        print('用户点击了确认');
      }
    },
  );
  
  client.close();
}
```

3. **DBus与系统服务交互**

```dart
import 'package:dbus/dbus.dart';

Future<void> checkNetworkStatus() async {
  final client = DBusClient.system();
  
  try {
    final object = DBusRemoteObject(
      client,
      name: 'org.freedesktop.NetworkManager',
      path: DBusObjectPath('/org/freedesktop/NetworkManager'),
    );
    
    final result = await object.getProperty(
      'org.freedesktop.NetworkManager',
      'NetworkingEnabled',
    );
    
    final enabled = result.asVariant().asBoolean();
    print('网络状态: ${enabled ? "已连接" : "未连接"}');
  } finally {
    client.close();
  }
}
```

#### Linux打包与分发

1. **创建Debian包（.deb）**

```bash
# 构建Linux应用
flutter build linux --release

# 安装打包工具
sudo apt-get install ruby-dev build-essential
sudo gem install fpm

# 创建Debian包
fpm -s dir -t deb -n "my-desktop-app" -v "1.0.0" \
  --description "My Flutter Desktop App" \
  --vendor "Your Company" \
  --license "MIT" \
  -d "libgtk-3-0" \
  -d "libblkid1" \
  -d "liblzma5" \
  ./build/linux/x64/release/bundle=/opt/my-desktop-app \
  ./assets/desktop/my-desktop-app.desktop=/usr/share/applications/my-desktop-app.desktop \
  ./assets/icons/app_icon.png=/usr/share/icons/hicolor/128x128/apps/my-desktop-app.png
```

2. **创建AppImage**

```bash
# 安装工具
wget -O linuxdeploy-x86_64.AppImage https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage
chmod +x linuxdeploy-x86_64.AppImage

# 准备AppDir结构
mkdir -p AppDir/usr/{bin,share/applications,share/icons/hicolor/256x256/apps}
cp -r build/linux/x64/release/bundle/* AppDir/usr/bin/
cp assets/desktop/my-desktop-app.desktop AppDir/usr/share/applications/
cp assets/icons/app_icon.png AppDir/usr/share/icons/hicolor/256x256/apps/my-desktop-app.png

# 生成AppImage
./linuxdeploy-x86_64.AppImage --appdir AppDir --output appimage
```

3. **创建Snap包**

创建`snap/snapcraft.yaml`文件：

```yaml
name: my-desktop-app
version: '1.0.0'
summary: My Flutter Desktop App
description: |
  A Flutter desktop application for Linux.
grade: stable
confinement: strict
base: core18

apps:
  my-desktop-app:
    command: my_desktop_app
    extensions: [gnome-3-28]
    plugs:
      - network
      - home
      - desktop
      - desktop-legacy
      - wayland
      - x11

parts:
  my-desktop-app:
    source: build/linux/x64/release/bundle/
    plugin: dump
    organize:
      '*': usr/bin/
```

然后构建Snap包：

```bash
snapcraft
```

### 桌面特定功能

以下是适用于所有桌面平台的通用功能：

#### 1. 拖放功能

```dart
import 'package:desktop_drop/desktop_drop.dart';
import 'package:flutter/material.dart';
import 'dart:io';

class DropTargetWidget extends StatefulWidget {
  @override
  _DropTargetWidgetState createState() => _DropTargetWidgetState();
}

class _DropTargetWidgetState extends State<DropTargetWidget> {
  bool _dragging = false;
  List<String> _filePaths = [];

  @override
  Widget build(BuildContext context) {
    return DropTarget(
      onDragDone: (detail) {
        setState(() {
          _filePaths = detail.files.map((e) => e.path).toList();
        });
        // 处理拖放的文件
        for (final file in detail.files) {
          print('拖放文件: ${file.path}');
          // 处理文件...
        }
      },
      onDragEntered: (detail) {
        setState(() {
          _dragging = true;
        });
      },
      onDragExited: (detail) {
        setState(() {
          _dragging = false;
        });
      },
      child: Container(
        height: 200,
        width: double.infinity,
        color: _dragging ? Colors.blue.withOpacity(0.4) : Colors.grey.withOpacity(0.2),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.upload_file, size: 48),
            SizedBox(height: 16),
            Text(_filePaths.isEmpty
                ? '拖放文件到此区域'
                : '已拖放${_filePaths.length}个文件'),
            if (_filePaths.isNotEmpty)
              Expanded(
                child: ListView.builder(
                  itemCount: _filePaths.length,
                  itemBuilder: (context, index) {
                    return ListTile(
                      title: Text(_filePaths[index]),
                    );
                  },
                ),
              ),
          ],
        ),
      ),
    );
  }
}
```

#### 2. 剪贴板操作

```dart
import 'package:flutter/services.dart';
import 'package:flutter/material.dart';
import 'dart:typed_data';

// 复制文本到剪贴板
Future<void> copyToClipboard(String text) async {
  await Clipboard.setData(ClipboardData(text: text));
}

// 从剪贴板获取文本
Future<String?> getClipboardText() async {
  final data = await Clipboard.getData(Clipboard.kTextPlain);
  return data?.text;
}

// 复制图像到剪贴板（仅适用于macOS和Windows）
Future<void> copyImageToClipboard(Uint8List imageBytes) async {
  // 需要使用平台特定代码实现
  final MethodChannel platform = MethodChannel('clipboard/image');
  try {
    await platform.invokeMethod('copyImage', {'image': imageBytes});
  } catch (e) {
    print('复制图像到剪贴板失败: $e');
  }
}
```

#### 3. 多窗口支持

使用`multi_window`包实现多窗口支持：

```dart
import 'package:multi_window/multi_window.dart';
import 'package:flutter/material.dart';

void main() {
  runApp(MyApp());
}

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: HomeScreen(),
    );
  }
}

class HomeScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('主窗口')),
      body: Center(
        child: ElevatedButton(
          onPressed: () => _createNewWindow(),
          child: Text('创建新窗口'),
        ),
      ),
    );
  }

  Future<void> _createNewWindow() async {
    final windowId = await MultiWindow.createWindow(
      '''
      import 'package:flutter/material.dart';
      import 'package:multi_window/multi_window.dart';

      void main() {
        runApp(MaterialApp(
          home: Scaffold(
            appBar: AppBar(title: Text('新窗口')),
            body: Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Text('这是一个新窗口'),
                  SizedBox(height: 16),
                  ElevatedButton(
                    onPressed: () {
                      MultiWindow.sendMessage({'action': 'CLOSE'}, 0);
                      MultiWindow.close();
                    },
                    child: Text('关闭窗口'),
                  ),
                ],
              ),
            ),
          ),
        ));
      }
      ''',
    );
    
    MultiWindow.setWindowTitle(windowId, '新窗口');
    MultiWindow.setWindowSize(windowId, Size(400, 300));
    MultiWindow.center(windowId);
    
    // 监听窗口消息
    MultiWindow.addListener((id, message) {
      if (message['action'] == 'CLOSE') {
        print('窗口 $id 已关闭');
      }
    });
  }
}
```

#### 4. 应用配置存储

```dart
import 'package:path_provider/path_provider.dart';
import 'dart:io';
import 'dart:convert';

class AppSettings {
  bool darkMode;
  String language;
  Map<String, dynamic> customSettings;
  
  AppSettings({
    this.darkMode = false,
    this.language = 'zh-CN',
    this.customSettings = const {},
  });
  
  factory AppSettings.fromJson(Map<String, dynamic> json) {
    return AppSettings(
      darkMode: json['darkMode'] ?? false,
      language: json['language'] ?? 'zh-CN',
      customSettings: json['customSettings'] ?? {},
    );
  }
  
  Map<String, dynamic> toJson() {
    return {
      'darkMode': darkMode,
      'language': language,
      'customSettings': customSettings,
    };
  }
  
  static Future<File> get _settingsFile async {
    final directory = await getApplicationSupportDirectory();
    return File('${directory.path}/settings.json');
  }
  
  static Future<AppSettings> load() async {
    try {
      final file = await _settingsFile;
      if (await file.exists()) {
        final content = await file.readAsString();
        return AppSettings.fromJson(jsonDecode(content));
      }
    } catch (e) {
      print('加载设置失败: $e');
    }
    return AppSettings();
  }
  
  Future<void> save() async {
    try {
      final file = await _settingsFile;
      await file.writeAsString(jsonEncode(toJson()));
    } catch (e) {
      print('保存设置失败: $e');
    }
  }
}
```

## 跨平台适配

开发Web和桌面应用时，需要考虑不同平台的特性和限制，以提供一致且原生化的用户体验。

### 自适应布局

#### 1. 响应式布局策略

```dart
import 'package:flutter/material.dart';

class ResponsiveLayout extends StatelessWidget {
  final Widget mobile;
  final Widget? tablet;
  final Widget desktop;

  const ResponsiveLayout({
    required this.mobile,
    this.tablet,
    required this.desktop,
  });

  // 设备类型判断
  static bool isMobile(BuildContext context) =>
      MediaQuery.of(context).size.width < 650;

  static bool isTablet(BuildContext context) =>
      MediaQuery.of(context).size.width >= 650 &&
      MediaQuery.of(context).size.width < 1100;

  static bool isDesktop(BuildContext context) =>
      MediaQuery.of(context).size.width >= 1100;

  @override
  Widget build(BuildContext context) {
    if (isDesktop(context)) {
      return desktop;
    } else if (isTablet(context) && tablet != null) {
      return tablet!;
    } else {
      return mobile;
    }
  }
}

// 使用示例
class MyResponsiveApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return ResponsiveLayout(
      mobile: MobileLayout(),
      tablet: TabletLayout(),
      desktop: DesktopLayout(),
    );
  }
}
```

#### 2. 适配不同输入方式

```dart
import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';

class AdaptiveInput extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    // 判断平台类型
    final bool isDesktopOrWeb = kIsWeb ||
        defaultTargetPlatform == TargetPlatform.linux ||
        defaultTargetPlatform == TargetPlatform.macOS ||
        defaultTargetPlatform == TargetPlatform.windows;

    return Scaffold(
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            // 鼠标悬停效果（桌面和Web）
            if (isDesktopOrWeb)
              MouseRegion(
                cursor: SystemMouseCursors.click,
                child: _buildInteractiveWidget(),
                onHover: (_) => print('鼠标悬停'),
              )
            else
              _buildInteractiveWidget(), // 移动设备使用普通组件
            
            SizedBox(height: 20),
            
            // 适配键盘快捷键（桌面和Web）
            if (isDesktopOrWeb)
              Focus(
                autofocus: true,
                onKeyEvent: (node, event) {
                  if (event is KeyDownEvent) {
                    if (event.logicalKey == LogicalKeyboardKey.keyS && 
                        event.isControlPressed) {
                      print('按下Ctrl+S');
                      return KeyEventResult.handled;
                    }
                  }
                  return KeyEventResult.ignored;
                },
                child: Container(
                  padding: EdgeInsets.all(16),
                  color: Colors.grey.shade200,
                  child: Text('此区域可响应键盘事件，试试Ctrl+S'),
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildInteractiveWidget() {
    return Container(
      width: 200,
      height: 60,
      decoration: BoxDecoration(
        color: Colors.blue,
        borderRadius: BorderRadius.circular(8),
      ),
      alignment: Alignment.center,
      child: Text(
        '交互组件',
        style: TextStyle(color: Colors.white, fontSize: 16),
      ),
    );
  }
}
```

### 平台特定代码

#### 1. 条件导入

使用条件导入为不同平台提供专用实现：

```dart
// web_utils.dart (仅在Web平台上使用)
import 'stub_utils.dart'
    if (dart.library.html) 'web_utils_impl.dart';

// web_utils_impl.dart (Web平台实现)
import 'dart:html' as html;

void openUrl(String url) {
  html.window.open(url, '_blank');
}

// stub_utils.dart (非Web平台的存根实现)
void openUrl(String url) {
  // 提供非Web平台的替代实现或抛出异常
  throw UnsupportedError('不支持在当前平台使用此功能');
}

// desktop_utils.dart (桌面平台特定代码)
import 'dart:io' show Platform;
import 'package:flutter/foundation.dart' show kIsWeb;

class PlatformUtils {
  static bool get isDesktop => !kIsWeb && (Platform.isWindows || 
      Platform.isMacOS || Platform.isLinux);
      
  static bool get isWindows => !kIsWeb && Platform.isWindows;
  static bool get isMacOS => !kIsWeb && Platform.isMacOS;
  static bool get isLinux => !kIsWeb && Platform.isLinux;
}
```

#### 2. 平台检测与功能降级

```dart
import 'package:flutter/foundation.dart' show kIsWeb;
import 'dart:io' show Platform;

class PlatformFeatures {
  // 检查平台
  static bool get isDesktopPlatform => !kIsWeb && 
      (Platform.isWindows || Platform.isMacOS || Platform.isLinux);
  static bool get isWebPlatform => kIsWeb;
  static bool get isMobilePlatform => !kIsWeb && 
      (Platform.isAndroid || Platform.isIOS);

  // 根据平台提供适当的功能
  static Widget getFilePickerButton(Function(File?) onFilePicked) {
    if (isWebPlatform) {
      return WebFilePickerButton(onFilePicked);
    } else if (isDesktopPlatform) {
      return DesktopFilePickerButton(onFilePicked);
    } else {
      return MobileFilePickerButton(onFilePicked);
    }
  }

  // 功能降级策略
  static Widget getAdvancedFeature() {
    if (isDesktopPlatform) {
      return FullFeaturedWidget();
    } else {
      // Web或移动平台使用简化版本
      return SimplifiedWidget();
    }
  }
}

// 使用示例
Widget buildCrossPlatformUI() {
  return Column(
    children: [
      if (PlatformFeatures.isDesktopPlatform)
        DesktopSpecificWidget()
      else if (PlatformFeatures.isWebPlatform)
        WebSpecificWidget()
      else
        MobileSpecificWidget(),
        
      // 所有平台通用部分
      CommonFeatureWidget(),
    ],
  );
}
```

### 插件适配

#### 1. 跨平台插件选择

```yaml
# pubspec.yaml
dependencies:
  # 跨平台文件选择
  file_selector: ^0.9.3  # 支持Web、桌面和移动平台
  
  # 本地存储
  shared_preferences: ^2.1.0  # 所有平台
  
  # 窗口管理（仅桌面）
  window_manager: ^0.3.2
  
  # URL启动
  url_launcher: ^6.1.10  # 所有平台
```

#### 2. 插件兼容性检查

```dart
import 'package:flutter/foundation.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';
import 'dart:io' if (dart.library.html) 'dart:html' as html;

/// 检查插件是否支持当前平台
bool isPluginSupported(String pluginName) {
  final supportMatrix = {
    'window_manager': !kIsWeb && (Platform.isWindows || 
                      Platform.isMacOS || Platform.isLinux),
    'path_provider': !kIsWeb,
    'share_plus': true, // 全平台支持
    'url_launcher': true, // 全平台支持
    // 添加更多插件...
  };
  
  return supportMatrix[pluginName] ?? false;
}

/// 平台特定功能的包装类
class PlatformService {
  static Future<void> shareContent({
    required String title,
    required String text,
    String? subject,
    List<String>? filePaths,
  }) async {
    if (kIsWeb) {
      // Web平台使用Navigator API
      try {
        final shareData = <String, dynamic>{
          'title': title,
          'text': text,
        };
        await html.window.navigator.share(shareData);
      } catch (e) {
        // 回退到复制到剪贴板
        await Clipboard.setData(ClipboardData(text: text));
      }
    } else if (Platform.isAndroid || Platform.isIOS) {
      // 移动平台使用share_plus
      await Share.share(text, subject: subject);
    } else {
      // 桌面平台回退方案
      await Clipboard.setData(ClipboardData(text: text));
    }
  }
}
```

## 性能优化

Flutter在Web和桌面平台上的性能优化策略：

### 1. Web性能优化

```dart
// 延迟加载大型组件
import 'large_component.dart' deferred as large;

class OptimizedApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: FutureBuilder(
        future: loadLibraries(),
        builder: (context, snapshot) {
          if (snapshot.connectionState == ConnectionState.done) {
            return large.LargeComponent();
          }
          return CircularProgressIndicator();
        },
      ),
    );
  }
  
  Future<void> loadLibraries() async {
    await large.loadLibrary();
  }
}

// 减少重建范围
class OptimizedList extends StatelessWidget {
  final List<ItemData> items;
  
  const OptimizedList({Key? key, required this.items}) : super(key: key);
  
  @override
  Widget build(BuildContext context) {
    return ListView.builder(
      itemCount: items.length,
      // 使用const构造函数或缓存状态
      itemBuilder: (context, index) => OptimizedListItem(
        key: ValueKey(items[index].id),
        item: items[index],
      ),
    );
  }
}

// 在Web上使用缓存图像
Widget buildCachedImage(String url) {
  if (kIsWeb) {
    // Web平台使用网络图像缓存
    return Image.network(
      url,
      cacheWidth: 300,
      cacheHeight: 200,
      frameBuilder: (_, child, frame, __) {
        return frame == null
            ? Container(
                height: 200,
                width: 300,
                color: Colors.grey.shade200,
              )
            : child;
      },
    );
  } else {
    // 非Web平台使用cached_network_image
    return CachedNetworkImage(
      imageUrl: url,
      placeholder: (context, url) => Container(
        height: 200,
        width: 300,
        color: Colors.grey.shade200,
      ),
    );
  }
}
```

### 2. 桌面性能优化

```dart
// 使用计算隔离进行密集型计算
import 'dart:isolate';

Future<List<int>> performHeavyComputation(List<int> inputData) async {
  final receivePort = ReceivePort();
  await Isolate.spawn(_heavyComputation, 
      [receivePort.sendPort, inputData]);
  
  return await receivePort.first as List<int>;
}

void _heavyComputation(List<dynamic> params) {
  SendPort sendPort = params[0];
  List<int> inputData = params[1];
  
  // 执行计算密集型操作
  List<int> result = inputData.map((e) => e * e).toList();
  
  // 将结果发送回主隔离
  sendPort.send(result);
}

// 优化大型列表渲染
class OptimizedDataTable extends StatelessWidget {
  final List<DataRow> rows;
  final List<DataColumn> columns;
  
  const OptimizedDataTable({
    Key? key,
    required this.rows,
    required this.columns,
  }) : super(key: key);
  
  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        // 计算可见行数
        final double rowHeight = 52.0;
        final int visibleRowsCount = 
            (constraints.maxHeight / rowHeight).ceil();
        
        return Scrollbar(
          child: ListView.builder(
            itemCount: rows.length,
            itemExtent: rowHeight,
            itemBuilder: (context, index) {
              if (index < visibleRowsCount || 
                  index >= rows.length - visibleRowsCount) {
                // 渲染可见行和即将可见的行
                return Container(
                  height: rowHeight,
                  child: Row(
                    children: List.generate(
                      columns.length,
                      (colIndex) => Expanded(
                        flex: 1,
                        child: rows[index].cells[colIndex].child,
                      ),
                    ),
                  ),
                );
              } else {
                // 返回占位符
                return SizedBox(height: rowHeight);
              }
            },
          ),
        );
      },
    );
  }
}
```

### 3. 通用性能优化

```dart
// 使用const构造器减少重建
class PerformanceWidget extends StatelessWidget {
  final String title;
  
  const PerformanceWidget({Key? key, required this.title}) : super(key: key);
  
  @override
  Widget build(BuildContext context) {
    return Column(
      children: const [
        // 使用const减少不必要的重建
        ExpensiveWidget(),
        AnotherExpensiveWidget(),
      ],
    );
  }
}

// 缓存复杂计算结果
class CachedComputation {
  static final Map<String, dynamic> _cache = {};
  
  static T getOrCompute<T>(String key, T Function() computation) {
    if (!_cache.containsKey(key)) {
      _cache[key] = computation();
    }
    return _cache[key] as T;
  }
  
  static void invalidate(String key) {
    _cache.remove(key);
  }
  
  static void clearAll() {
    _cache.clear();
  }
}

// 图像和资源优化
class OptimizedAssets extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        // 根据平台和设备像素比选择最佳分辨率
        Image.asset(
          'assets/images/logo.png',
          width: 100,
          height: 100,
          cacheWidth: 200, // 2x像素比
          cacheHeight: 200,
        ),
        
        // SVG图像更适合缩放
        SvgPicture.asset(
          'assets/icons/icon.svg',
          width: 48,
          height: 48,
        ),
      ],
    );
  }
}
```

## 测试策略

针对Web和桌面应用的测试策略：

```dart
// integration_test/app_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:my_app/main.dart' as app;

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  
  group('跨平台集成测试', () {
    testWidgets('测试基本功能', (WidgetTester tester) async {
      app.main();
      await tester.pumpAndSettle();
      
      // 基本交互测试
      expect(find.text('欢迎使用'), findsOneWidget);
      await tester.tap(find.byType(ElevatedButton));
      await tester.pumpAndSettle();
      
      expect(find.text('页面已加载'), findsOneWidget);
    });
    
    testWidgets('测试平台特定功能', (WidgetTester tester) async {
      app.main();
      await tester.pumpAndSettle();
      
      if (kIsWeb) {
        // Web特定测试
        await tester.tap(find.byKey(Key('webSpecificButton')));
        await tester.pumpAndSettle();
        expect(find.text('Web功能已激活'), findsOneWidget);
      } else if (PlatformUtils.isDesktop) {
        // 桌面特定测试
        await tester.tap(find.byKey(Key('desktopSpecificButton')));
        await tester.pumpAndSettle();
        expect(find.text('桌面功能已激活'), findsOneWidget);
      }
    });
  });
}
```

## 构建与发布

综合的构建和发布流程配置：

```yaml
# CI/CD配置示例 (.github/workflows/build.yml)
name: 构建与发布

on:
  push:
    tags:
      - 'v*'
    branches:
      - main
  pull_request:
    branches:
      - main

jobs:
  build_web:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: subosito/flutter-action@v2
        with:
          flutter-version: '3.10.0'
          channel: 'stable'
      - run: flutter pub get
      - run: flutter test
      - run: flutter build web --web-renderer canvaskit --release
      - name: Deploy to Firebase
        if: startsWith(github.ref, 'refs/tags/v')
        uses: FirebaseExtended/action-hosting-deploy@v0
        with:
          repoToken: '${{ secrets.GITHUB_TOKEN }}'
          firebaseServiceAccount: '${{ secrets.FIREBASE_SERVICE_ACCOUNT }}'
          projectId: my-flutter-app
          channelId: live

  build_windows:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - uses: subosito/flutter-action@v2
        with:
          flutter-version: '3.10.0'
      - run: flutter config --enable-windows-desktop
      - run: flutter pub get
      - run: flutter build windows --release
      - name: Create Installer
        if: startsWith(github.ref, 'refs/tags/v')
        run: |
          choco install innosetup -y
          iscc installer/setup.iss
      - name: Upload Artifacts
        uses: actions/upload-artifact@v3
        with:
          name: windows-installer
          path: installer/Output/my_app_setup.exe

  build_macos:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v3
      - uses: subosito/flutter-action@v2
        with:
          flutter-version: '3.10.0'
      - run: flutter config --enable-macos-desktop
      - run: flutter pub get
      - run: flutter build macos --release
      - name: Create DMG
        if: startsWith(github.ref, 'refs/tags/v')
        run: |
          brew install create-dmg
          create-dmg \
            --volname "我的Flutter应用" \
            --window-pos 200 120 \
            --window-size 600 400 \
            --icon-size 100 \
            --icon "my_app.app" 175 190 \
            --app-drop-link 425 190 \
            "my_app.dmg" \
            "build/macos/Build/Products/Release/my_app.app"
      - name: Upload Artifacts
        uses: actions/upload-artifact@v3
        with:
          name: macos-dmg
          path: my_app.dmg
```

## 真实案例分析

以下是一个简化的跨平台文件管理器应用，展示如何在各平台提供一致体验：

```dart
import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';
import 'package:file_picker/file_picker.dart';
import 'package:path_provider/path_provider.dart';
import 'package:url_launcher/url_launcher.dart';
import 'dart:io' if (dart.library.html) 'web_shims/io.dart';

void main() {
  runApp(MyApp());
}

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: '跨平台文件管理器',
      theme: ThemeData(
        primarySwatch: Colors.blue,
        brightness: Brightness.light,
      ),
      darkTheme: ThemeData(
        primarySwatch: Colors.blue,
        brightness: Brightness.dark,
      ),
      themeMode: ThemeMode.system,
      home: FileManagerHome(),
    );
  }
}

class FileManagerHome extends StatefulWidget {
  @override
  _FileManagerHomeState createState() => _FileManagerHomeState();
}

class _FileManagerHomeState extends State<FileManagerHome> {
  List<FileSystemEntity> _files = [];
  String _currentPath = '';
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _loadInitialDirectory();
  }

  Future<void> _loadInitialDirectory() async {
    setState(() => _isLoading = true);
    
    try {
      if (kIsWeb) {
        // Web平台不支持直接访问文件系统
        _currentPath = 'Web存储';
        _files = []; // 可以显示IndexedDB或LocalStorage中保存的文件
      } else {
        // 桌面/移动平台
        final directory = await getApplicationDocumentsDirectory();
        await _loadDirectory(directory.path);
      }
    } catch (e) {
      print('加载目录错误: $e');
    } finally {
      setState(() => _isLoading = false);
    }
  }

  Future<void> _loadDirectory(String path) async {
    if (kIsWeb) return;
    
    try {
      final dir = Directory(path);
      final List<FileSystemEntity> entities = await dir.list().toList();
      entities.sort((a, b) {
        // 目录排在文件前面
        if (a is Directory && b is File) return -1;
        if (a is File && b is Directory) return 1;
        return a.path.compareTo(b.path);
      });
      
      setState(() {
        _currentPath = path;
        _files = entities;
      });
    } catch (e) {
      print('访问目录错误: $e');
    }
  }

  Future<void> _pickFile() async {
    try {
      FilePickerResult? result = await FilePicker.platform.pickFiles();
      if (result != null) {
        // 处理选择的文件
        final file = result.files.first;
        print('选择的文件: ${file.name}');
        
        if (!kIsWeb && file.path != null) {
          // 非Web平台可以访问文件路径
          final path = file.path!;
          final directory = path.substring(0, path.lastIndexOf(Platform.pathSeparator));
          await _loadDirectory(directory);
        }
      }
    } catch (e) {
      print('选择文件错误: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('文件管理器'),
        actions: [
          IconButton(
            icon: Icon(Icons.refresh),
            onPressed: () => _loadInitialDirectory(),
          ),
        ],
      ),
      body: _buildBody(),
      floatingActionButton: FloatingActionButton(
        child: Icon(Icons.add),
        onPressed: _pickFile,
      ),
    );
  }

  Widget _buildBody() {
    if (_isLoading) {
      return Center(child: CircularProgressIndicator());
    }
    
    if (kIsWeb) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.cloud, size: 64, color: Colors.blue),
            SizedBox(height: 16),
            Text('Web平台文件管理',
                style: Theme.of(context).textTheme.titleLarge),
            SizedBox(height: 24),
            ElevatedButton.icon(
              icon: Icon(Icons.upload_file),
              label: Text('上传文件'),
              onPressed: _pickFile,
            ),
          ],
        ),
      );
    }
    
    return Column(
      children: [
        // 路径导航栏
        Padding(
          padding: const EdgeInsets.all(8.0),
          child: Row(
            children: [
              Icon(Icons.folder, color: Colors.amber),
              SizedBox(width: 8),
              Expanded(
                child: Text(
                  _currentPath,
                  style: TextStyle(fontWeight: FontWeight.bold),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              if (!kIsWeb && _currentPath.isNotEmpty)
                IconButton(
                  icon: Icon(Icons.arrow_upward),
                  onPressed: () {
                    final parent = _currentPath.substring(
                      0, _currentPath.lastIndexOf(Platform.pathSeparator));
                    if (parent.isNotEmpty) {
                      _loadDirectory(parent);
                    }
                  },
                ),
            ],
          ),
        ),
        
        Divider(),
        
        // 文件列表
        Expanded(
          child: _files.isEmpty
              ? Center(child: Text('目录为空'))
              : ListView.builder(
                  itemCount: _files.length,
                  itemBuilder: (context, index) {
                    final entity = _files[index];
                    final bool isDirectory = entity is Directory;
                    final name = entity.path.split(Platform.pathSeparator).last;
                    
                    return ListTile(
                      leading: Icon(
                        isDirectory ? Icons.folder : Icons.insert_drive_file,
                        color: isDirectory ? Colors.amber : Colors.blue,
                      ),
                      title: Text(name),
                      subtitle: Text(
                        isDirectory ? '目录' : '文件',
                        style: TextStyle(fontSize: 12),
                      ),
                      onTap: () async {
                        if (isDirectory) {
                          await _loadDirectory(entity.path);
                        } else if (entity is File) {
                          // 打开文件
                          if (await File(entity.path).exists()) {
                            final url = Uri.file(entity.path);
                            if (await canLaunchUrl(url)) {
                              await launchUrl(url);
                            }
                          }
                        }
                      },
                    );
                  },
                ),
        ),
      ],
    );
  }
}

// Web平台的IO模拟 (web_shims/io.dart)
class File {
  final String path;
  
  File(this.path);
  
  Future<bool> exists() async => false;
}

class Directory {
  final String path;
  
  Directory(this.path);
  
  Stream<FileSystemEntity> list() {
    return Stream.empty();
  }
}

abstract class FileSystemEntity {
  String get path;
}

class Platform {
  static String get pathSeparator => '/';
}
```

通过本文的学习，您应该能够使用Flutter构建高质量的Web和桌面应用程序，并处理不同平台的特定需求和限制。对于更复杂的场景，建议进一步探索特定于平台的API和优化技术。
