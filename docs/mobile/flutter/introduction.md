# Flutter简介与环境搭建

Flutter是Google开发的开源UI框架，用于构建高性能、高保真的跨平台应用。使用单一代码库，开发者可以为iOS、Android、Web、桌面等平台创建应用。

## Flutter的核心优势

- **高效开发** - 热重载功能让开发者能即时看到代码更改的效果
- **表现力UI** - 丰富的内置Material Design和Cupertino风格组件
- **原生性能** - 直接编译为原生代码，不依赖平台的OEM组件
- **跨平台一致性** - 在所有平台上提供一致的视觉和交互体验
- **单一代码库** - 维护一套代码即可支持多个平台

## Dart语言

Flutter使用Dart作为编程语言，Dart是一种客户端优化的语言，具有以下特点：

- 类型安全但支持类型推断
- 面向对象编程范式
- 支持JIT(即时编译)和AOT(提前编译)
- 强大的异步支持(Future和Stream)
- 丰富的标准库

```dart
// Dart示例代码
void main() {
  print('Hello, Flutter!');
  
  // 变量声明与类型推断
  var name = 'Flutter Developer';
  String framework = 'Flutter';
  
  // 字符串插值
  print('$name uses $framework');
  
  // 异步函数
  fetchData().then((data) => print(data));
}

Future<String> fetchData() async {
  // 模拟网络请求
  await Future.delayed(Duration(seconds: 2));
  return 'Data loaded successfully';
}
```

## 环境搭建

### 系统要求

**Windows:**
- Windows 7 SP1或更高版本(64位)
- 磁盘空间: 至少1.32 GB(不包括IDE/工具)
- 工具: Windows PowerShell 5.0或更新版本，Git for Windows

**macOS:**
- 支持Intel或Apple Silicon芯片的Mac
- macOS 10.14 (Mojave)或更高版本
- 磁盘空间: 至少2.8 GB(不包括IDE/工具)
- 工具: bash, curl, git, mkdir, rm, unzip, which

**Linux:**
- 任何64位Linux(例如Ubuntu, Debian)
- 磁盘空间: 至少600 MB(不包括IDE/工具)
- 工具: bash, curl, git, mkdir, rm, unzip, which, xz-utils

### 安装Flutter SDK

#### Windows安装步骤

1. 下载[Flutter SDK](https://docs.flutter.dev/get-started/install/windows)的最新稳定版本
2. 将下载的zip文件解压到所需位置(避免需要特殊权限的路径，如C:\Program Files\)
3. 将`flutter\bin`目录添加到环境变量Path中
4. 运行`flutter doctor`检查是否需要安装其他依赖项

```powershell
# 在PowerShell中检查Flutter安装
flutter doctor
```

#### macOS安装步骤

1. 下载[Flutter SDK](https://docs.flutter.dev/get-started/install/macos)的最新稳定版本
2. 将下载的zip文件解压到所需位置
3. 将Flutter添加到PATH

```bash
# 在bash配置文件中添加
export PATH="$PATH:`pwd`/flutter/bin"

# 刷新配置
source ~/.bashrc  # 或 source ~/.zshrc

# 检查安装
flutter doctor
```

#### Linux安装步骤

1. 下载[Flutter SDK](https://docs.flutter.dev/get-started/install/linux)的最新稳定版本
2. 解压到所需位置

```bash
# 例如，在Linux中安装Flutter
cd ~/development
tar xf ~/Downloads/flutter_linux_3.x.x-stable.tar.xz
export PATH="$PATH:`pwd`/flutter/bin"

# 检查安装
flutter doctor
```

### 安装IDE

Flutter支持多种IDE，以下是最常用的选项：

**Visual Studio Code**
1. 安装[Visual Studio Code](https://code.visualstudio.com/)
2. 安装Flutter和Dart插件

**Android Studio / IntelliJ IDEA**
1. 安装[Android Studio](https://developer.android.com/studio)或[IntelliJ IDEA](https://www.jetbrains.com/idea/)
2. 安装Flutter和Dart插件

### 平台设置

#### Android设置

1. 安装Android Studio
2. 通过SDK Manager安装Android SDK、平台工具和构建工具
3. 设置Android模拟器或连接实体设备

```bash
# 列出可用的模拟器
flutter emulators

# 启动一个模拟器
flutter emulators --launch <emulator_id>
```

#### iOS设置(仅限macOS)

1. 安装最新版本的Xcode
2. 配置Xcode命令行工具

```bash
sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer
sudo xcodebuild -runFirstLaunch
```

3. 确保同意Xcode许可协议

```bash
sudo xcodebuild -license
```

### 验证安装

完成安装后，运行以下命令检查环境配置：

```bash
flutter doctor -v
```

这个命令会详细列出所有依赖项的状态，并提供修复问题的提示。

## 创建第一个Flutter应用

### 命令行创建应用

```bash
# 创建新应用
flutter create my_first_app

# 进入项目目录
cd my_first_app

# 运行应用
flutter run
```

### IDE中创建应用

**Visual Studio Code:**
1. 按`Ctrl+Shift+P`(Windows/Linux)或`Cmd+Shift+P`(macOS)
2. 输入"Flutter: New Project"
3. 选择项目类型和位置
4. 按F5运行

**Android Studio / IntelliJ:**
1. 选择"File" > "New" > "New Flutter Project"
2. 选择项目类型和配置设置
3. 点击"Run"按钮运行

## 项目结构

一个基本的Flutter项目结构如下：

```
my_first_app/
├── .dart_tool/         # Dart工具相关文件
├── .idea/              # IDE配置文件(如果使用IntelliJ/Android Studio)
├── android/            # Android平台特定代码
├── build/              # 构建输出目录
├── ios/                # iOS平台特定代码
├── lib/                # 主要Dart源代码
│   └── main.dart       # 应用入口点
├── test/               # 测试文件
├── web/                # Web平台特定代码(如果启用)
├── pubspec.yaml        # 项目配置和依赖
└── README.md           # 项目说明文档
```

## 核心文件介绍

### pubspec.yaml

这是Flutter应用的配置文件，定义应用名称、描述、版本和依赖项。

```yaml
name: my_first_app
description: My first Flutter application

# 应用版本
version: 1.0.0+1

environment:
  sdk: ">=2.17.0 <3.0.0"

dependencies:
  flutter:
    sdk: flutter
  # 其他依赖项
  cupertino_icons: ^1.0.2

dev_dependencies:
  flutter_test:
    sdk: flutter
  # 开发依赖项
  flutter_lints: ^2.0.0

flutter:
  # 资源配置
  uses-material-design: true
  # 资源引用
  assets:
    - assets/images/
```

### main.dart

应用的入口点，包含`main()`函数和根组件。

```dart
import 'package:flutter/material.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
      theme: ThemeData(
        primarySwatch: Colors.blue,
      ),
      home: const MyHomePage(title: 'Flutter Demo Home Page'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({Key? key, required this.title}) : super(key: key);

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  int _counter = 0;

  void _incrementCounter() {
    setState(() {
      _counter++;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            const Text(
              'You have pushed the button this many times:',
            ),
            Text(
              '$_counter',
              style: Theme.of(context).textTheme.headline4,
            ),
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _incrementCounter,
        tooltip: 'Increment',
        child: const Icon(Icons.add),
      ),
    );
  }
}
```

## 常见问题解决

### Flutter Doctor常见问题

1. **Android SDK未找到或不完整**
   - 确保已安装Android SDK
   - 设置`ANDROID_HOME`环境变量指向SDK位置

2. **iOS工具链不完整(macOS)**
   - 确保已安装最新版Xcode
   - 运行`sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer`

3. **Android Studio未找到**
   - 确保已安装Android Studio
   - 设置`ANDROID_STUDIO_HOME`环境变量

### 常见运行时问题

1. **Gradle构建失败**
   - 检查网络连接(可能需要下载依赖)
   - 更新Gradle版本
   - 清理项目:`flutter clean`

2. **iOS构建失败(macOS)**
   - 运行`pod update`
   - 重启Xcode
   - 使用`flutter clean`清理项目

## 下一步

- 深入学习[Dart语言基础](dart-basics.md)
- 了解Flutter的[核心概念](core-concepts.md)
- 探索[Flutter官方文档](https://docs.flutter.dev/)
- 加入[Flutter社区](https://flutter.dev/community) 