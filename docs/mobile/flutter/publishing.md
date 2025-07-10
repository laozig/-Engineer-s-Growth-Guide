# Flutter 发布与部署

## 目录

- [应用发布概述](#应用发布概述)
- [准备工作](#准备工作)
  - [版本号管理](#版本号管理)
  - [应用图标设置](#应用图标设置)
  - [启动画面配置](#启动画面配置)
  - [应用权限配置](#应用权限配置)
- [Android 应用发布](#android-应用发布)
  - [签名密钥生成](#签名密钥生成)
  - [应用签名配置](#应用签名配置)
  - [构建发布版APK](#构建发布版apk)
  - [构建AAB包](#构建aab包)
  - [Google Play 发布流程](#google-play-发布流程)
  - [其他应用商店发布](#其他应用商店发布)
- [iOS 应用发布](#ios-应用发布)
  - [证书与配置文件](#证书与配置文件)
  - [构建IPA包](#构建ipa包)
  - [TestFlight测试](#testflight测试)
  - [App Store发布流程](#app-store发布流程)
- [持续集成与自动化部署](#持续集成与自动化部署)
  - [使用GitHub Actions](#使用github-actions)
  - [使用Codemagic](#使用codemagic)
  - [使用Fastlane](#使用fastlane)
- [应用更新策略](#应用更新策略)
  - [热更新实现](#热更新实现)
  - [版本控制与升级提示](#版本控制与升级提示)
- [发布检查清单](#发布检查清单)
- [常见问题与解决方案](#常见问题与解决方案)

## 应用发布概述

Flutter应用开发完成后，需要将应用打包并发布到各大应用商店，使用户能够下载使用。发布流程包括应用打包、签名、测试和提交到应用商店审核等步骤。本文档将详细介绍Android和iOS平台的发布流程。

## 准备工作

### 版本号管理

在`pubspec.yaml`文件中管理应用版本：

```yaml
version: 1.0.0+1
```

版本号由两部分组成：
- `1.0.0` - 语义化版本号（用户可见）
- `1` - 构建版本号（内部版本计数）

每次发布应用时，应更新这些版本号。语义化版本遵循 [主版本.次版本.补丁] 格式：

- **主版本**：进行不兼容的API更改时增加
- **次版本**：添加向后兼容的功能时增加
- **补丁**：进行向后兼容的bug修复时增加

### 应用图标设置

#### Android应用图标

使用`flutter_launcher_icons`包生成多种尺寸的图标：

1. 添加依赖：

```yaml
dev_dependencies:
  flutter_launcher_icons: ^0.13.1

flutter_launcher_icons:
  android: "launcher_icon"
  ios: true
  image_path: "assets/icon/app_icon.png"
  min_sdk_android: 21 # Android最低SDK版本
  adaptive_icon_background: "#FFFFFF" # Android自适应图标背景色
  adaptive_icon_foreground: "assets/icon/foreground.png" # Android自适应图标前景
```

2. 运行命令生成图标：

```bash
flutter pub run flutter_launcher_icons
```

#### iOS应用图标

iOS图标配置在`ios/Runner/Assets.xcassets/AppIcon.appiconset`目录，可以使用上述插件自动生成或手动替换。

### 启动画面配置

使用`flutter_native_splash`包配置启动画面：

1. 添加依赖：

```yaml
dev_dependencies:
  flutter_native_splash: ^2.3.6

flutter_native_splash:
  color: "#42a5f5"  # 纯色背景
  # background_image: "assets/splash.png" # 或使用背景图片
  image: assets/splash_logo.png  # 中心显示的图片
  android_12:  # Android 12专用配置
    image: assets/splash_logo.png
    icon_background_color: "#42a5f5"
```

2. 生成启动画面：

```bash
flutter pub run flutter_native_splash:create
```

### 应用权限配置

#### Android权限配置

在`android/app/src/main/AndroidManifest.xml`文件中配置权限：

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <!-- 网络权限 -->
    <uses-permission android:name="android.permission.INTERNET"/>
    <!-- 相机权限 -->
    <uses-permission android:name="android.permission.CAMERA"/>
    <!-- 存储权限 -->
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <!-- 位置权限 -->
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
    <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION"/>
    
    <application
        android:label="应用名称"
        android:icon="@mipmap/launcher_icon">
        <!-- 应用配置... -->
    </application>
</manifest>
```

#### iOS权限配置

在`ios/Runner/Info.plist`文件中配置权限：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- 相机权限 -->
    <key>NSCameraUsageDescription</key>
    <string>此应用需要访问相机以拍摄照片</string>
    <!-- 相册权限 -->
    <key>NSPhotoLibraryUsageDescription</key>
    <string>此应用需要访问相册以选择图片</string>
    <!-- 位置权限 -->
    <key>NSLocationWhenInUseUsageDescription</key>
    <string>此应用需要使用您的位置提供本地化服务</string>
    <!-- 麦克风权限 -->
    <key>NSMicrophoneUsageDescription</key>
    <string>此应用需要使用麦克风录制音频</string>
    <!-- 其他配置项... -->
</dict>
</plist>
```

## Android 应用发布

### 签名密钥生成

Android应用发布前需要创建签名密钥：

1. 使用Java的keytool工具生成密钥：

```bash
keytool -genkey -v -keystore my-release-key.jks -keyalg RSA -keysize 2048 -validity 10000 -alias my-key-alias
```

2. 按提示输入密钥库口令、名字姓氏、组织单位等信息。

### 应用签名配置

1. 在项目根目录创建`key.properties`文件（不要提交到版本控制）：

```properties
storePassword=<密钥库口令>
keyPassword=<密钥口令>
keyAlias=my-key-alias
storeFile=<密钥库文件位置，如 ../my-release-key.jks>
```

2. 修改`android/app/build.gradle`配置签名：

```gradle
def keystoreProperties = new Properties()
def keystorePropertiesFile = rootProject.file('key.properties')
if (keystorePropertiesFile.exists()) {
    keystoreProperties.load(new FileInputStream(keystorePropertiesFile))
}

android {
    // ...
    
    signingConfigs {
        release {
            keyAlias keystoreProperties['keyAlias']
            keyPassword keystoreProperties['keyPassword']
            storeFile keystoreProperties['storeFile'] ? file(keystoreProperties['storeFile']) : null
            storePassword keystoreProperties['storePassword']
        }
    }
    
    buildTypes {
        release {
            signingConfig signingConfigs.release
            minifyEnabled true
            shrinkResources true
            proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
        }
    }
}
```

### 构建发布版APK

执行以下命令构建发布版APK：

```bash
flutter build apk --release
```

构建完成后，APK文件位于`build/app/outputs/flutter-apk/app-release.apk`。

### 构建AAB包

Google Play商店推荐使用Android App Bundle (AAB) 格式：

```bash
flutter build appbundle --release
```

构建完成后，AAB文件位于`build/app/outputs/bundle/release/app-release.aab`。

### Google Play 发布流程

1. **创建开发者账号**：访问[Google Play开发者控制台](https://play.google.com/console/)，支付$25注册费。

2. **创建应用**：在开发者控制台点击"创建应用"，输入应用名称和默认语言。

3. **填写应用信息**：
   - 应用描述
   - 宣传图片和屏幕截图
   - 应用分类
   - 内容分级
   - 联系信息
   - 隐私政策

4. **上传AAB或APK**：进入"版本管理" > "生产版本"，上传应用包。

5. **设置价格与分发**：选择免费或付费，以及应用可用的国家/地区。

6. **发布审核**：提交审核后等待Google审核，通常需要几小时到几天。

### 其他应用商店发布

中国大陆地区可能需要发布到其他应用商店：

1. **华为应用市场**：
   - 注册[华为开发者联盟](https://developer.huawei.com/)账号
   - 创建应用并上传APK
   - 提交资料审核

2. **小米应用商店**：
   - 注册[小米开放平台](https://dev.mi.com/)账号
   - 创建应用并上传APK
   - 提交资料审核

3. **OPPO软件商店**：
   - 注册[OPPO开放平台](https://open.oppomobile.com/)账号
   - 创建应用并上传APK
   - 提交资料审核

4. **其他商店**：腾讯应用宝、vivo应用商店等流程类似。

## iOS 应用发布

### 证书与配置文件

iOS应用发布需要获取证书和配置文件：

1. **创建Apple开发者账号**：注册[Apple Developer Program](https://developer.apple.com/programs/)，个人开发者年费$99。

2. **生成证书**：
   - 登录[Apple Developer](https://developer.apple.com/)
   - 进入"Certificates, Identifiers & Profiles"
   - 创建开发证书和发布证书

3. **注册App ID**：
   - 在"Identifiers"中添加新的App ID
   - 输入应用Bundle ID（与Flutter项目中一致）
   - 选择所需功能和权限

4. **创建配置文件**：
   - 在"Profiles"中创建开发和发布配置文件
   - 关联之前创建的App ID和证书

5. **安装证书和配置文件**：
   - 下载并双击安装证书到钥匙串
   - 下载并安装配置文件到Xcode

### 构建IPA包

通过以下步骤构建iOS应用：

1. 确保iOS部分配置正确：

```bash
open ios/Runner.xcworkspace
```

2. 在Xcode中，设置正确的Team和Signing配置。

3. 使用Flutter命令构建：

```bash
flutter build ipa --release
```

构建完成后，IPA文件位于`build/ios/ipa`目录。

### TestFlight测试

发布前可以通过TestFlight进行测试：

1. 在[App Store Connect](https://appstoreconnect.apple.com/)创建应用。

2. 使用Xcode或Application Loader上传构建好的IPA。

3. 构建上传后，在TestFlight标签页处理合规信息。

4. 添加测试人员并邀请他们进行测试。

### App Store发布流程

1. **准备应用信息**：
   - 应用名称和描述
   - 关键词
   - 支持网站和支持邮箱
   - 隐私政策URL
   - App Store预览和屏幕截图
   - 应用分类

2. **提交审核**：
   - 选择之前通过TestFlight测试的构建版本
   - 填写版本信息
   - 提交审核

3. **审核过程**：
   - Apple审核通常需要24-48小时
   - 可能被拒绝，需根据反馈修改再提交

4. **发布上线**：
   - 审核通过后，可选择手动发布或自动发布
   - 应用上线后，通常几小时内可在App Store搜索到

## 持续集成与自动化部署

### 使用GitHub Actions

在GitHub仓库中添加`.github/workflows/flutter-ci.yml`文件：

```yaml
name: Flutter CI/CD

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Flutter
        uses: subosito/flutter-action@v2
        with:
          flutter-version: '3.16.0'
          channel: 'stable'
      
      - name: Install dependencies
        run: flutter pub get
      
      - name: Analyze code
        run: flutter analyze
      
      - name: Run tests
        run: flutter test
  
  build-android:
    needs: build-and-test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Flutter
        uses: subosito/flutter-action@v2
        with:
          flutter-version: '3.16.0'
          channel: 'stable'
      
      - name: Install dependencies
        run: flutter pub get
      
      - name: Build APK
        run: flutter build apk --release
      
      - name: Upload APK
        uses: actions/upload-artifact@v3
        with:
          name: release-apk
          path: build/app/outputs/flutter-apk/app-release.apk
  
  build-ios:
    needs: build-and-test
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Flutter
        uses: subosito/flutter-action@v2
        with:
          flutter-version: '3.16.0'
          channel: 'stable'
      
      - name: Install dependencies
        run: flutter pub get
      
      - name: Build iOS
        run: flutter build ios --release --no-codesign
```

### 使用Codemagic

[Codemagic](https://codemagic.io/)是专为Flutter应用设计的CI/CD平台：

1. 注册Codemagic并连接代码仓库。

2. 创建`codemagic.yaml`文件：

```yaml
workflows:
  android-workflow:
    name: Android Build
    max_build_duration: 60
    instance_type: mac_mini_m1
    environment:
      flutter: stable
    scripts:
      - name: Get Flutter packages
        script: flutter packages pub get
      - name: Flutter analyze
        script: flutter analyze
      - name: Flutter test
        script: flutter test
      - name: Build APK
        script: flutter build apk --release
    artifacts:
      - build/app/outputs/flutter-apk/app-release.apk
  
  ios-workflow:
    name: iOS Build
    max_build_duration: 60
    instance_type: mac_mini_m1
    environment:
      flutter: stable
      xcode: latest
      cocoapods: default
    scripts:
      - name: Get Flutter packages
        script: flutter packages pub get
      - name: Install pods
        script: find . -name "Podfile" -execdir pod install \;
      - name: Flutter analyze
        script: flutter analyze
      - name: Flutter test
        script: flutter test
      - name: Build iOS
        script: flutter build ios --release --no-codesign
```

### 使用Fastlane

[Fastlane](https://fastlane.tools/)是一套自动化工具，可用于简化应用发布流程。

#### Android Fastlane配置

1. 初始化Fastlane：

```bash
cd android
fastlane init
```

2. 编辑`android/fastlane/Fastfile`：

```ruby
default_platform(:android)

platform :android do
  desc "提交新版本到Play商店内测轨道"
  lane :beta do
    gradle(task: "clean")
    gradle(
      task: "bundle",
      build_type: "Release"
    )
    upload_to_play_store(
      track: "beta",
      aab: "../build/app/outputs/bundle/release/app-release.aab"
    )
  end

  desc "提交新版本到Play商店正式轨道"
  lane :production do
    gradle(task: "clean")
    gradle(
      task: "bundle",
      build_type: "Release"
    )
    upload_to_play_store(
      aab: "../build/app/outputs/bundle/release/app-release.aab"
    )
  end
end
```

#### iOS Fastlane配置

1. 初始化Fastlane：

```bash
cd ios
fastlane init
```

2. 编辑`ios/fastlane/Fastfile`：

```ruby
default_platform(:ios)

platform :ios do
  desc "提交到TestFlight"
  lane :beta do
    build_app(
      workspace: "Runner.xcworkspace",
      scheme: "Runner",
      export_method: "app-store"
    )
    upload_to_testflight
  end

  desc "发布到App Store"
  lane :release do
    build_app(
      workspace: "Runner.xcworkspace",
      scheme: "Runner",
      export_method: "app-store"
    )
    upload_to_app_store(
      submit_for_review: true,
      force: true,
      automatic_release: true
    )
  end
end
```

## 应用更新策略

### 热更新实现

Flutter应用可以使用热更新方案更新非原生代码部分，常用的解决方案有：

1. **Flutter 官方解决方案**：

可以使用 [melos](https://pub.dev/packages/melos) 和 [dynamic_app](https://pub.dev/packages/dynamic_app) 等包实现基本的动态更新。

2. **自定义热更新**：

```dart
class AppUpdater {
  static Future<bool> checkForUpdates() async {
    // 检查服务器是否有新版本
    final response = await http.get(Uri.parse('https://yourapi.com/check-update'));
    if (response.statusCode == 200) {
      final data = jsonDecode(response.body);
      if (data['hasUpdate'] == true) {
        return true;
      }
    }
    return false;
  }
  
  static Future<void> downloadUpdate() async {
    // 下载新资源
    final response = await http.get(Uri.parse('https://yourapi.com/download-update'));
    if (response.statusCode == 200) {
      // 保存更新文件
      final appDir = await getApplicationDocumentsDirectory();
      final file = File('${appDir.path}/update.zip');
      await file.writeAsBytes(response.bodyBytes);
      
      // 解压更新包
      await extractUpdatePackage(file.path);
      
      // 应用更新
      await applyUpdate();
    }
  }
  
  static Future<void> extractUpdatePackage(String filePath) async {
    // 使用压缩库解压文件
  }
  
  static Future<void> applyUpdate() async {
    // 应用更新，可能需要重启应用
  }
}
```

3. **第三方解决方案**：

- [CodePush](https://github.com/microsoft/code-push) (React Native)
- [AppCenter](https://appcenter.ms/)

请注意，iOS App Store政策对热更新有严格限制，更新不应更改应用的主要功能或绕过App Store审核。

### 版本控制与升级提示

实现版本检查和强制更新功能：

```dart
class VersionChecker {
  Future<void> checkVersion() async {
    try {
      // 从服务器获取版本信息
      final response = await http.get(Uri.parse('https://yourapi.com/version'));
      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        final serverVersion = data['latestVersion'];
        final forceUpdate = data['forceUpdate'];
        
        // 获取当前应用版本
        final packageInfo = await PackageInfo.fromPlatform();
        final currentVersion = packageInfo.version;
        
        if (serverVersion != currentVersion) {
          if (forceUpdate) {
            // 显示强制更新对话框
            showForceUpdateDialog();
          } else {
            // 显示建议更新对话框
            showUpdateDialog();
          }
        }
      }
    } catch (e) {
      print('版本检查失败: $e');
    }
  }
  
  void showForceUpdateDialog() {
    // 显示强制更新对话框，用户必须更新才能继续使用
  }
  
  void showUpdateDialog() {
    // 显示更新提示，用户可以选择稍后更新
  }
}
```

## 发布检查清单

在发布应用前，请检查以下项目：

### 功能检查
- [ ] 所有关键功能是否正常工作
- [ ] 是否处理了边缘情况和错误情况
- [ ] 离线功能是否正常
- [ ] 应用权限请求是否正常显示和处理

### UI/UX检查
- [ ] 所有屏幕上的UI元素是否正确显示
- [ ] 不同设备尺寸上的适配是否正常
- [ ] 深色模式/浅色模式切换是否正常
- [ ] 动画和过渡是否流畅

### 性能检查
- [ ] 应用启动时间是否在可接受范围内
- [ ] 滚动和页面切换是否流畅
- [ ] 内存使用是否合理
- [ ] 电池使用是否优化

### 安全检查
- [ ] 敏感数据是否加密存储
- [ ] API调用是否使用HTTPS
- [ ] 是否移除了调试代码和日志

### 商店发布准备
- [ ] 应用图标和启动图是否高质量
- [ ] 应用描述和关键词是否优化
- [ ] 隐私政策是否符合要求
- [ ] 应用截图和预览视频是否吸引人

## 常见问题与解决方案

### 问题1：Android应用签名问题

**症状**：构建发布版APK时出现签名错误。

**解决方案**：
- 确认`key.properties`文件路径和内容正确
- 确认`build.gradle`中签名配置正确
- 尝试重新生成签名密钥

### 问题2：iOS证书配置问题

**症状**：构建iOS应用时出现证书或配置文件错误。

**解决方案**：
- 在Xcode中更新团队和证书设置
- 重新下载并安装配置文件
- 检查Bundle ID是否与开发者账号中注册的一致

### 问题3：应用尺寸过大

**症状**：构建的应用体积超过预期。

**解决方案**：
- 启用代码压缩：在`build.gradle`中设置`minifyEnabled true`
- 优化图像资源，使用WebP格式
- 移除未使用的库和资源
- 使用Split APKs或App Bundle格式

### 问题4：应用审核被拒

**症状**：应用提交审核后被拒绝。

**解决方案**：
- 仔细阅读拒绝原因，针对性修改
- 检查应用是否符合商店政策和指南
- 确保隐私政策完整并符合要求
- 与审核团队沟通，解释应用功能和特性

---

通过本文档，你应该能够顺利完成Flutter应用的打包和发布流程。记住，发布只是应用生命周期的一部分，持续更新和维护同样重要。祝你的应用取得成功！
