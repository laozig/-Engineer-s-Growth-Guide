# React Native 构建与发布

将 React Native 应用部署到应用商店是开发过程中的关键阶段。本文档将指导你完成准备、构建和发布 React Native 应用到 App Store 和 Google Play 的全过程。

## 目录

- [发布前准备](#发布前准备)
- [版本管理](#版本管理)
- [iOS 构建与发布](#ios-构建与发布)
- [Android 构建与发布](#android-构建与发布)
- [自动化构建](#自动化构建)
- [应用内更新](#应用内更新)
- [常见问题与解决方案](#常见问题与解决方案)
- [发布检查清单](#发布检查清单)
- [最佳实践](#最佳实践)

## 发布前准备

在发布应用前，确保完成以下准备工作：

### 1. 应用配置

#### 应用图标与启动屏幕

确保为不同设备准备了适当分辨率的图标和启动屏幕：

**iOS 图标尺寸**:
- iPhone: 60x60, 120x120, 180x180 pt
- iPad: 76x76, 152x152, 167x167 pt
- App Store: 1024x1024 pt

**Android 图标尺寸**:
- mdpi: 48x48 px
- hdpi: 72x72 px
- xhdpi: 96x96 px
- xxhdpi: 144x144 px
- xxxhdpi: 192x192 px
- Play Store: 512x512 px

#### 应用名称与标识符

**iOS (在 Info.plist 中)**:
```xml
<key>CFBundleDisplayName</key>
<string>应用名称</string>
<key>CFBundleIdentifier</key>
<string>com.yourcompany.appname</string>
```

**Android (在 app/build.gradle 中)**:
```gradle
android {
    defaultConfig {
        applicationId "com.yourcompany.appname"
        versionCode 1
        versionName "1.0.0"
    }
}
```

### 2. 权限配置

#### iOS 权限 (在 Info.plist 中)

```xml
<!-- 相机权限 -->
<key>NSCameraUsageDescription</key>
<string>此应用需要访问您的相机以拍摄照片</string>

<!-- 照片库权限 -->
<key>NSPhotoLibraryUsageDescription</key>
<string>此应用需要访问您的照片库以选择照片</string>

<!-- 位置权限 -->
<key>NSLocationWhenInUseUsageDescription</key>
<string>此应用需要访问您的位置以提供基于位置的服务</string>
```

#### Android 权限 (在 AndroidManifest.xml 中)

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.CAMERA" />
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
```

### 3. 生产环境配置

创建环境配置文件来区分开发、测试和生产环境：

```javascript
// config.js
const ENV = {
  dev: {
    apiUrl: 'https://dev-api.example.com',
    enableLogs: true,
  },
  staging: {
    apiUrl: 'https://staging-api.example.com',
    enableLogs: true,
  },
  prod: {
    apiUrl: 'https://api.example.com',
    enableLogs: false,
  }
};

// 根据环境变量或构建配置选择环境
const getEnvVars = () => {
  // 可以使用 react-native-config 等库读取环境变量
  const environment = process.env.NODE_ENV || 'dev';
  return ENV[environment];
};

export default getEnvVars();
```

### 4. 性能与安全审查

发布前进行全面检查：

- 性能优化（参考[性能优化指南](./performance.md)）
- 安全审查（API 密钥保护、数据加密等）
- 代码混淆（特别是 Android）
- 删除调试代码和控制台日志

```javascript
// 生产环境禁用控制台日志
if (process.env.NODE_ENV === 'production') {
  console.log = () => {};
  console.warn = () => {};
  console.error = () => {};
}
```

## 版本管理

### 语义化版本控制

采用语义化版本号 (SemVer)：**主版本.次版本.补丁版本**

- 主版本：不兼容的 API 修改
- 次版本：向后兼容的功能新增
- 补丁版本：向后兼容的问题修复

### 更新 iOS 版本

在 Xcode 中更新 `Info.plist` 文件：

```xml
<key>CFBundleShortVersionString</key>
<string>1.0.0</string> <!-- 对应 versionName -->
<key>CFBundleVersion</key>
<string>1</string> <!-- 对应 versionCode，每次提交 App Store 必须递增 -->
```

### 更新 Android 版本

编辑 `android/app/build.gradle` 文件：

```gradle
android {
    defaultConfig {
        versionCode 1 // 整数值，每次更新时递增
        versionName "1.0.0" // 语义化版本号
    }
}
```

### 自动化版本管理

使用脚本自动更新版本号：

```javascript
// scripts/update-version.js
const fs = require('fs');
const path = require('path');

// 读取 package.json
const packageJsonPath = path.resolve(__dirname, '../package.json');
const packageJson = require(packageJsonPath);
const currentVersion = packageJson.version; // 例如 "1.0.0"

// 更新 iOS 版本
const infoPlistPath = path.resolve(__dirname, '../ios/YourApp/Info.plist');
let infoPlistContent = fs.readFileSync(infoPlistPath, 'utf8');
infoPlistContent = infoPlistContent.replace(
  /<key>CFBundleShortVersionString<\/key>\s*<string>[^<]+<\/string>/,
  `<key>CFBundleShortVersionString</key>\n\t<string>${currentVersion}</string>`
);
fs.writeFileSync(infoPlistPath, infoPlistContent);

// 更新 Android 版本
const buildGradlePath = path.resolve(__dirname, '../android/app/build.gradle');
let buildGradleContent = fs.readFileSync(buildGradlePath, 'utf8');
buildGradleContent = buildGradleContent.replace(
  /versionName "[^"]+"/,
  `versionName "${currentVersion}"`
);
fs.writeFileSync(buildGradlePath, buildGradleContent);

console.log(`版本已更新至 ${currentVersion}`);
```

## iOS 构建与发布

### 1. 证书与配置文件

在发布 iOS 应用前，需要在 [Apple Developer Portal](https://developer.apple.com/account/) 上设置：

1. **App ID**：应用的唯一标识符
2. **证书**：开发证书和发布证书
3. **配置文件**：包含证书和应用 ID 信息

可以通过 Xcode 自动管理证书和配置文件：
1. 打开 Xcode
2. 打开项目设置
3. 选择 "Signing & Capabilities"
4. 勾选 "Automatically manage signing"

### 2. 创建发布构建

#### 使用 Xcode 构建

1. 打开 Xcode
2. 选择 "Generic iOS Device" 作为目标设备
3. 选择 "Product" > "Archive"
4. 构建完成后，打开 "Window" > "Organizer"
5. 选择最新的归档文件，点击 "Distribute App"

#### 使用命令行构建

```bash
# 安装依赖
cd ios
pod install

# 清理项目
xcodebuild clean -workspace YourApp.xcworkspace -scheme YourApp -configuration Release

# 构建 .ipa 文件
xcodebuild archive -workspace YourApp.xcworkspace -scheme YourApp -configuration Release -archivePath build/YourApp.xcarchive
xcodebuild -exportArchive -archivePath build/YourApp.xcarchive -exportOptionsPlist ExportOptions.plist -exportPath build/
```

ExportOptions.plist 示例：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key>
    <string>app-store</string>
    <key>teamID</key>
    <string>YOUR_TEAM_ID</string>
</dict>
</plist>
```

### 3. TestFlight 测试

在正式发布前，使用 TestFlight 进行测试：

1. 在 [App Store Connect](https://appstoreconnect.apple.com/) 创建应用
2. 上传构建好的应用
3. 添加测试人员
4. 发送邀请
5. 收集反馈并修复问题

### 4. 提交到 App Store

1. 在 App Store Connect 完成应用信息：
   - 应用名称和描述
   - 关键词
   - 屏幕截图（不同设备尺寸）
   - 隐私政策 URL
   - 分级信息
2. 选择测试通过的构建版本
3. 提交审核
4. 等待审核结果（通常需要 1-2 天）
5. 获得批准后发布

## Android 构建与发布

### 1. 签名配置

创建发布密钥：

```bash
keytool -genkeypair -v -keystore my-release-key.keystore -alias my-key-alias -keyalg RSA -keysize 2048 -validity 10000
```

在 `android/app/build.gradle` 中配置签名：

```gradle
android {
    defaultConfig { /* ... */ }
    signingConfigs {
        release {
            storeFile file('my-release-key.keystore')
            storePassword 'your-store-password'
            keyAlias 'my-key-alias'
            keyPassword 'your-key-password'
        }
    }
    buildTypes {
        release {
            signingConfig signingConfigs.release
            minifyEnabled true
            proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
        }
    }
}
```

为安全起见，不要将密码直接放在构建文件中，而是使用环境变量或 `gradle.properties`：

```gradle
// build.gradle
signingConfigs {
    release {
        storeFile file('my-release-key.keystore')
        storePassword System.getenv("STORE_PASSWORD")
        keyAlias System.getenv("KEY_ALIAS")
        keyPassword System.getenv("KEY_PASSWORD")
    }
}

// 或者从 gradle.properties 读取
signingConfigs {
    release {
        storeFile file('my-release-key.keystore')
        storePassword STORE_PASSWORD
        keyAlias KEY_ALIAS
        keyPassword KEY_PASSWORD
    }
}
```

### 2. 创建发布构建

#### 使用命令行构建 APK

```bash
cd android
./gradlew assembleRelease
```

生成的 APK 文件位于 `android/app/build/outputs/apk/release/app-release.apk`

#### 创建 Android App Bundle (AAB)

```bash
cd android
./gradlew bundleRelease
```

生成的 AAB 文件位于 `android/app/build/outputs/bundle/release/app-release.aab`

### 3. 测试发布构建

在发布前测试构建：

```bash
# 安装 APK 到连接的设备
adb install app/build/outputs/apk/release/app-release.apk

# 或使用 Android Studio 的内部测试功能
```

### 4. 发布到 Google Play

1. 创建 [Google Play 开发者账号](https://play.google.com/apps/publish/)
2. 创建新应用
3. 填写应用信息：
   - 应用名称和描述
   - 分类
   - 内容分级
   - 隐私政策
4. 上传应用资源：
   - 图标
   - 特色图片
   - 屏幕截图（不同设备尺寸）
5. 上传 AAB 或 APK 文件
6. 设置发布轨道（内部测试、封闭测试、开放测试或生产）
7. 提交审核

## 自动化构建

### 使用 Fastlane 自动化

[Fastlane](https://fastlane.tools/) 是一个流行的自动化工具，可以简化构建和发布流程。

#### 安装 Fastlane

```bash
# 安装 Fastlane
gem install fastlane

# 初始化 Fastlane
cd ios # 或 android
fastlane init
```

#### iOS 自动化示例

创建 `ios/fastlane/Fastfile`：

```ruby
default_platform(:ios)

platform :ios do
  desc "构建并上传到 TestFlight"
  lane :beta do
    increment_build_number
    build_app(workspace: "YourApp.xcworkspace", scheme: "YourApp")
    upload_to_testflight
  end
  
  desc "构建并发布到 App Store"
  lane :release do
    increment_build_number
    build_app(workspace: "YourApp.xcworkspace", scheme: "YourApp")
    upload_to_app_store(
      skip_metadata: true,
      skip_screenshots: true
    )
  end
end
```

运行命令：

```bash
cd ios
fastlane beta # 或 fastlane release
```

#### Android 自动化示例

创建 `android/fastlane/Fastfile`：

```ruby
default_platform(:android)

platform :android do
  desc "构建并上传到 Play Store 内部测试轨道"
  lane :beta do
    gradle(task: "clean assembleRelease")
    upload_to_play_store(
      track: 'internal',
      aab: "app/build/outputs/bundle/release/app-release.aab"
    )
  end
  
  desc "构建并发布到 Play Store 生产轨道"
  lane :release do
    gradle(task: "clean bundleRelease")
    upload_to_play_store(
      aab: "app/build/outputs/bundle/release/app-release.aab"
    )
  end
end
```

运行命令：

```bash
cd android
fastlane beta # 或 fastlane release
```

### 使用 CI/CD 服务

#### GitHub Actions 示例

创建 `.github/workflows/release.yml`：

```yaml
name: Release App

on:
  push:
    tags:
      - 'v*'

jobs:
  build-ios:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Ruby
        uses: ruby/setup-ruby@v1
        with:
          ruby-version: 2.7
      - name: Install dependencies
        run: |
          gem install bundler
          bundle install
          npm install
          cd ios && pod install
      - name: Build and Release iOS
        run: |
          cd ios
          bundle exec fastlane release
        env:
          APPLE_ID: ${{ secrets.APPLE_ID }}
          APP_STORE_CONNECT_API_KEY: ${{ secrets.APP_STORE_CONNECT_API_KEY }}
          MATCH_PASSWORD: ${{ secrets.MATCH_PASSWORD }}
          
  build-android:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up JDK
        uses: actions/setup-java@v2
        with:
          distribution: 'adopt'
          java-version: '11'
      - name: Set up Ruby
        uses: ruby/setup-ruby@v1
        with:
          ruby-version: 2.7
      - name: Install dependencies
        run: |
          gem install bundler
          bundle install
          npm install
      - name: Build and Release Android
        run: |
          echo $ANDROID_KEYSTORE_BASE64 | base64 --decode > android/app/my-release-key.keystore
          cd android
          bundle exec fastlane release
        env:
          ANDROID_KEYSTORE_BASE64: ${{ secrets.ANDROID_KEYSTORE_BASE64 }}
          STORE_PASSWORD: ${{ secrets.STORE_PASSWORD }}
          KEY_ALIAS: ${{ secrets.KEY_ALIAS }}
          KEY_PASSWORD: ${{ secrets.KEY_PASSWORD }}
          PLAY_STORE_JSON_KEY: ${{ secrets.PLAY_STORE_JSON_KEY }}
```

## 应用内更新

### 使用 CodePush

[CodePush](https://github.com/microsoft/react-native-code-push) 允许你在不发布新版本的情况下更新 JavaScript 和资源。

#### 安装 CodePush

```bash
npm install react-native-code-push
npx react-native link react-native-code-push
```

#### 配置应用

```javascript
// App.js
import codePush from "react-native-code-push";

const codePushOptions = {
  checkFrequency: codePush.CheckFrequency.ON_APP_START,
  installMode: codePush.InstallMode.IMMEDIATE
};

const App = () => {
  // 应用代码
};

export default codePush(codePushOptions)(App);
```

#### 发布更新

```bash
# 安装 AppCenter CLI
npm install -g appcenter-cli

# 登录
appcenter login

# 发布更新
appcenter codepush release-react -a <username>/<appname> -d Production
```

## 常见问题与解决方案

### 1. iOS 构建失败

**问题**: Xcode 构建错误或签名问题。

**解决方案**:
- 清理构建目录: Xcode > Product > Clean Build Folder
- 检查证书和配置文件
- 更新 CocoaPods: `pod install --repo-update`

### 2. Android 构建失败

**问题**: Gradle 构建错误。

**解决方案**:
- 清理构建: `cd android && ./gradlew clean`
- 检查 Gradle 版本兼容性
- 检查签名配置

### 3. 应用被拒

**问题**: App Store 或 Google Play 审核拒绝。

**解决方案**:
- 仔细阅读拒绝原因
- 遵循平台指南
- 解决特定问题后重新提交

### 4. 版本升级问题

**问题**: 应用更新后用户数据丢失。

**解决方案**:
- 实现适当的数据迁移策略
- 在重大更新前做充分测试
- 考虑使用 CodePush 进行非破坏性更新

## 发布检查清单

在发布应用前，确保检查以下项目：

- [ ] 应用版本已更新
- [ ] 所有文本和资源已本地化
- [ ] 已移除调试代码和日志
- [ ] 已测试生产环境 API 连接
- [ ] 已完成所有平台的测试
- [ ] 隐私政策符合最新规定
- [ ] 应用图标和启动屏幕已正确设置
- [ ] 权限使用说明已更新
- [ ] 发布说明已准备
- [ ] 应用商店截图和元数据已更新
- [ ] 付费功能已测试
- [ ] 性能和内存使用已优化

## 最佳实践

### 版本发布策略

1. **渐进式发布**:
   - 使用 TestFlight 和 Google Play 的阶段性发布
   - 先发布给内部测试人员，然后扩大到更多用户

2. **发布节奏**:
   - 保持规律的发布频率（如每两周或每月）
   - 重大功能更新与小型修复分开发布

3. **紧急修复**:
   - 为关键问题预留快速发布通道
   - 使用 CodePush 进行紧急 JS 修复

### 安全最佳实践

1. **密钥管理**:
   - 使用环境变量存储敏感信息
   - 避免将密钥直接放入代码

2. **代码保护**:
   - 启用 JavaScript 代码混淆
   - 使用 ProGuard 混淆 Android 代码

3. **API 安全**:
   - 实现 API 请求签名和验证
   - 使用 HTTPS 和证书固定

### 持续集成与部署

1. **自动化测试**:
   - 集成单元测试和 UI 测试
   - 在每次提交后运行测试

2. **自动构建**:
   - 设置定期夜间构建
   - 自动生成测试版本供团队使用

3. **部署自动化**:
   - 使用 Fastlane 自动化发布流程
   - 将版本标签与构建关联

通过遵循这些最佳实践和指南，你可以简化 React Native 应用的构建和发布过程，提高效率并减少错误。随着应用的成长，这些流程可以进一步优化和自动化，以适应你的团队需求。 