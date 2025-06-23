# Android简介与环境搭建

## Android平台概述

Android是由Google开发的基于Linux内核的开源移动操作系统，主要用于智能手机、平板电脑、智能电视、智能手表等设备。作为全球最流行的移动操作系统之一，Android拥有庞大的用户群体和丰富的应用生态系统。

### Android系统架构

Android系统架构由以下几层组成：

1. **Linux内核层**：提供底层系统功能，如进程管理、内存管理、安全机制等
2. **硬件抽象层(HAL)**：提供标准接口，将硬件功能暴露给更高层的Java API框架
3. **原生C/C++库**：提供核心功能的原生库，如SQLite、WebKit、OpenGL等
4. **Android运行时(ART)**：执行Android应用的运行时环境，替代了早期的Dalvik虚拟机
5. **Java API框架**：开发者用于构建应用的Java类库
6. **系统应用**：预装的核心应用，如电话、短信、浏览器等

### Android版本历史

Android系统自2008年首次发布以来，经历了多个主要版本更新：

| 版本 | API级别 | 代号 | 发布年份 |
|------|---------|------|----------|
| Android 1.0 | 1 | (无代号) | 2008 |
| Android 1.5 | 3 | Cupcake (纸杯蛋糕) | 2009 |
| Android 2.2 | 8 | Froyo (冻酸奶) | 2010 |
| Android 4.0 | 14-15 | Ice Cream Sandwich (冰淇淋三明治) | 2011 |
| Android 4.4 | 19 | KitKat (奇巧) | 2013 |
| Android 5.0 | 21 | Lollipop (棒棒糖) | 2014 |
| Android 6.0 | 23 | Marshmallow (棉花糖) | 2015 |
| Android 7.0 | 24 | Nougat (牛轧糖) | 2016 |
| Android 8.0 | 26 | Oreo (奥利奥) | 2017 |
| Android 9.0 | 28 | Pie (派) | 2018 |
| Android 10 | 29 | (无代号) | 2019 |
| Android 11 | 30 | (无代号) | 2020 |
| Android 12 | 31 | (无代号) | 2021 |
| Android 13 | 33 | (无代号) | 2022 |
| Android 14 | 34 | (无代号) | 2023 |

## 开发环境搭建

### 安装Java开发工具包(JDK)

虽然现在Android开发主要使用Kotlin语言，但Android Studio仍需要JDK环境。

1. 访问[Oracle官网](https://www.oracle.com/java/technologies/javase-downloads.html)或使用OpenJDK
2. 下载并安装JDK 11或更高版本
3. 设置JAVA_HOME环境变量

### 安装Android Studio

Android Studio是官方的Android集成开发环境(IDE)，基于IntelliJ IDEA。

1. 访问[Android Studio官网](https://developer.android.com/studio)
2. 下载最新版本的Android Studio
3. 运行安装程序，按照向导完成安装
4. 首次启动时，Android Studio会引导你完成初始设置和SDK安装

### 配置Android SDK

Android SDK (Software Development Kit) 包含开发Android应用所需的工具和API：

1. 在Android Studio中，选择"Tools" > "SDK Manager"
2. 在"SDK Platforms"标签页中，选择你需要支持的Android版本
3. 在"SDK Tools"标签页中，确保以下组件已安装：
   - Android SDK Build-Tools
   - Android Emulator
   - Android SDK Platform-Tools
   - Google Play services
   - Android SDK Command-line Tools

### 创建Android虚拟设备(AVD)

Android虚拟设备是在计算机上模拟真实Android设备的工具：

1. 在Android Studio中，选择"Tools" > "AVD Manager"
2. 点击"Create Virtual Device"
3. 选择设备类型和型号（如Pixel手机）
4. 选择系统镜像（建议选择带有Google Play的镜像）
5. 配置AVD选项，如屏幕方向、内存大小等
6. 点击"Finish"完成创建

### 配置真机调试

使用真实设备进行应用测试通常比模拟器更准确：

1. 在Android设备上，进入"设置" > "关于手机"
2. 连续点击"版本号"7次，启用开发者选项
3. 返回设置，进入"开发者选项"
4. 启用"USB调试"
5. 使用USB线连接设备和计算机
6. 在设备上确认允许USB调试

## 创建第一个Android应用

### 创建新项目

1. 打开Android Studio，点击"New Project"
2. 选择"Empty Activity"模板
3. 配置项目：
   - 输入应用名称（如"HelloAndroid"）
   - 设置包名（如"com.example.helloandroid"）
   - 选择保存位置
   - 选择语言（Kotlin或Java）
   - 选择最低支持的API级别
4. 点击"Finish"创建项目

### 项目结构概览

Android项目的主要目录和文件：

- **app/src/main/java/**：存放Java/Kotlin源代码
- **app/src/main/res/**：存放资源文件
  - **layout/**：XML布局文件
  - **values/**：字符串、颜色、样式等资源
  - **drawable/**：图像资源
- **app/src/main/AndroidManifest.xml**：应用清单文件
- **app/build.gradle**：应用级构建配置
- **build.gradle**：项目级构建配置

### 运行应用

1. 确保已连接真机或已创建虚拟设备
2. 点击工具栏上的"Run"按钮或按Shift+F10
3. 选择目标设备
4. 等待应用构建和安装
5. 应用将在设备上启动

## 开发工具与资源

### 官方文档与资源

- [Android开发者官网](https://developer.android.com/)
- [Android API参考](https://developer.android.com/reference)
- [Android Jetpack](https://developer.android.com/jetpack)
- [Material Design指南](https://material.io/design)

### 有用的开发工具

- **Logcat**：查看应用日志
- **Layout Inspector**：分析和调试UI
- **Profiler**：监控应用性能
- **Device File Explorer**：浏览设备文件系统
- **APK Analyzer**：分析APK文件结构和大小

### 社区资源

- [Stack Overflow](https://stackoverflow.com/questions/tagged/android)
- [Android开发者Reddit](https://www.reddit.com/r/androiddev/)
- [GitHub上的Android开源项目](https://github.com/topics/android)

## 下一步学习

完成环境搭建后，建议继续学习：

- [Android基础组件](basic-components.md)：了解Activity、Fragment等核心组件
- [UI开发基础](ui-basics.md)：学习布局和界面设计
- [Kotlin编程](https://kotlinlang.org/docs/getting-started.html)：掌握Android开发的首选语言

通过本指南，你已经完成了Android开发环境的搭建，并了解了Android平台的基本概念。随着学习的深入，你将能够开发出功能丰富、用户体验出色的Android应用。 