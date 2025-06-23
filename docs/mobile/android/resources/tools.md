# 开发工具

本文档介绍Android开发过程中使用的各类工具，包括集成开发环境（IDE）、调试工具、构建工具和性能分析工具等，帮助开发者提高开发效率和产品质量。

## 集成开发环境 (IDE)

### Android Studio
**官网**: [developer.android.com/studio](https://developer.android.com/studio)  
**类型**: 官方IDE  
**功能特点**:
- 基于IntelliJ IDEA的全功能IDE
- 内置Android模拟器
- 可视化布局编辑器
- 智能代码编辑器
- 实时分析器和性能工具
- 集成版本控制
- Gradle构建系统

**实用技巧**:
- 使用**Live Templates**加速常用代码片段输入（Settings > Editor > Live Templates）
- 启用**Lint**检查，及早发现潜在问题
- 利用**Memory Profiler**监控应用内存使用
- 使用**Layout Inspector**实时分析UI层次结构

### Visual Studio Code + Android插件
**官网**: [code.visualstudio.com](https://code.visualstudio.com/)  
**类型**: 轻量级编辑器+插件  
**优势**:
- 启动速度快
- 占用资源少
- 可通过插件扩展功能
- 适合轻量级开发或特定场景（如React Native开发）

**主要插件**:
- **Android iOS Emulator**: 直接从VS Code启动模拟器
- **Kotlin Language**: Kotlin语言支持
- **Gradle Language**: Gradle构建脚本支持

## 调试工具

### ADB (Android Debug Bridge)
**官网**: [developer.android.com/studio/command-line/adb](https://developer.android.com/studio/command-line/adb)  
**类型**: 命令行工具  
**主要功能**:
- 安装/卸载应用
- 复制文件
- 查看日志（logcat）
- 运行shell命令
- 调试应用程序

**常用命令**:
```bash
# 列出连接的设备
adb devices

# 安装应用
adb install path/to/app.apk

# 卸载应用
adb uninstall com.example.app

# 显示日志
adb logcat

# 将文件复制到设备
adb push local/path device/path

# 从设备复制文件
adb pull device/path local/path

# 在设备上运行shell命令
adb shell <command>

# 重启设备
adb reboot
```

### Logcat
**位置**: Android Studio > View > Tool Windows > Logcat  
**类型**: 日志查看器  
**功能**:
- 实时查看应用日志
- 按包名、日志级别、文本过滤
- 彩色编码不同级别的日志
- 保存日志到文件

**技巧**:
- 使用自定义过滤器保存常用搜索条件
- 结合正则表达式进行高级过滤
- 用`Log.d("TAG", "message")`或Timber等工具在代码中添加日志

### Layout Inspector
**位置**: Android Studio > View > Tool Windows > Layout Inspector  
**类型**: UI调试工具  
**功能**:
- 实时查看应用UI结构
- 检查视图属性和层次
- 对比布局与设计图
- 分析布局性能问题

## 构建工具

### Gradle
**官网**: [gradle.org](https://gradle.org/)  
**类型**: 构建自动化工具  
**功能**:
- 管理依赖
- 配置构建变体（debug/release等）
- 执行自定义构建任务
- 生成不同版本的APK/AAB

**重要概念**:
- **build.gradle (项目级)**: 定义全局配置和子项目通用设置
- **build.gradle (模块级)**: 定义特定模块的配置，如应用版本、依赖等
- **gradle.properties**: 定义全局属性，如内存设置
- **settings.gradle**: 配置项目结构，定义包含哪些模块

**常用任务**:
```bash
# 清理构建
./gradlew clean

# 编译项目
./gradlew build

# 安装debug版本
./gradlew installDebug

# 运行单元测试
./gradlew test

# 运行UI测试
./gradlew connectedAndroidTest

# 生成APK
./gradlew assembleRelease

# 生成AAB
./gradlew bundleRelease
```

### Maven
**官网**: [maven.apache.org](https://maven.apache.org/)  
**类型**: 构建自动化工具  
**功能**: 与Gradle类似，但在Android中使用较少
**用途**: 主要用于发布库到Maven仓库

## 性能分析工具

### Android Profiler
**位置**: Android Studio > View > Tool Windows > Profiler  
**类型**: 性能分析套件  
**组件**:
- **CPU Profiler**: 分析CPU使用率、检测方法跟踪
- **Memory Profiler**: 监控内存分配、查找内存泄漏
- **Network Profiler**: 检查网络活动、分析请求响应
- **Energy Profiler**: 分析电池消耗、找出耗电问题

**使用场景**:
- 分析UI卡顿
- 调查内存泄漏
- 优化网络请求
- 改善电池性能

### Firebase Performance Monitoring
**官网**: [firebase.google.com/products/performance](https://firebase.google.com/products/performance)  
**类型**: 云端性能监控  
**功能**:
- 真实用户应用性能监控
- 自动跟踪页面加载和网络请求
- 自定义跟踪关键用户操作
- 性能数据分析和报告

**优势**:
- 可以在真实用户设备上收集数据
- 无需用户手动报告问题
- 发现特定设备或区域的性能问题

## UI设计工具

### Android UI设计器
**位置**: Android Studio内置  
**类型**: 布局设计工具  
**功能**:
- 可视化编辑XML布局
- 拖放组件
- 实时预览不同设备/主题
- 约束布局可视化编辑

### Material Theme Editor
**位置**: Android Studio > Tools > Material Theme Builder  
**类型**: 主题设计工具  
**功能**:
- 创建和自定义Material Design主题
- 预览不同组件的外观
- 生成主题相关代码

### Figma与Android导出
**官网**: [figma.com](https://www.figma.com/)  
**类型**: UI/UX设计工具  
**Android集成**:
- 导出资源为Android可用格式
- 生成尺寸和颜色值
- 插件支持转换为Compose代码

## 测试工具

### Espresso
**官网**: [developer.android.com/training/testing/espresso](https://developer.android.com/training/testing/espresso)  
**类型**: UI测试框架  
**功能**:
- 编写UI自动化测试
- 模拟用户交互
- 检查UI状态和内容

**示例**:
```kotlin
@Test
fun greeterSaysHello() {
    // 输入文本
    onView(withId(R.id.name_field))
        .perform(typeText("Steve"), closeSoftKeyboard())
    
    // 点击按钮
    onView(withId(R.id.greet_button)).perform(click())
    
    // 检查结果
    onView(withId(R.id.greeting))
        .check(matches(withText("Hello Steve!")))
}
```

### JUnit
**官网**: [junit.org](https://junit.org/)  
**类型**: 单元测试框架  
**功能**:
- 编写和运行单元测试
- 验证代码行为
- 支持测试参数化和分组

**示例**:
```kotlin
class CalculatorTest {
    @Test
    fun addition_isCorrect() {
        val calculator = Calculator()
        assertEquals(4, calculator.add(2, 2))
    }
}
```

### Mockito
**官网**: [site.mockito.org](https://site.mockito.org/)  
**类型**: 模拟框架  
**功能**:
- 创建测试替身（模拟对象）
- 验证方法调用
- 设置返回值和异常

**示例**:
```kotlin
@Test
fun fetchAndProcessData() {
    // 创建模拟对象
    val mockApi = mock(ApiService::class.java)
    
    // 设置模拟行为
    `when`(mockApi.getData()).thenReturn(listOf("item1", "item2"))
    
    val processor = DataProcessor(mockApi)
    processor.processData()
    
    // 验证模拟对象的方法被调用
    verify(mockApi).getData()
}
```

## 辅助工具

### Scrcpy
**GitHub**: [github.com/Genymobile/scrcpy](https://github.com/Genymobile/scrcpy)  
**类型**: 设备屏幕镜像工具  
**功能**:
- 在电脑上显示并控制Android设备
- 高性能（低延迟）
- 无需root
- 支持录制屏幕

**优势**:
- 便于演示和截图
- 使用键盘输入更快
- 方便在大屏幕上操作

### APK Analyzer
**位置**: Android Studio > Build > Analyze APK  
**类型**: APK分析工具  
**功能**:
- 检查APK大小和内容
- 分析DEX文件和方法数
- 查看资源文件和库
- 对比不同版本的APK

**用途**:
- 减小APK体积
- 调查特定问题
- 了解依赖库的影响

## 结论

选择合适的工具可以显著提高Android开发的效率和质量。除了本文档介绍的工具外，还有许多专门的工具可以解决特定问题。持续学习和掌握新工具是Android开发者必备的技能。 