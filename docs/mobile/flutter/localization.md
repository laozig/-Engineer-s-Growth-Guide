# Flutter 国际化与本地化

## 目录

- [概述](#概述)
- [基础设置](#基础设置)
  - [依赖项配置](#依赖项配置)
  - [支持的语言配置](#支持的语言配置)
- [使用 Flutter Intl 包](#使用-flutter-intl-包)
  - [设置与配置](#设置与配置)
  - [生成本地化文件](#生成本地化文件)
  - [使用生成的消息](#使用生成的消息)
- [手动实现国际化](#手动实现国际化)
  - [创建本地化类](#创建本地化类)
  - [本地化委托](#本地化委托)
  - [加载和切换语言](#加载和切换语言)
- [文化适配](#文化适配)
  - [日期和时间格式](#日期和时间格式)
  - [数字和货币格式](#数字和货币格式)
  - [RTL（从右到左）支持](#rtl从右到左支持)
- [资源本地化](#资源本地化)
  - [图片资源](#图片资源)
  - [其他资源](#其他资源)
- [最佳实践](#最佳实践)
- [常见问题及解决方案](#常见问题及解决方案)
- [完整示例](#完整示例)

## 概述

国际化（Internationalization，通常缩写为 i18n）和本地化（Localization，通常缩写为 l10n）是使应用程序能够适应不同语言和地区需求的过程。Flutter 提供了强大的工具和库来支持这些功能，使开发者能够创建真正全球化的应用程序。

- **国际化 (i18n)**: 设计和开发应用程序，使其可以适应不同的语言和地区。
- **本地化 (l10n)**: 将应用程序的文本和资源翻译成特定语言和地区的过程。

## 基础设置

### 依赖项配置

首先，在 `pubspec.yaml` 文件中添加必要的依赖：

```yaml
dependencies:
  flutter:
    sdk: flutter
  flutter_localizations:
    sdk: flutter
  intl: ^0.18.0  # 使用最新版本
```

### 支持的语言配置

在 `pubspec.yaml` 文件中，声明应用程序支持的语言：

```yaml
flutter:
  generate: true  # 这将启用自动生成本地化代码
  uses-material-design: true
```

在 `l10n.yaml` 文件（在项目根目录创建）中配置本地化设置：

```yaml
arb-dir: lib/l10n
template-arb-file: app_en.arb
output-localization-file: app_localizations.dart
output-class: AppLocalizations
```

## 使用 Flutter Intl 包

Flutter 官方建议使用 ARB 文件（Application Resource Bundle）来管理本地化字符串。

### 设置与配置

创建 `lib/l10n` 目录，然后添加模板 ARB 文件。例如，`app_en.arb`（英语）：

```json
{
  "helloWorld": "Hello World",
  "@helloWorld": {
    "description": "The conventional greeting"
  },
  "welcome": "Welcome {name}",
  "@welcome": {
    "description": "Welcome message",
    "placeholders": {
      "name": {
        "type": "String",
        "example": "John"
      }
    }
  }
}
```

添加中文翻译 `app_zh.arb`：

```json
{
  "helloWorld": "你好，世界",
  "welcome": "欢迎 {name}"
}
```

### 生成本地化文件

运行 Flutter 命令生成本地化文件：

```bash
flutter gen-l10n
```

### 使用生成的消息

在 `MaterialApp` 中配置本地化支持：

```dart
import 'package:flutter/material.dart';
import 'package:flutter_gen/gen_l10n/app_localizations.dart';
import 'package:flutter_localizations/flutter_localizations.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter本地化示例',
      // 设置本地化资源委托
      localizationsDelegates: const [
        AppLocalizations.delegate, // 应用程序特定的本地化委托
        GlobalMaterialLocalizations.delegate, // Material 组件本地化
        GlobalWidgetsLocalizations.delegate, // 基本部件本地化
        GlobalCupertinoLocalizations.delegate, // iOS 部件本地化
      ],
      // 支持的语言列表
      supportedLocales: const [
        Locale('en', ''), // 英语
        Locale('zh', ''), // 中文
        // 可以添加更多语言
      ],
      // 使用设备语言
      localeResolutionCallback: (locale, supportedLocales) {
        for (var supportedLocale in supportedLocales) {
          if (supportedLocale.languageCode == locale?.languageCode) {
            return supportedLocale;
          }
        }
        return supportedLocales.first; // 默认为第一种支持的语言
      },
      home: const MyHomePage(),
    );
  }
}

class MyHomePage extends StatelessWidget {
  const MyHomePage({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    // 获取当前本地化实例
    final localizations = AppLocalizations.of(context)!;
    
    return Scaffold(
      appBar: AppBar(
        title: Text(localizations.helloWorld),
      ),
      body: Center(
        child: Text(localizations.welcome('张三')),
      ),
    );
  }
}
```

## 手动实现国际化

如果你需要更多控制，可以手动实现国际化系统。

### 创建本地化类

```dart
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

class AppLocalizations {
  final Locale locale;
  
  AppLocalizations(this.locale);
  
  // 静态方法，用于在整个应用程序中访问本地化实例
  static AppLocalizations of(BuildContext context) {
    return Localizations.of<AppLocalizations>(context, AppLocalizations)!;
  }
  
  // 静态代理类
  static const LocalizationsDelegate<AppLocalizations> delegate = _AppLocalizationsDelegate();
  
  // 不同语言的翻译映射
  static final Map<String, Map<String, String>> _localizedValues = {
    'en': {
      'hello_world': 'Hello World',
      'welcome': 'Welcome',
    },
    'zh': {
      'hello_world': '你好，世界',
      'welcome': '欢迎',
    },
  };
  
  String get helloWorld {
    return _localizedValues[locale.languageCode]?['hello_world'] ?? 'Hello World';
  }
  
  String get welcome {
    return _localizedValues[locale.languageCode]?['welcome'] ?? 'Welcome';
  }
}

// 本地化委托类
class _AppLocalizationsDelegate extends LocalizationsDelegate<AppLocalizations> {
  const _AppLocalizationsDelegate();
  
  @override
  bool isSupported(Locale locale) {
    // 定义支持的语言
    return ['en', 'zh'].contains(locale.languageCode);
  }
  
  @override
  Future<AppLocalizations> load(Locale locale) {
    // 返回本地化实例
    return SynchronousFuture<AppLocalizations>(AppLocalizations(locale));
  }
  
  @override
  bool shouldReload(covariant LocalizationsDelegate<AppLocalizations> old) => false;
}
```

### 本地化委托

在 `MaterialApp` 中注册本地化委托：

```dart
MaterialApp(
  // 其他配置...
  localizationsDelegates: const [
    AppLocalizations.delegate,
    GlobalMaterialLocalizations.delegate,
    GlobalWidgetsLocalizations.delegate,
    GlobalCupertinoLocalizations.delegate,
  ],
  supportedLocales: const [
    Locale('en', ''),
    Locale('zh', ''),
  ],
  // 其他配置...
)
```

### 加载和切换语言

使用 Provider 或其他状态管理解决方案来动态更改应用程序的语言：

```dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

class LocaleProvider with ChangeNotifier {
  Locale _locale = const Locale('en');
  
  Locale get locale => _locale;
  
  void setLocale(Locale locale) {
    _locale = locale;
    notifyListeners();
  }
}

// 在应用程序中使用
void main() {
  runApp(
    ChangeNotifierProvider(
      create: (_) => LocaleProvider(),
      child: const MyApp(),
    ),
  );
}

class MyApp extends StatelessWidget {
  const MyApp({Key? key}) : super(key: key);
  
  @override
  Widget build(BuildContext context) {
    return Consumer<LocaleProvider>(
      builder: (context, provider, child) {
        return MaterialApp(
          locale: provider.locale, // 使用 Provider 中的语言环境
          // 其他本地化配置...
          home: const LanguageSwitcher(),
        );
      },
    );
  }
}

// 语言切换界面
class LanguageSwitcher extends StatelessWidget {
  const LanguageSwitcher({Key? key}) : super(key: key);
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Text(AppLocalizations.of(context).helloWorld),
            const SizedBox(height: 20),
            ElevatedButton(
              onPressed: () {
                final provider = Provider.of<LocaleProvider>(context, listen: false);
                // 切换到英语
                provider.setLocale(const Locale('en'));
              },
              child: const Text('English'),
            ),
            ElevatedButton(
              onPressed: () {
                final provider = Provider.of<LocaleProvider>(context, listen: false);
                // 切换到中文
                provider.setLocale(const Locale('zh'));
              },
              child: const Text('中文'),
            ),
          ],
        ),
      ),
    );
  }
}
```

## 文化适配

### 日期和时间格式

使用 `intl` 包来正确格式化日期和时间：

```dart
import 'package:intl/intl.dart';

String formatDate(DateTime date, String locale) {
  return DateFormat.yMMMMd(locale).format(date);
}

String formatTime(DateTime time, String locale) {
  return DateFormat.Hms(locale).format(time);
}

// 使用示例
void showFormattedDateTime(BuildContext context) {
  final now = DateTime.now();
  final locale = Localizations.localeOf(context).languageCode;
  
  final formattedDate = formatDate(now, locale);
  final formattedTime = formatTime(now, locale);
  
  print('Date: $formattedDate');
  print('Time: $formattedTime');
}
```

### 数字和货币格式

同样使用 `intl` 包格式化数字和货币：

```dart
import 'package:intl/intl.dart';

String formatNumber(num number, String locale) {
  return NumberFormat.decimalPattern(locale).format(number);
}

String formatCurrency(num amount, String locale, String currencyCode) {
  return NumberFormat.currency(locale: locale, symbol: currencyCode).format(amount);
}

// 使用示例
void showFormattedNumbers(BuildContext context) {
  final locale = Localizations.localeOf(context).languageCode;
  
  final formattedNumber = formatNumber(1234567.89, locale);
  final formattedCurrency = formatCurrency(1234567.89, locale, '¥');
  
  print('Number: $formattedNumber');
  print('Currency: $formattedCurrency');
}
```

### RTL（从右到左）支持

Flutter 内置了对 RTL（从右到左）语言的支持，如阿拉伯语和希伯来语：

```dart
import 'package:flutter/material.dart';

// 在 Widget 中使用 Directionality
Widget buildRtlAwareWidget() {
  return Directionality(
    textDirection: TextDirection.rtl, // 或使用 TextDirection.ltr
    child: Row(
      children: [
        Icon(Icons.arrow_back),
        SizedBox(width: 8),
        Text('返回'),
      ],
    ),
  );
}

// 在大多数情况下，不需要手动指定，Flutter 会根据语言自动设置文本方向
MaterialApp(
  // 其他配置...
  supportedLocales: const [
    Locale('en', ''), // 英语，LTR
    Locale('zh', ''), // 中文，LTR
    Locale('ar', ''), // 阿拉伯语，RTL
    Locale('he', ''), // 希伯来语，RTL
  ],
)
```

## 资源本地化

### 图片资源

为不同语言提供不同的图片资源：

```
assets/
  images/
    en/
      logo.png
    zh/
      logo.png
```

在代码中根据当前语言选择适当的图片：

```dart
Widget buildLocalizedImage(BuildContext context) {
  final locale = Localizations.localeOf(context).languageCode;
  return Image.asset('assets/images/$locale/logo.png');
}
```

### 其他资源

同样可以本地化其他资源，如音频文件或视频：

```dart
String getLocalizedAssetPath(BuildContext context, String assetName) {
  final locale = Localizations.localeOf(context).languageCode;
  return 'assets/$locale/$assetName';
}

// 使用示例
Widget buildLocalizedAudio(BuildContext context) {
  final audioPath = getLocalizedAssetPath(context, 'welcome.mp3');
  // 使用 audioPath 加载音频
  return Container();
}
```

## 最佳实践

1. **早期规划国际化**：从项目开始就考虑国际化，而不是在项目后期才添加。

2. **避免硬编码字符串**：所有用户可见的文本都应该本地化，避免在代码中直接硬编码字符串。

3. **上下文化翻译**：为翻译人员提供上下文信息，使翻译更加准确。

4. **处理文本扩展**：翻译后的文本长度可能比原始文本长或短，确保 UI 能够适应不同长度的文本。

5. **测试各种语言**：在所有支持的语言中测试应用程序，确保布局和功能正常。

6. **单独管理翻译文件**：将翻译文件与代码分开管理，使非开发人员也能参与翻译过程。

7. **记录区域特定问题**：记录任何与特定地区或文化相关的特殊处理。

## 常见问题及解决方案

### 问题1：翻译文本未显示

**原因**：可能没有正确配置本地化委托或者 ARB 文件中缺少翻译字符串。

**解决方案**：
- 确保在 `MaterialApp` 中正确配置了 `localizationsDelegates` 和 `supportedLocales`
- 检查 ARB 文件中是否包含所有需要的翻译

### 问题2：应用未使用设备语言

**原因**：可能没有实现 `localeResolutionCallback` 或者设备语言不在支持的语言列表中。

**解决方案**：
```dart
localeResolutionCallback: (deviceLocale, supportedLocales) {
  for (var locale in supportedLocales) {
    if (locale.languageCode == deviceLocale?.languageCode) {
      return deviceLocale;
    }
  }
  return supportedLocales.first; // 默认语言
}
```

### 问题3：文本溢出

**原因**：翻译后的文本可能比原文长。

**解决方案**：
- 使用 `Flexible` 或 `Expanded` 包装文本组件
- 使用 `FittedBox` 缩放文本
- 为长文本设计可滚动的 UI

## 完整示例

以下是一个完整的国际化应用示例：

```dart
import 'package:flutter/material.dart';
import 'package:flutter_gen/gen_l10n/app_localizations.dart';
import 'package:flutter_localizations/flutter_localizations.dart';

void main() {
  runApp(const LocalizationDemoApp());
}

class LocalizationDemoApp extends StatefulWidget {
  const LocalizationDemoApp({Key? key}) : super(key: key);

  @override
  State<LocalizationDemoApp> createState() => _LocalizationDemoAppState();
}

class _LocalizationDemoAppState extends State<LocalizationDemoApp> {
  Locale _locale = const Locale('en');

  void _setLocale(Locale locale) {
    setState(() {
      _locale = locale;
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter 国际化演示',
      theme: ThemeData(
        primarySwatch: Colors.blue,
        visualDensity: VisualDensity.adaptivePlatformDensity,
      ),
      locale: _locale,
      localizationsDelegates: const [
        AppLocalizations.delegate,
        GlobalMaterialLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
      ],
      supportedLocales: const [
        Locale('en', ''), // 英语
        Locale('zh', ''), // 中文
      ],
      home: LocalizationHomePage(onLocaleChanged: _setLocale),
    );
  }
}

class LocalizationHomePage extends StatefulWidget {
  final void Function(Locale) onLocaleChanged;
  
  const LocalizationHomePage({Key? key, required this.onLocaleChanged}) : super(key: key);

  @override
  State<LocalizationHomePage> createState() => _LocalizationHomePageState();
}

class _LocalizationHomePageState extends State<LocalizationHomePage> {
  final _nameController = TextEditingController(text: '张三');

  @override
  void dispose() {
    _nameController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final localizations = AppLocalizations.of(context)!;
    final currentLocale = Localizations.localeOf(context);
    
    return Scaffold(
      appBar: AppBar(
        title: Text(localizations.helloWorld),
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              localizations.welcome(_nameController.text),
              style: Theme.of(context).textTheme.headlineSmall,
            ),
            const SizedBox(height: 20),
            TextField(
              controller: _nameController,
              decoration: InputDecoration(
                labelText: localizations.nameFieldLabel,
                border: const OutlineInputBorder(),
              ),
              onChanged: (value) {
                setState(() {});
              },
            ),
            const SizedBox(height: 40),
            Text(
              '当前语言: ${currentLocale.languageCode}',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 20),
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceEvenly,
              children: [
                ElevatedButton(
                  onPressed: () {
                    widget.onLocaleChanged(const Locale('en'));
                  },
                  child: const Text('English'),
                ),
                ElevatedButton(
                  onPressed: () {
                    widget.onLocaleChanged(const Locale('zh'));
                  },
                  child: const Text('中文'),
                ),
              ],
            ),
            const SizedBox(height: 40),
            // 显示本地化的日期和时间
            Text(
              '当前日期: ${_getLocalizedDate(context)}',
              style: Theme.of(context).textTheme.bodyLarge,
            ),
            const SizedBox(height: 10),
            Text(
              '当前货币: ${_getLocalizedCurrency(context, 1234.56)}',
              style: Theme.of(context).textTheme.bodyLarge,
            ),
          ],
        ),
      ),
    );
  }

  String _getLocalizedDate(BuildContext context) {
    final locale = Localizations.localeOf(context).languageCode;
    return DateFormat.yMMMMd(locale).format(DateTime.now());
  }

  String _getLocalizedCurrency(BuildContext context, double amount) {
    final locale = Localizations.localeOf(context).languageCode;
    final currencySymbol = locale == 'zh' ? '¥' : '\$';
    return NumberFormat.currency(locale: locale, symbol: currencySymbol).format(amount);
  }
}
```

要完成此示例，需要创建相应的 ARB 文件：

**lib/l10n/app_en.arb:**
```json
{
  "helloWorld": "Hello World",
  "@helloWorld": {
    "description": "The conventional greeting"
  },
  "welcome": "Welcome, {name}!",
  "@welcome": {
    "description": "Welcome message",
    "placeholders": {
      "name": {
        "type": "String",
        "example": "John"
      }
    }
  },
  "nameFieldLabel": "Enter your name",
  "@nameFieldLabel": {
    "description": "Label for the name input field"
  }
}
```

**lib/l10n/app_zh.arb:**
```json
{
  "helloWorld": "你好，世界",
  "welcome": "欢迎，{name}！",
  "nameFieldLabel": "输入您的姓名"
}
```

通过这个完整示例，你可以看到如何实现语言切换、本地化文本、日期和货币格式化等功能。

国际化和本地化是让你的应用程序在全球范围内可用的重要一步。通过遵循本文档中的指导和最佳实践，你可以确保你的 Flutter 应用程序能够无缝地适应不同的语言和文化环境。
