# 路由与导航

在Flutter应用开发中，路由与导航是构建多页面应用的基础。本文档将介绍Flutter中的各种路由导航方法，从基础导航到高级路由管理。

## 基础概念

在Flutter中，"路由"（Route）指的是一个屏幕或页面，而"导航"（Navigation）是管理这些路由的过程。Flutter的导航系统基于栈结构，可以推入（push）或弹出（pop）路由。

### 路由的类型

1. **物理路由（MaterialPageRoute/CupertinoPageRoute）**：
   - 平台特定的页面切换动画
   - 内置的页面过渡效果

2. **自定义路由**：
   - 通过继承PageRouteBuilder创建自定义过渡动画
   - 可以完全控制过渡效果

3. **命名路由**：
   - 通过字符串名称标识路由
   - 集中式路由管理

## 基本导航

### 直接导航（Push & Pop）

最简单的导航方式是使用Navigator直接在路由栈上执行push和pop操作。

```dart
// 导航到新页面
Navigator.push(
  context,
  MaterialPageRoute(builder: (context) => SecondPage()),
);

// 返回上一页面
Navigator.pop(context);
```

### 传递参数

可以在导航时传递参数给目标页面：

```dart
// 传递参数
Navigator.push(
  context,
  MaterialPageRoute(
    builder: (context) => DetailPage(
      itemId: 123,
      title: '产品详情',
    ),
  ),
);

// 接收参数
class DetailPage extends StatelessWidget {
  final int itemId;
  final String title;
  
  const DetailPage({
    Key? key, 
    required this.itemId,
    required this.title,
  }) : super(key: key);
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(title)),
      body: Center(
        child: Text('Item ID: $itemId'),
      ),
    );
  }
}
```

### 返回结果

可以从页面返回数据：

```dart
// 导航并等待结果
Future<void> _navigateAndGetResult() async {
  final result = await Navigator.push(
    context,
    MaterialPageRoute(builder: (context) => SelectionPage()),
  );
  
  if (result != null) {
    // 处理返回结果
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('选择了: $result')),
    );
  }
}

// 在目标页面返回结果
Navigator.pop(context, '选择的值');
```

## 命名路由

命名路由允许通过字符串名称引用路由，这使得路由管理更加集中和有条理。

### 定义路由表

在MaterialApp中定义路由表：

```dart
MaterialApp(
  // 初始路由
  initialRoute: '/',
  
  // 路由表
  routes: {
    '/': (context) => HomePage(),
    '/details': (context) => DetailsPage(),
    '/settings': (context) => SettingsPage(),
    '/profile': (context) => ProfilePage(),
  },
);
```

### 使用命名路由

```dart
// 导航到命名路由
Navigator.pushNamed(
  context,
  '/details',
);

// 带参数的命名路由
Navigator.pushNamed(
  context,
  '/details',
  arguments: {'id': 123, 'title': '产品详情'},
);

// 获取参数
class DetailsPage extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final args = ModalRoute.of(context)!.settings.arguments as Map<String, dynamic>;
    final id = args['id'];
    final title = args['title'];
    
    return Scaffold(
      appBar: AppBar(title: Text(title)),
      body: Center(child: Text('ID: $id')),
    );
  }
}
```

### onGenerateRoute

对于需要动态生成的路由，可以使用onGenerateRoute：

```dart
MaterialApp(
  onGenerateRoute: (settings) {
    // 提取路由名称
    final name = settings.name;
    
    // 处理动态路由参数，例如: /item/123
    if (name != null && name.startsWith('/item/')) {
      final itemId = int.tryParse(name.substring(6)) ?? 0;
      
      return MaterialPageRoute(
        builder: (context) => ItemDetailPage(itemId: itemId),
        settings: settings,
      );
    }
    
    // 未找到匹配的路由
    return MaterialPageRoute(
      builder: (context) => NotFoundPage(),
      settings: settings,
    );
  },
);
```

### onUnknownRoute

处理未知路由：

```dart
MaterialApp(
  onUnknownRoute: (settings) {
    return MaterialPageRoute(
      builder: (context) => NotFoundPage(),
    );
  },
);
```

## 导航操作

### 基本导航操作

```dart
// 跳转到新页面
Navigator.pushNamed(context, '/details');

// 返回上一页面
Navigator.pop(context);

// 替换当前页面
Navigator.pushReplacementNamed(context, '/login');

// 跳转到新页面，并移除之前的所有页面
Navigator.pushNamedAndRemoveUntil(
  context,
  '/home',
  (route) => false, // 移除所有路由
);

// 跳转到新页面，并移除直到特定路由
Navigator.pushNamedAndRemoveUntil(
  context,
  '/details',
  ModalRoute.withName('/home'), // 保留"/home"路由
);

// 重复推送同一路由
Navigator.popAndPushNamed(context, '/details');
```

### 导航器键（Navigator Key）

使用全局导航键可以在不需要BuildContext的情况下进行导航：

```dart
// 定义一个全局导航键
final GlobalKey<NavigatorState> navigatorKey = GlobalKey<NavigatorState>();

// 在MaterialApp中使用
MaterialApp(
  navigatorKey: navigatorKey,
  // ...
);

// 在任何地方使用导航键进行导航
navigatorKey.currentState!.pushNamed('/details');
```

## 路由转场动画

### 内置转场动画

```dart
// 使用Material过渡动画
Navigator.push(
  context,
  MaterialPageRoute(
    builder: (context) => SecondPage(),
    fullscreenDialog: false, // 是否为全屏对话框
  ),
);

// 使用Cupertino过渡动画
Navigator.push(
  context,
  CupertinoPageRoute(
    builder: (context) => SecondPage(),
    fullscreenDialog: false,
  ),
);
```

### 自定义转场动画

```dart
// 创建自定义页面路由
Navigator.push(
  context,
  PageRouteBuilder(
    pageBuilder: (context, animation, secondaryAnimation) => SecondPage(),
    transitionsBuilder: (context, animation, secondaryAnimation, child) {
      // 淡入淡出效果
      return FadeTransition(
        opacity: animation,
        child: child,
      );
    },
    transitionDuration: Duration(milliseconds: 500), // 过渡动画持续时间
  ),
);
```

### 常见动画效果

```dart
// 滑动效果
SlideTransition(
  position: Tween<Offset>(
    begin: const Offset(1.0, 0.0),
    end: Offset.zero,
  ).animate(animation),
  child: child,
);

// 缩放效果
ScaleTransition(
  scale: animation,
  child: child,
);

// 旋转效果
RotationTransition(
  turns: animation,
  child: child,
);

// 组合动画
SlideTransition(
  position: Tween<Offset>(
    begin: const Offset(0.0, 1.0),
    end: Offset.zero,
  ).animate(animation),
  child: FadeTransition(
    opacity: animation,
    child: child,
  ),
);
```

## 嵌套导航器

在Flutter中，可以使用嵌套导航器来管理应用内的不同部分，例如标签页内的导航。

### 基本嵌套导航器

```dart
class NestedNavigationDemo extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('嵌套导航器')),
      body: Navigator(
        // 初始路由
        initialRoute: 'nested/home',
        
        // 嵌套导航器的路由表
        onGenerateRoute: (settings) {
          switch (settings.name) {
            case 'nested/home':
              return MaterialPageRoute(
                builder: (context) => NestedHomePage(),
                settings: settings,
              );
            case 'nested/details':
              return MaterialPageRoute(
                builder: (context) => NestedDetailsPage(),
                settings: settings,
              );
            default:
              return null;
          }
        },
      ),
    );
  }
}

// 在嵌套导航器内部导航
Navigator.of(context).pushNamed('nested/details');
```

### 底部导航栏与嵌套导航

```dart
class TabNavigationDemo extends StatefulWidget {
  @override
  _TabNavigationDemoState createState() => _TabNavigationDemoState();
}

class _TabNavigationDemoState extends State<TabNavigationDemo> {
  int _selectedIndex = 0;
  
  // 为每个标签页创建导航键
  final List<GlobalKey<NavigatorState>> _navigatorKeys = [
    GlobalKey<NavigatorState>(),
    GlobalKey<NavigatorState>(),
    GlobalKey<NavigatorState>(),
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Stack(
        children: [
          _buildOffstageNavigator(0),
          _buildOffstageNavigator(1),
          _buildOffstageNavigator(2),
        ],
      ),
      bottomNavigationBar: BottomNavigationBar(
        currentIndex: _selectedIndex,
        onTap: (index) {
          setState(() {
            _selectedIndex = index;
          });
        },
        items: [
          BottomNavigationBarItem(icon: Icon(Icons.home), label: '首页'),
          BottomNavigationBarItem(icon: Icon(Icons.search), label: '搜索'),
          BottomNavigationBarItem(icon: Icon(Icons.person), label: '我的'),
        ],
      ),
    );
  }
  
  Widget _buildOffstageNavigator(int index) {
    return Offstage(
      offstage: _selectedIndex != index,
      child: Navigator(
        key: _navigatorKeys[index],
        onGenerateRoute: (settings) {
          return MaterialPageRoute(
            builder: (context) {
              switch (index) {
                case 0:
                  return HomePage();
                case 1:
                  return SearchPage();
                case 2:
                  return ProfilePage();
                default:
                  return HomePage();
              }
            },
          );
        },
      ),
    );
  }
}
```

## 高级路由管理库

虽然Flutter内置了导航功能，但对于复杂应用，使用专门的路由管理库可以简化开发过程。

### GoRouter

GoRouter是一个强大的路由库，支持声明式路由、深度链接和路由参数。

安装：

```yaml
dependencies:
  go_router: ^12.0.0
```

基本用法：

```dart
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

// 配置路由
final GoRouter _router = GoRouter(
  routes: [
    GoRoute(
      path: '/',
      builder: (context, state) => HomePage(),
      routes: [
        GoRoute(
          path: 'details/:id',
          builder: (context, state) {
            final id = state.pathParameters['id'];
            return DetailsPage(id: id!);
          },
        ),
        GoRoute(
          path: 'settings',
          builder: (context, state) => SettingsPage(),
        ),
      ],
    ),
  ],
  errorBuilder: (context, state) => NotFoundPage(),
);

// 在应用中使用
MaterialApp.router(
  routerConfig: _router,
  title: 'GoRouter示例',
);

// 导航操作
context.go('/');
context.go('/details/123');
context.go('/settings');

// 带查询参数
context.go('/details/123?color=red&size=large');

// 读取查询参数
final color = state.uri.queryParameters['color'];
```

### GetX导航

GetX提供了简单易用的导航API：

```dart
// 安装GetX
dependencies:
  get: ^4.6.5

// 使用GetX导航
import 'package:get/get.dart';

// 初始化
void main() {
  runApp(
    GetMaterialApp(
      initialRoute: '/',
      getPages: [
        GetPage(name: '/', page: () => HomePage()),
        GetPage(name: '/details/:id', page: () => DetailsPage()),
        GetPage(
          name: '/settings',
          page: () => SettingsPage(),
          transition: Transition.rightToLeft,
        ),
      ],
    ),
  );
}

// 导航操作
Get.toNamed('/details/123');
Get.back();
Get.offNamed('/login'); // 替换当前页面
Get.offAllNamed('/home'); // 清除所有页面并导航

// 传递参数
Get.toNamed(
  '/details/123',
  arguments: {'title': '产品详情', 'color': 'red'},
);

// 获取参数
// 1. 动态路径参数
final id = Get.parameters['id'];

// 2. 传递的参数
final title = Get.arguments['title'];
```

### AutoRoute

AutoRoute是一个使用代码生成的路由解决方案，减少样板代码：

```yaml
dependencies:
  auto_route: ^7.8.0

dev_dependencies:
  auto_route_generator: ^7.3.1
  build_runner: ^2.4.6
```

定义路由配置：

```dart
// app_router.dart
import 'package:auto_route/auto_route.dart';

import 'pages/home_page.dart';
import 'pages/details_page.dart';
import 'pages/settings_page.dart';

part 'app_router.gr.dart';

@AutoRouterConfig()
class AppRouter extends _$AppRouter {
  @override
  List<AutoRoute> get routes => [
    AutoRoute(page: HomeRoute.page, initial: true),
    AutoRoute(page: DetailsRoute.page),
    AutoRoute(page: SettingsRoute.page),
  ];
}
```

页面注解：

```dart
import 'package:auto_route/auto_route.dart';

@RoutePage()
class HomePage extends StatelessWidget {
  // ...
}

@RoutePage()
class DetailsPage extends StatelessWidget {
  final String id;
  
  const DetailsPage({@PathParam('id') required this.id});
  
  // ...
}
```

生成路由代码：

```bash
flutter pub run build_runner build
```

使用生成的路由：

```dart
void main() {
  final appRouter = AppRouter();
  runApp(
    MaterialApp.router(
      routerConfig: appRouter.config(),
    ),
  );
}

// 导航
context.router.push(DetailsRoute(id: '123'));
context.router.pushNamed('/details/123');
context.router.pop();
```

## 深度链接与Web URL策略

### 设置深度链接

在Android和iOS平台上配置深度链接，使应用可以响应特定URL：

Android (AndroidManifest.xml)：

```xml
<intent-filter>
  <action android:name="android.intent.action.VIEW" />
  <category android:name="android.intent.category.DEFAULT" />
  <category android:name="android.intent.category.BROWSABLE" />
  <!-- 使用自定义URL方案 -->
  <data android:scheme="myapp" android:host="open" />
  <!-- 使用HTTP/HTTPS URLs -->
  <data android:scheme="https" android:host="example.com" />
</intent-filter>
```

iOS (Info.plist)：

```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleTypeRole</key>
    <string>Editor</string>
    <key>CFBundleURLName</key>
    <string>com.example.myapp</string>
    <key>CFBundleURLSchemes</key>
    <array>
      <string>myapp</string>
    </array>
  </dict>
</array>
```

### 处理深度链接

使用uni_links包处理深度链接：

```yaml
dependencies:
  uni_links: ^0.5.1
```

监听深度链接：

```dart
import 'dart:async';
import 'package:uni_links/uni_links.dart';

// 初始化和处理首次启动URI
Future<void> initUniLinks() async {
  // 处理首次启动
  try {
    final initialLink = await getInitialLink();
    if (initialLink != null) {
      _handleLink(initialLink);
    }
  } catch (e) {
    // 处理异常
  }
  
  // 监听后续的链接
  linkSubscription = linkStream.listen((String? link) {
    if (link != null) {
      _handleLink(link);
    }
  }, onError: (err) {
    // 处理异常
  });
}

void _handleLink(String link) {
  // 例如: myapp://open/product/123
  Uri uri = Uri.parse(link);
  
  if (uri.host == 'open') {
    final pathSegments = uri.pathSegments;
    
    if (pathSegments.length >= 2 && pathSegments[0] == 'product') {
      final productId = pathSegments[1];
      // 导航到产品页面
      navigatorKey.currentState!.pushNamed('/product/$productId');
    }
  }
}
```

### Web URL策略

为Flutter Web应用设置URL策略：

```dart
import 'package:flutter_web_plugins/flutter_web_plugins.dart';

void main() {
  // 配置URL策略（哈希或路径）
  setUrlStrategy(PathUrlStrategy());
  // 或使用哈希策略
  // setUrlStrategy(const HashUrlStrategy());
  
  runApp(MyApp());
}
```

## 路由过渡中的数据持久性

在路由过渡过程中，Flutter会重建Widget树，可能导致状态丢失。以下是一些保持状态的方法：

### 1. 使用Provider

```dart
void main() {
  runApp(
    MultiProvider(
      providers: [
        ChangeNotifierProvider(create: (_) => CartModel()),
      ],
      child: MyApp(),
    ),
  );
}

// 在任何页面中访问
final cart = context.watch<CartModel>();
```

### 2. 使用InheritedWidget

```dart
class MyAppState extends InheritedWidget {
  final AppData data;
  
  const MyAppState({
    Key? key,
    required this.data,
    required Widget child,
  }) : super(key: key, child: child);
  
  static MyAppState of(BuildContext context) {
    return context.dependOnInheritedWidgetOfExactType<MyAppState>()!;
  }
  
  @override
  bool updateShouldNotify(MyAppState oldWidget) => data != oldWidget.data;
}
```

### 3. 使用全局状态管理解决方案

参考[状态管理](state-management.md)文档。

## 测试路由和导航

### 单元测试

测试导航逻辑：

```dart
void main() {
  testWidgets('测试导航按钮点击后页面跳转', (WidgetTester tester) async {
    // 创建并显示包含导航按钮的应用
    await tester.pumpWidget(
      MaterialApp(
        routes: {
          '/': (context) => HomePage(),
          '/details': (context) => DetailsPage(),
        },
      ),
    );
    
    // 查找并点击导航按钮
    await tester.tap(find.byKey(Key('navigate_to_details')));
    await tester.pumpAndSettle(); // 等待动画完成
    
    // 验证是否已导航到目标页面
    expect(find.text('详情页面'), findsOneWidget);
  });
}
```

### 集成测试

```dart
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  
  testWidgets('测试完整导航流程', (WidgetTester tester) async {
    app.main();
    await tester.pumpAndSettle();
    
    // 测试登录流程
    await tester.enterText(find.byKey(Key('username')), 'user');
    await tester.enterText(find.byKey(Key('password')), 'pass');
    await tester.tap(find.byKey(Key('login_button')));
    await tester.pumpAndSettle();
    
    // 验证是否导航到了首页
    expect(find.text('首页'), findsOneWidget);
    
    // 测试其他导航流程...
  });
}
```

## 最佳实践

### 路由组织

1. **集中管理路由**：
   - 将所有路由定义集中在一个地方
   - 使用常量而非硬编码字符串

```dart
// routes.dart
class Routes {
  static const String home = '/';
  static const String details = '/details';
  static const String settings = '/settings';
  
  static Map<String, WidgetBuilder> getRoutes() {
    return {
      home: (context) => HomePage(),
      details: (context) => DetailsPage(),
      settings: (context) => SettingsPage(),
    };
  }
}

// 使用
MaterialApp(
  routes: Routes.getRoutes(),
  initialRoute: Routes.home,
);
```

2. **路由分层**：
   - 为应用的不同部分创建独立的导航器
   - 使用嵌套导航器处理复杂的流程

### 性能考虑

1. **懒加载页面**：
   - 使用FutureBuilder或延迟加载来减少启动时间

```dart
FutureBuilder<Widget>(
  future: Future.delayed(
    Duration(milliseconds: 200),
    () => HeavyWidget(),
  ),
  builder: (context, snapshot) {
    if (snapshot.hasData) {
      return snapshot.data!;
    }
    return LoadingIndicator();
  },
);
```

2. **保持页面状态**：
   - 使用`AutomaticKeepAliveClientMixin`保留页面状态

```dart
class MyStatefulPage extends StatefulWidget {
  @override
  _MyStatefulPageState createState() => _MyStatefulPageState();
}

class _MyStatefulPageState extends State<MyStatefulPage>
    with AutomaticKeepAliveClientMixin {
  @override
  bool get wantKeepAlive => true;
  
  @override
  Widget build(BuildContext context) {
    super.build(context); // 必须调用
    return Scaffold(/* ... */);
  }
}
```

### 用户体验

1. **过渡动画**：
   - 使用平滑的过渡动画提高用户体验
   - 根据操作类型选择合适的动画（推入、弹出、替换）

2. **错误处理**：
   - 提供清晰的错误页面而非崩溃
   - 实现404页面处理不存在的路由

3. **后退按钮处理**：
   - 合理处理Android的物理后退按钮
   - 使用`WillPopScope`拦截后退操作

```dart
WillPopScope(
  onWillPop: () async {
    // 处理后退逻辑
    final shouldPop = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text('确认退出?'),
        content: Text('是否要退出应用?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text('取消'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text('确认'),
          ),
        ],
      ),
    );
    return shouldPop ?? false;
  },
  child: Scaffold(/* ... */),
);
```

## 常见问题与解决方案

### 1. 如何在没有BuildContext的情况下导航？

使用全局NavigatorKey：

```dart
final GlobalKey<NavigatorState> navigatorKey = GlobalKey<NavigatorState>();

void main() {
  runApp(
    MaterialApp(
      navigatorKey: navigatorKey,
      // ...
    ),
  );
}

// 在任何地方导航
void navigateFromAnywhere() {
  navigatorKey.currentState!.pushNamed('/details');
}
```

### 2. 如何在重定向之前检查身份验证状态？

使用onGenerateRoute结合身份验证检查：

```dart
MaterialApp(
  onGenerateRoute: (settings) {
    // 检查是否需要身份验证的路由
    if (_requiresAuth(settings.name) && !_isAuthenticated()) {
      // 重定向到登录页面
      return MaterialPageRoute(
        builder: (context) => LoginPage(),
        settings: RouteSettings(name: '/login'),
      );
    }
    
    // 正常路由处理
    switch (settings.name) {
      case '/':
        return MaterialPageRoute(builder: (context) => HomePage());
      case '/profile':
        return MaterialPageRoute(builder: (context) => ProfilePage());
      // ...
    }
    
    return null;
  },
);

bool _requiresAuth(String? routeName) {
  // 需要身份验证的路由列表
  final authRoutes = ['/profile', '/settings', '/orders'];
  return routeName != null && authRoutes.contains(routeName);
}

bool _isAuthenticated() {
  // 检查用户是否已登录
  return AuthService.instance.isLoggedIn;
}
```

### 3. 如何确保页面只创建一次？

使用PageStorageKey保存页面状态：

```dart
ListView(
  children: [
    for (int i = 0; i < items.length; i++)
      ListTile(
        key: PageStorageKey('item_$i'),
        title: Text(items[i]),
      ),
  ],
);
```

## 总结

Flutter提供了多种管理路由和导航的方法，从简单的`Navigator.push()`到复杂的嵌套导航器和第三方路由库。选择合适的导航方案取决于应用的复杂性和特定需求：

- **简单应用**：使用基本的Navigator API或命名路由
- **中等复杂度**：使用onGenerateRoute和命名路由的组合
- **复杂应用**：考虑使用第三方路由库如GoRouter或AutoRoute

良好的路由系统设计应考虑：
1. 代码组织和可维护性
2. 用户体验和过渡动画
3. 深度链接支持
4. 状态持久性
5. 测试和错误处理

## 下一步

- 了解[网络与数据获取](networking.md)
- 学习[表单与用户输入](forms-input.md)
- 探索[本地存储](local-storage.md)
