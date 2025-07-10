# 布局与UI设计

Flutter提供了丰富的布局组件和UI工具，使开发者能够创建美观、响应式的用户界面。本文档将介绍Flutter的布局系统、常用UI组件和设计原则。

## 布局基础

Flutter的布局模型基于Widget树，通过组合不同类型的布局Widget来构建复杂的界面。

### Flutter布局的工作原理

1. **约束传递**: 父Widget向子Widget传递约束(constraints)
2. **大小确定**: 子Widget根据这些约束确定自己的大小
3. **位置确定**: 父Widget决定子Widget的位置

布局过程是一个递归的过程，从Widget树的根部开始，向下传递约束，然后从叶节点开始，向上报告大小。

### 约束类型

Flutter中的约束由`BoxConstraints`类表示，包含四个重要的值：

- `minWidth`: 最小宽度
- `maxWidth`: 最大宽度
- `minHeight`: 最小高度
- `maxHeight`: 最大高度

不同的布局Widget会施加不同的约束：

```dart
// 紧约束 - 强制子Widget采用特定大小
Container(width: 100, height: 100, child: MyWidget())

// 松约束 - 允许子Widget在一定范围内决定自己的大小
Center(child: MyWidget())

// 无界约束 - 在某个维度上没有上限
ListView(children: [MyWidget()])
```

## 常用布局Widget

### 单子布局Widget

这些Widget只能有一个子Widget：

#### Container

最常用的布局Widget之一，可以添加内边距、外边距、边框、背景色等：

```dart
Container(
  margin: EdgeInsets.all(10.0),
  padding: EdgeInsets.symmetric(horizontal: 20.0, vertical: 15.0),
  decoration: BoxDecoration(
    color: Colors.white,
    borderRadius: BorderRadius.circular(8.0),
    boxShadow: [
      BoxShadow(
        color: Colors.black.withOpacity(0.1),
        blurRadius: 5.0,
        offset: Offset(0, 2),
      ),
    ],
  ),
  child: Text('Hello Flutter'),
)
```

#### Center

将子Widget居中显示：

```dart
Center(
  child: Text('居中文本'),
)
```

#### Padding

给子Widget添加内边距：

```dart
Padding(
  padding: EdgeInsets.all(16.0),
  child: Text('带内边距的文本'),
)
```

#### Align

按指定的对齐方式放置子Widget：

```dart
Align(
  alignment: Alignment.bottomRight,
  child: Text('右下角对齐的文本'),
)
```

#### SizedBox

指定固定尺寸的盒子，也可用来创建固定的间隔：

```dart
// 固定尺寸的Widget
SizedBox(
  width: 100.0,
  height: 50.0,
  child: ColoredBox(color: Colors.blue),
)

// 创建垂直间隔
SizedBox(height: 16.0)
```

#### AspectRatio

按指定的宽高比布局子Widget：

```dart
AspectRatio(
  aspectRatio: 16 / 9,
  child: Image.network('https://example.com/image.jpg'),
)
```

#### FractionallySizedBox

根据父Widget的百分比来确定子Widget的大小：

```dart
FractionallySizedBox(
  widthFactor: 0.8, // 占父Widget宽度的80%
  heightFactor: 0.5, // 占父Widget高度的50%
  child: Container(color: Colors.green),
)
```

### 多子布局Widget

这些Widget可以有多个子Widget：

#### Row

水平排列多个子Widget：

```dart
Row(
  mainAxisAlignment: MainAxisAlignment.spaceEvenly,
  crossAxisAlignment: CrossAxisAlignment.center,
  children: [
    Icon(Icons.star, size: 30),
    Text('评分'),
    Text('4.8'),
  ],
)
```

#### Column

垂直排列多个子Widget：

```dart
Column(
  mainAxisSize: MainAxisSize.min,
  mainAxisAlignment: MainAxisAlignment.start,
  crossAxisAlignment: CrossAxisAlignment.stretch,
  children: [
    Text('标题', style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
    SizedBox(height: 8),
    Text('副标题'),
    SizedBox(height: 16),
    Text('正文内容...'),
  ],
)
```

#### Stack

层叠布局多个子Widget：

```dart
Stack(
  alignment: Alignment.center,
  children: [
    Image.asset('background.jpg'),
    Positioned(
      bottom: 20,
      right: 20,
      child: Container(
        padding: EdgeInsets.all(8),
        color: Colors.black.withOpacity(0.7),
        child: Text(
          '照片说明',
          style: TextStyle(color: Colors.white),
        ),
      ),
    ),
  ],
)
```

#### Wrap

当内容超出一行或一列时自动换行：

```dart
Wrap(
  spacing: 8.0, // 水平间距
  runSpacing: 8.0, // 垂直间距
  children: [
    Chip(label: Text('Flutter')),
    Chip(label: Text('Dart')),
    Chip(label: Text('UI')),
    Chip(label: Text('Mobile')),
    Chip(label: Text('App')),
    Chip(label: Text('Development')),
  ],
)
```

#### GridView

网格布局：

```dart
GridView.builder(
  gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
    crossAxisCount: 3, // 每行3个
    crossAxisSpacing: 10.0, // 水平间距
    mainAxisSpacing: 10.0, // 垂直间距
  ),
  itemCount: 9,
  itemBuilder: (context, index) {
    return Container(
      color: Colors.blue[(index + 1) * 100],
      child: Center(
        child: Text('Item $index'),
      ),
    );
  },
)
```

### 滚动布局Widget

当内容超出屏幕范围时，需要使用滚动Widget：

#### ListView

列表布局，支持垂直和水平滚动：

```dart
// 基本用法
ListView(
  children: [
    ListTile(title: Text('Item 1')),
    ListTile(title: Text('Item 2')),
    ListTile(title: Text('Item 3')),
  ],
)

// 动态列表
ListView.builder(
  itemCount: 100,
  itemBuilder: (context, index) {
    return ListTile(
      title: Text('Item $index'),
    );
  },
)

// 分隔列表
ListView.separated(
  itemCount: 20,
  separatorBuilder: (context, index) => Divider(),
  itemBuilder: (context, index) {
    return ListTile(
      title: Text('Item $index'),
    );
  },
)
```

#### SingleChildScrollView

包含单个子Widget的滚动视图：

```dart
SingleChildScrollView(
  child: Column(
    children: List.generate(20, (index) {
      return Container(
        height: 100,
        color: index % 2 == 0 ? Colors.blue[50] : Colors.blue[100],
        child: Center(
          child: Text('Item $index'),
        ),
      );
    }),
  ),
)
```

#### PageView

全屏页面滚动：

```dart
PageView(
  children: [
    Container(color: Colors.red, child: Center(child: Text('Page 1'))),
    Container(color: Colors.green, child: Center(child: Text('Page 2'))),
    Container(color: Colors.blue, child: Center(child: Text('Page 3'))),
  ],
)
```

## 响应式布局

Flutter支持创建适应不同屏幕尺寸和方向的响应式布局。

### 使用MediaQuery获取屏幕信息

```dart
Widget build(BuildContext context) {
  final size = MediaQuery.of(context).size;
  final orientation = MediaQuery.of(context).orientation;
  
  return Column(
    children: [
      Text('屏幕宽度: ${size.width}'),
      Text('屏幕高度: ${size.height}'),
      Text('方向: ${orientation == Orientation.portrait ? "竖屏" : "横屏"}'),
    ],
  );
}
```

### 使用LayoutBuilder响应父Widget约束

```dart
LayoutBuilder(
  builder: (BuildContext context, BoxConstraints constraints) {
    if (constraints.maxWidth > 600) {
      // 宽屏布局
      return TwoColumnLayout();
    } else {
      // 窄屏布局
      return SingleColumnLayout();
    }
  },
)
```

### 自适应布局策略

1. **百分比布局**：使用`FractionallySizedBox`或计算比例
2. **断点适配**：根据不同屏幕宽度应用不同布局
3. **Flex布局**：使用`Expanded`和`Flexible`进行弹性分配

```dart
// Flex布局示例
Row(
  children: [
    // 占用固定宽度
    Container(width: 100, color: Colors.red),
    // 占用剩余空间的3/4
    Expanded(
      flex: 3,
      child: Container(color: Colors.green),
    ),
    // 占用剩余空间的1/4
    Expanded(
      flex: 1,
      child: Container(color: Colors.blue),
    ),
  ],
)
```

## 常见UI组件

### 文本组件

#### Text

显示文本内容：

```dart
Text(
  '这是一段文本',
  style: TextStyle(
    fontSize: 16.0,
    fontWeight: FontWeight.bold,
    color: Colors.blue,
    letterSpacing: 1.2,
    height: 1.5,
  ),
  textAlign: TextAlign.center,
  maxLines: 2,
  overflow: TextOverflow.ellipsis,
)
```

#### RichText与TextSpan

显示不同样式的文本：

```dart
RichText(
  text: TextSpan(
    style: TextStyle(color: Colors.black),
    children: [
      TextSpan(text: '欢迎来到 '),
      TextSpan(
        text: 'Flutter',
        style: TextStyle(
          color: Colors.blue,
          fontWeight: FontWeight.bold,
        ),
      ),
      TextSpan(text: ' 世界!'),
    ],
  ),
)
```

### 按钮组件

Flutter提供多种按钮组件：

```dart
// 材料设计按钮
ElevatedButton(
  onPressed: () {
    print('按钮被点击');
  },
  style: ElevatedButton.styleFrom(
    primary: Colors.blue,
    onPrimary: Colors.white,
    padding: EdgeInsets.symmetric(horizontal: 20, vertical: 12),
    shape: RoundedRectangleBorder(
      borderRadius: BorderRadius.circular(8),
    ),
  ),
  child: Text('确认'),
)

// 文本按钮
TextButton(
  onPressed: () {},
  child: Text('取消'),
)

// 轮廓按钮
OutlinedButton(
  onPressed: () {},
  child: Text('更多信息'),
)

// 图标按钮
IconButton(
  icon: Icon(Icons.favorite),
  color: Colors.red,
  onPressed: () {},
)
```

### 输入组件

#### TextField

文本输入框：

```dart
TextField(
  decoration: InputDecoration(
    labelText: '用户名',
    hintText: '请输入您的用户名',
    prefixIcon: Icon(Icons.person),
    border: OutlineInputBorder(
      borderRadius: BorderRadius.circular(10),
    ),
  ),
  onChanged: (value) {
    print('输入内容: $value');
  },
)
```

#### Form和TextFormField

表单输入与验证：

```dart
final _formKey = GlobalKey<FormState>();

Form(
  key: _formKey,
  child: Column(
    children: [
      TextFormField(
        decoration: InputDecoration(labelText: '邮箱'),
        validator: (value) {
          if (value == null || value.isEmpty) {
            return '请输入邮箱';
          }
          if (!value.contains('@')) {
            return '请输入有效的邮箱地址';
          }
          return null;
        },
      ),
      TextFormField(
        decoration: InputDecoration(labelText: '密码'),
        obscureText: true,
        validator: (value) {
          if (value == null || value.isEmpty) {
            return '请输入密码';
          }
          if (value.length < 6) {
            return '密码至少6个字符';
          }
          return null;
        },
      ),
      ElevatedButton(
        onPressed: () {
          if (_formKey.currentState!.validate()) {
            // 表单验证通过，提交数据
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(content: Text('处理数据中...')),
            );
          }
        },
        child: Text('提交'),
      ),
    ],
  ),
)
```

### 图片组件

```dart
// 从资源加载图片
Image.asset(
  'assets/images/logo.png',
  width: 200,
  height: 100,
  fit: BoxFit.cover,
)

// 从网络加载图片
Image.network(
  'https://flutter.dev/images/flutter-logo-sharing.png',
  loadingBuilder: (context, child, loadingProgress) {
    if (loadingBuilder == null) return child;
    return Center(
      child: CircularProgressIndicator(
        value: loadingProgress.expectedTotalBytes != null
            ? loadingProgress.cumulativeBytesLoaded /
                loadingProgress.expectedTotalBytes!
            : null,
      ),
    );
  },
)
```

### 卡片和列表组件

```dart
// 卡片
Card(
  elevation: 4.0,
  shape: RoundedRectangleBorder(
    borderRadius: BorderRadius.circular(10.0),
  ),
  child: Padding(
    padding: EdgeInsets.all(16.0),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          '标题',
          style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
        ),
        SizedBox(height: 8),
        Text('这是卡片的内容，可以包含多种组件和信息。'),
      ],
    ),
  ),
)

// 列表项
ListTile(
  leading: CircleAvatar(child: Icon(Icons.person)),
  title: Text('用户名'),
  subtitle: Text('用户简介'),
  trailing: Icon(Icons.arrow_forward_ios, size: 16),
  onTap: () {
    print('列表项被点击');
  },
)
```

## UI设计原则

### Material Design

Flutter原生支持Material Design，提供了丰富的Material组件：

```dart
MaterialApp(
  theme: ThemeData(
    primarySwatch: Colors.blue,
    brightness: Brightness.light,
    visualDensity: VisualDensity.adaptivePlatformDensity,
    appBarTheme: AppBarTheme(
      backgroundColor: Colors.white,
      foregroundColor: Colors.black,
      elevation: 1,
    ),
    // 更多主题设置...
  ),
  home: MyHomePage(),
)
```

### Cupertino (iOS风格)

Flutter也支持iOS风格的Cupertino组件：

```dart
CupertinoApp(
  theme: CupertinoThemeData(
    primaryColor: CupertinoColors.systemBlue,
    brightness: Brightness.light,
  ),
  home: CupertinoPageScaffold(
    navigationBar: CupertinoNavigationBar(
      middle: Text('Cupertino App'),
    ),
    child: Center(
      child: Text('Hello, Cupertino!'),
    ),
  ),
)
```

### 自适应设计

根据平台自动选择不同风格的组件：

```dart
Widget build(BuildContext context) {
  final platform = Theme.of(context).platform;
  
  if (platform == TargetPlatform.iOS) {
    return CupertinoButton(
      child: Text('点击我'),
      onPressed: () {},
    );
  } else {
    return ElevatedButton(
      child: Text('点击我'),
      onPressed: () {},
    );
  }
}
```

## 主题定制

Flutter的主题系统允许您统一管理应用的视觉样式：

```dart
// 应用全局主题
MaterialApp(
  theme: ThemeData(
    // 颜色
    primarySwatch: Colors.purple,
    accentColor: Colors.orangeAccent,
    
    // 文本样式
    textTheme: TextTheme(
      headline1: TextStyle(fontSize: 24.0, fontWeight: FontWeight.bold),
      bodyText1: TextStyle(fontSize: 16.0, color: Colors.grey[800]),
    ),
    
    // 按钮样式
    elevatedButtonTheme: ElevatedButtonThemeData(
      style: ElevatedButton.styleFrom(
        primary: Colors.purple,
        padding: EdgeInsets.symmetric(horizontal: 20, vertical: 12),
      ),
    ),
    
    // 输入框样式
    inputDecorationTheme: InputDecorationTheme(
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(8),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(8),
        borderSide: BorderSide(color: Colors.purple, width: 2),
      ),
    ),
  ),
  // ...
)
```

### 暗黑模式支持

```dart
MaterialApp(
  themeMode: ThemeMode.system, // 跟随系统
  theme: ThemeData.light(), // 亮色主题
  darkTheme: ThemeData.dark(), // 暗色主题
  // ...
)
```

## 常见布局模式

### 卡片列表

```dart
ListView.builder(
  padding: EdgeInsets.all(16),
  itemCount: 10,
  itemBuilder: (context, index) {
    return Card(
      margin: EdgeInsets.only(bottom: 16),
      child: Padding(
        padding: EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              '标题 $index',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
            ),
            SizedBox(height: 8),
            Text('这是卡片 $index 的详细内容描述。'),
          ],
        ),
      ),
    );
  },
)
```

### 网格布局

```dart
GridView.count(
  crossAxisCount: 2, // 每行2个
  padding: EdgeInsets.all(16),
  mainAxisSpacing: 16,
  crossAxisSpacing: 16,
  children: List.generate(8, (index) {
    return Container(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(8),
        color: Colors.primaries[index % Colors.primaries.length],
      ),
      child: Center(
        child: Text(
          'Item $index',
          style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
        ),
      ),
    );
  }),
)
```

### 底部导航栏布局

```dart
class MyHomePage extends StatefulWidget {
  @override
  _MyHomePageState createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  int _selectedIndex = 0;
  
  static List<Widget> _pages = <Widget>[
    Center(child: Text('首页')),
    Center(child: Text('搜索')),
    Center(child: Text('通知')),
    Center(child: Text('设置')),
  ];
  
  void _onItemTapped(int index) {
    setState(() {
      _selectedIndex = index;
    });
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('底部导航栏示例')),
      body: _pages[_selectedIndex],
      bottomNavigationBar: BottomNavigationBar(
        items: const <BottomNavigationBarItem>[
          BottomNavigationBarItem(
            icon: Icon(Icons.home),
            label: '首页',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.search),
            label: '搜索',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.notifications),
            label: '通知',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.settings),
            label: '设置',
          ),
        ],
        currentIndex: _selectedIndex,
        selectedItemColor: Colors.amber[800],
        unselectedItemColor: Colors.grey,
        showUnselectedLabels: true,
        onTap: _onItemTapped,
      ),
    );
  }
}
```

### 抽屉菜单布局

```dart
Scaffold(
  appBar: AppBar(title: Text('抽屉菜单示例')),
  drawer: Drawer(
    child: ListView(
      padding: EdgeInsets.zero,
      children: [
        DrawerHeader(
          decoration: BoxDecoration(
            color: Colors.blue,
          ),
          child: Text(
            '应用菜单',
            style: TextStyle(
              color: Colors.white,
              fontSize: 24,
            ),
          ),
        ),
        ListTile(
          leading: Icon(Icons.home),
          title: Text('首页'),
          onTap: () {
            // 更新UI并关闭抽屉
            Navigator.pop(context);
          },
        ),
        ListTile(
          leading: Icon(Icons.person),
          title: Text('个人资料'),
          onTap: () {
            Navigator.pop(context);
          },
        ),
        ListTile(
          leading: Icon(Icons.settings),
          title: Text('设置'),
          onTap: () {
            Navigator.pop(context);
          },
        ),
      ],
    ),
  ),
  body: Center(
    child: Text('主内容区域'),
  ),
)
```

## UI优化技巧

### 视觉一致性

- 使用一致的颜色方案
- 统一字体和文本样式
- 保持组件间距的一致性
- 设置统一的圆角半径

```dart
// 定义常量
class AppStyles {
  static const double spacing = 16.0;
  static const double borderRadius = 8.0;
  static const Color primaryColor = Colors.blue;
  static const Color accentColor = Colors.orange;
  
  static const TextStyle headingStyle = TextStyle(
    fontSize: 20,
    fontWeight: FontWeight.bold,
  );
  
  static const TextStyle bodyStyle = TextStyle(
    fontSize: 16,
    height: 1.5,
  );
}

// 使用常量
Container(
  padding: EdgeInsets.all(AppStyles.spacing),
  decoration: BoxDecoration(
    color: Colors.white,
    borderRadius: BorderRadius.circular(AppStyles.borderRadius),
  ),
  child: Text(
    '标题文本',
    style: AppStyles.headingStyle,
  ),
)
```

### 视觉反馈

- 为交互元素添加状态变化
- 使用动画提示状态变更
- 提供加载指示器

```dart
// 交互状态变化示例
InkWell(
  onTap: () {},
  splashColor: Colors.blue.withOpacity(0.3),
  highlightColor: Colors.blue.withOpacity(0.1),
  child: Padding(
    padding: EdgeInsets.all(12.0),
    child: Text('点击我'),
  ),
)

// 加载指示器示例
FutureBuilder<String>(
  future: fetchData(),
  builder: (context, snapshot) {
    if (snapshot.connectionState == ConnectionState.waiting) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            CircularProgressIndicator(),
            SizedBox(height: 16),
            Text('数据加载中...'),
          ],
        ),
      );
    } else if (snapshot.hasError) {
      return Center(child: Text('加载失败: ${snapshot.error}'));
    } else {
      return Center(child: Text('数据: ${snapshot.data}'));
    }
  },
)
```

### 可访问性

- 提供足够的对比度
- 使用语义标签
- 确保合适的点击区域大小

```dart
// 语义标签示例
Semantics(
  label: '关闭对话框',
  child: IconButton(
    icon: Icon(Icons.close),
    onPressed: () {
      Navigator.pop(context);
    },
  ),
)

// 增大点击区域
GestureDetector(
  behavior: HitTestBehavior.opaque, // 使整个区域可点击
  onTap: () {},
  child: Padding(
    padding: EdgeInsets.all(12.0), // 增加内边距
    child: Icon(Icons.star, size: 24),
  ),
)
```

## 实用UI示例

### 登录表单

```dart
class LoginScreen extends StatelessWidget {
  final _formKey = GlobalKey<FormState>();
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('登录')),
      body: Padding(
        padding: const EdgeInsets.all(24.0),
        child: Form(
          key: _formKey,
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // 标志
              Center(
                child: FlutterLogo(size: 80),
              ),
              SizedBox(height: 48),
              
              // 邮箱输入框
              TextFormField(
                controller: _emailController,
                decoration: InputDecoration(
                  labelText: '邮箱',
                  prefixIcon: Icon(Icons.email),
                  border: OutlineInputBorder(),
                ),
                keyboardType: TextInputType.emailAddress,
                validator: (value) {
                  if (value == null || value.isEmpty) {
                    return '请输入邮箱';
                  }
                  if (!value.contains('@')) {
                    return '请输入有效的邮箱地址';
                  }
                  return null;
                },
              ),
              SizedBox(height: 16),
              
              // 密码输入框
              TextFormField(
                controller: _passwordController,
                decoration: InputDecoration(
                  labelText: '密码',
                  prefixIcon: Icon(Icons.lock),
                  border: OutlineInputBorder(),
                ),
                obscureText: true,
                validator: (value) {
                  if (value == null || value.isEmpty) {
                    return '请输入密码';
                  }
                  if (value.length < 6) {
                    return '密码至少6个字符';
                  }
                  return null;
                },
              ),
              SizedBox(height: 24),
              
              // 登录按钮
              ElevatedButton(
                onPressed: () {
                  if (_formKey.currentState!.validate()) {
                    // 执行登录逻辑
                  }
                },
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Text('登录'),
                ),
              ),
              SizedBox(height: 16),
              
              // 忘记密码链接
              Center(
                child: TextButton(
                  onPressed: () {},
                  child: Text('忘记密码?'),
                ),
              ),
              SizedBox(height: 24),
              
              // 注册提示
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Text('还没有账号?'),
                  TextButton(
                    onPressed: () {},
                    child: Text('注册'),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}
```

### 产品卡片

```dart
Card(
  elevation: 4.0,
  shape: RoundedRectangleBorder(
    borderRadius: BorderRadius.circular(12.0),
  ),
  child: Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      // 产品图片
      ClipRRect(
        borderRadius: BorderRadius.vertical(top: Radius.circular(12.0)),
        child: Image.network(
          'https://example.com/product.jpg',
          height: 180,
          width: double.infinity,
          fit: BoxFit.cover,
        ),
      ),
      
      // 产品信息
      Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // 产品名称
            Text(
              '高品质无线耳机',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
              ),
            ),
            SizedBox(height: 8),
            
            // 产品描述
            Text(
              '具有主动降噪功能的高品质无线蓝牙耳机，续航时间长达24小时。',
              style: TextStyle(
                fontSize: 14,
                color: Colors.grey[600],
              ),
            ),
            SizedBox(height: 16),
            
            // 价格和评分
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  '¥ 899.00',
                  style: TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.bold,
                    color: Colors.red[700],
                  ),
                ),
                Row(
                  children: [
                    Icon(Icons.star, size: 18, color: Colors.amber),
                    Text(
                      ' 4.8 (239)',
                      style: TextStyle(fontSize: 14),
                    ),
                  ],
                ),
              ],
            ),
            SizedBox(height: 16),
            
            // 操作按钮
            Row(
              children: [
                Expanded(
                  child: OutlinedButton.icon(
                    icon: Icon(Icons.favorite_border),
                    label: Text('收藏'),
                    onPressed: () {},
                  ),
                ),
                SizedBox(width: 16),
                Expanded(
                  child: ElevatedButton.icon(
                    icon: Icon(Icons.shopping_cart),
                    label: Text('加入购物车'),
                    onPressed: () {},
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    ],
  ),
)
```

## 总结

Flutter的布局系统提供了灵活且强大的工具来创建各种UI布局。关键点包括：

1. **理解约束传递**：Flutter布局过程中，父Widget向子Widget传递约束，子Widget确定大小，父Widget确定位置
2. **选择合适的布局Widget**：根据需求选择适当的布局Widget，如Row、Column、Stack等
3. **掌握响应式布局技巧**：使用MediaQuery、LayoutBuilder等工具创建适配不同屏幕的布局
4. **设计视觉一致的UI**：使用主题系统保证应用风格的一致性
5. **优化用户体验**：提供视觉反馈、合适的间距和清晰的层次结构

通过结合这些基本原则和组件，您可以在Flutter中创建美观、响应式且用户友好的界面。

## 下一步

- 学习[状态管理](state-management.md)
- 了解[路由与导航](navigation-routing.md)
- 探索[表单与用户输入](forms-input.md)
