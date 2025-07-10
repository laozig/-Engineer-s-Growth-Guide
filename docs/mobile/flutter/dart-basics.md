# Dart语言基础

Dart是Flutter框架的基础编程语言，由Google开发。它是一种强类型、面向对象的语言，专为构建web、移动和桌面应用程序而设计。本文档将介绍Dart的核心概念和语法，帮助您开始Flutter开发。

## 语言特点

- **类型安全** - 支持静态类型检查，但也有类型推断
- **面向对象** - 一切皆对象，所有对象都是类的实例
- **空安全** - 从Dart 2.12开始支持空安全(null safety)
- **异步支持** - 原生支持异步编程(Future, Stream, async/await)
- **JIT与AOT编译** - 开发时使用即时编译(JIT)，生产环境使用提前编译(AOT)

## 基础语法

### 变量声明

Dart提供多种声明变量的方式：

```dart
// 使用var让Dart自动推断类型
var name = 'Bob';

// 显式声明类型
String username = 'Alice';
int age = 30;
double height = 1.75;
bool isActive = true;

// 使用final声明不可变变量
final String country = 'China';

// 使用const声明编译时常量
const pi = 3.14159;

// 支持空安全的可空类型
String? nullableName; // 可以为null
String nonNullableName = 'Must have a value'; // 不能为null
```

### 基本数据类型

Dart有几种内置的数据类型：

```dart
// 数值类型
int integer = 42;
double decimal = 3.14;
num dynamic = 10; // 可以是int或double

// 字符串
String greeting = 'Hello';
String interpolation = 'Hello, $name'; // 字符串插值
String multiline = '''
  This is a
  multi-line string.
''';

// 布尔值
bool isDartFun = true;
bool result = 5 > 3;

// 列表(数组)
List<String> fruits = ['apple', 'banana', 'orange'];
var numbers = <int>[1, 2, 3, 4, 5];
var emptyList = [];

// 集合
Set<String> uniqueFruits = {'apple', 'banana', 'orange'};
var uniqueNumbers = <int>{1, 2, 3, 4, 5};

// 映射(字典)
Map<String, int> ages = {
  'Alice': 30,
  'Bob': 25,
  'Charlie': 35,
};
var scores = {
  'Math': 95,
  'Science': 88,
  'History': 92,
};
```

### 控制流

Dart支持常见的控制流语句：

```dart
// If语句
if (age >= 18) {
  print('Adult');
} else if (age >= 13) {
  print('Teenager');
} else {
  print('Child');
}

// Switch语句
switch (fruit) {
  case 'apple':
    print('Red fruit');
    break;
  case 'banana':
    print('Yellow fruit');
    break;
  default:
    print('Unknown fruit');
}

// For循环
for (int i = 0; i < 5; i++) {
  print(i);
}

// For-in循环
for (var fruit in fruits) {
  print(fruit);
}

// While循环
int count = 0;
while (count < 5) {
  print(count);
  count++;
}

// Do-while循环
do {
  print(count);
  count--;
} while (count > 0);
```

### 函数

Dart中的函数定义与使用：

```dart
// 基本函数
int add(int a, int b) {
  return a + b;
}

// 箭头函数(单行函数)
int multiply(int a, int b) => a * b;

// 可选位置参数
String greet(String name, [String? greeting]) {
  greeting ??= 'Hello'; // 空值合并运算符
  return '$greeting, $name!';
}

// 命名参数
void introduce({required String name, int? age, String? occupation}) {
  print('Name: $name');
  if (age != null) print('Age: $age');
  if (occupation != null) print('Occupation: $occupation');
}

// 函数作为参数
void processNumbers(List<int> numbers, int Function(int) processor) {
  for (var number in numbers) {
    print(processor(number));
  }
}

// 匿名函数
var double = (int x) => x * 2;
```

### 类和对象

Dart是一种面向对象的语言，支持类和对象：

```dart
// 基本类定义
class Person {
  // 属性
  String name;
  int age;
  
  // 构造函数
  Person(this.name, this.age);
  
  // 命名构造函数
  Person.guest() {
    name = 'Guest';
    age = 0;
  }
  
  // 方法
  void introduce() {
    print('My name is $name and I am $age years old.');
  }
}

// 使用类
var person = Person('Alice', 30);
person.introduce();

var guest = Person.guest();
guest.introduce();
```

### 继承

Dart支持单继承：

```dart
// 父类
class Animal {
  String name;
  
  Animal(this.name);
  
  void makeSound() {
    print('Some generic sound');
  }
}

// 子类
class Dog extends Animal {
  Dog(String name) : super(name);
  
  @override
  void makeSound() {
    print('Woof!');
  }
}

// 使用继承
var dog = Dog('Rex');
dog.makeSound(); // 输出: Woof!
```

### 接口和抽象类

Dart没有专门的接口语法，任何类都可以作为接口被实现：

```dart
// 抽象类
abstract class Shape {
  double get area; // 抽象方法
  
  void printInfo() {
    print('This shape has area: ${area}');
  }
}

// 实现抽象类
class Circle extends Shape {
  double radius;
  
  Circle(this.radius);
  
  @override
  double get area => 3.14 * radius * radius;
}

// 隐式接口
class Logger {
  void log(String message) {
    print('LOG: $message');
  }
}

// 使用implements关键字实现接口
class ConsoleLogger implements Logger {
  @override
  void log(String message) {
    print('CONSOLE: $message');
  }
}
```

### Mixin

Dart支持通过mixin重用类的代码：

```dart
// 定义mixin
mixin Musical {
  bool canPlayMusic = true;
  
  void playMusic() {
    print('Playing music');
  }
}

mixin Danceable {
  bool canDance = true;
  
  void dance() {
    print('Dancing');
  }
}

// 使用mixin
class Performer with Musical, Danceable {
  String name;
  
  Performer(this.name);
  
  void perform() {
    print('$name is performing:');
    playMusic();
    dance();
  }
}
```

## 异步编程

Dart提供了强大的异步支持：

### Future

Future表示一个异步操作的最终完成或失败，类似于JavaScript中的Promise：

```dart
// 创建Future
Future<String> fetchData() {
  return Future.delayed(Duration(seconds: 2), () {
    return 'Data fetched successfully';
  });
}

// 使用Future
fetchData().then((data) {
  print(data);
}).catchError((error) {
  print('Error: $error');
});

// 使用async/await
Future<void> loadData() async {
  try {
    String data = await fetchData();
    print(data);
  } catch (error) {
    print('Error: $error');
  }
}
```

### Stream

Stream表示一系列异步事件：

```dart
// 创建Stream
Stream<int> countStream(int max) async* {
  for (int i = 1; i <= max; i++) {
    await Future.delayed(Duration(seconds: 1));
    yield i;
  }
}

// 使用Stream.listen()
void listenToStream() {
  final stream = countStream(5);
  stream.listen(
    (data) => print('Data: $data'),
    onError: (error) => print('Error: $error'),
    onDone: () => print('Stream completed'),
  );
}

// 使用async/await处理Stream
Future<void> processStream() async {
  try {
    await for (final value in countStream(3)) {
      print('Processed: $value');
    }
  } catch (error) {
    print('Error: $error');
  }
}
```

## 空安全

Dart 2.12引入了健全的空安全系统：

```dart
// 可空类型
String? nullableName;
int? age;

// 非空断言运算符
void printName(String? name) {
  print(name!.toUpperCase()); // 如果name为null，抛出异常
}

// 空值感知运算符
void greet(String? name) {
  print('Hello, ${name?.toUpperCase()}'); // 如果name为null，表达式返回null
}

// 空值合并运算符
String displayName(String? name) {
  return name ?? 'Unknown'; // 如果name为null，返回'Unknown'
}

// 条件属性访问
int? stringLength(String? str) {
  return str?.length; // 如果str为null，返回null
}

// late关键字(延迟初始化)
class User {
  late String email; // 会在构造后但在使用前初始化
  
  void loadEmail() {
    email = 'user@example.com';
  }
}
```

## 集合操作

Dart提供了丰富的集合操作API：

```dart
// List操作
final numbers = [1, 2, 3, 4, 5];

// 映射
final doubled = numbers.map((n) => n * 2).toList();  // [2, 4, 6, 8, 10]

// 过滤
final evens = numbers.where((n) => n % 2 == 0).toList();  // [2, 4]

// 归约
final sum = numbers.reduce((value, element) => value + element);  // 15

// 折叠
final sumWithInitial = numbers.fold(10, (sum, n) => sum + n);  // 25

// 排序
final fruits = ['banana', 'apple', 'orange'];
fruits.sort(); // ['apple', 'banana', 'orange']

// 查找
final hasThree = numbers.contains(3);  // true
final firstEven = numbers.firstWhere((n) => n % 2 == 0);  // 2
```

## 错误处理

Dart使用异常进行错误处理：

```dart
// 异常捕获
try {
  int result = 10 ~/ 0; // 抛出IntegerDivisionByZeroException
  print(result);
} on IntegerDivisionByZeroException {
  print('Cannot divide by zero');
} catch (e) {
  print('Unknown error: $e');
} finally {
  print('This always executes');
}

// 抛出异常
void checkAge(int age) {
  if (age < 0) {
    throw ArgumentError('Age cannot be negative');
  }
  if (age > 120) {
    throw RangeError('Age is invalid');
  }
}

// 自定义异常
class CustomException implements Exception {
  final String message;
  
  CustomException(this.message);
  
  @override
  String toString() => 'CustomException: $message';
}
```

## 库与依赖

Dart使用库系统进行代码组织：

```dart
// 导入核心库
import 'dart:math';
import 'dart:convert';

// 导入外部库
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

// 导入项目内的库
import 'package:my_app/models/user.dart';

// 部分导入
import 'package:my_library/utilities.dart' show Function1, Function2;
import 'package:other_library/tools.dart' hide DeprecatedFunction;

// 延迟加载(懒加载)库
import 'package:large_library/main.dart' deferred as large;

Future<void> loadLibrary() async {
  await large.loadLibrary();
  large.someFunction();
}
```

## Flutter中的Dart

在Flutter开发中，Dart语言有一些特定的应用方式：

```dart
import 'package:flutter/material.dart';

// 主函数
void main() {
  runApp(MyApp());
}

// 无状态Widget
class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
      theme: ThemeData(
        primarySwatch: Colors.blue,
      ),
      home: MyHomePage(),
    );
  }
}

// 有状态Widget
class MyHomePage extends StatefulWidget {
  @override
  _MyHomePageState createState() => _MyHomePageState();
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
        title: Text('Flutter Demo'),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            Text('You have pushed the button this many times:'),
            Text(
              '$_counter',
              style: TextStyle(fontSize: 24),
            ),
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _incrementCounter,
        tooltip: 'Increment',
        child: Icon(Icons.add),
      ),
    );
  }
}
```

## 常见Dart代码模式

### 单例模式

```dart
class Singleton {
  // 私有静态实例
  static final Singleton _instance = Singleton._internal();
  
  // 工厂构造函数
  factory Singleton() {
    return _instance;
  }
  
  // 私有构造函数
  Singleton._internal();
  
  // 类的其他方法和属性
  void doSomething() {
    print('Singleton is doing something');
  }
}

// 使用
void main() {
  var instance1 = Singleton();
  var instance2 = Singleton();
  print(identical(instance1, instance2));  // true，是同一个实例
}
```

### Builder模式

```dart
class User {
  final String name;
  final int age;
  final String email;
  final String address;
  
  User._builder(UserBuilder builder)
      : name = builder._name,
        age = builder._age,
        email = builder._email,
        address = builder._address;
}

class UserBuilder {
  String _name;
  int _age;
  String? _email;
  String? _address;
  
  UserBuilder(this._name, this._age);
  
  UserBuilder email(String email) {
    _email = email;
    return this;
  }
  
  UserBuilder address(String address) {
    _address = address;
    return this;
  }
  
  User build() {
    return User._builder(this);
  }
}

// 使用
void main() {
  final user = UserBuilder('John', 30)
      .email('john@example.com')
      .address('123 Main St')
      .build();
}
```

## Dart和JavaScript的差异

对于有JavaScript背景的开发者，了解这些差异会很有帮助：

1. **类型系统**：Dart是静态类型的，JavaScript是动态类型的
2. **类的实现**：Dart有真正的类，JavaScript使用原型继承
3. **私有成员**：Dart使用下划线前缀表示私有成员，JavaScript无原生私有成员(ES2022之前)
4. **并发模型**：Dart使用隔离区(isolates)而不是线程，JavaScript使用事件循环
5. **null处理**：Dart有空安全系统，JavaScript没有类似机制(可选链运算符除外)
6. **包管理**：Dart使用pub，JavaScript使用npm或yarn

## 深入学习资源

- [Dart官方文档](https://dart.dev/guides)
- [DartPad](https://dartpad.dev/) - 在线Dart编辑器
- [Effective Dart指南](https://dart.dev/effective-dart) - Dart代码风格指南

## 下一步

现在您已经掌握了Dart的基础知识，接下来可以继续学习：

- [Flutter核心概念](core-concepts.md)
- [Flutter布局与UI设计](layout-ui.md)
- [Flutter状态管理](state-management.md) 