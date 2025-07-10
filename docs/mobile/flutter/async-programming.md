# Flutter 异步编程

异步编程是现代应用程序开发中不可或缺的一部分，尤其在移动应用开发中。Flutter提供了强大的异步编程支持，主要通过Dart语言的`Future`和`Stream`来实现。本文将详细介绍Flutter中的异步编程概念和实践。

## 目录

- [基础概念](#基础概念)
- [Future](#future)
  - [创建Future](#创建future)
  - [处理Future](#处理future)
  - [错误处理](#future错误处理)
  - [Future组合](#future组合)
- [Stream](#stream)
  - [创建Stream](#创建stream)
  - [监听Stream](#监听stream)
  - [转换Stream](#转换stream)
  - [错误处理](#stream错误处理)
- [异步UI更新](#异步ui更新)
  - [FutureBuilder](#futurebuilder)
  - [StreamBuilder](#streambuilder)
- [异步编程模式](#异步编程模式)
  - [生产者-消费者模式](#生产者-消费者模式)
  - [事件驱动编程](#事件驱动编程)
- [最佳实践](#最佳实践)
- [常见问题](#常见问题)
- [参考资源](#参考资源)

## 基础概念

在深入了解Flutter异步编程之前，让我们先理解几个基本概念：

- **同步操作**：按顺序执行，每个操作完成后才执行下一个操作
- **异步操作**：不阻塞主线程，允许程序继续执行其他任务
- **并发**：多个任务看似同时执行（可能在单核上通过时间片轮转）
- **并行**：多个任务真正同时执行（需要多核处理器）

Flutter应用中的UI渲染和用户交互都在主线程（也称为UI线程）上进行。如果在主线程上执行耗时操作（如网络请求、文件读写），会导致应用卡顿甚至无响应。异步编程允许这些耗时操作在后台线程执行，完成后再通知主线程更新UI。

## Future

`Future`代表一个异步操作的结果，它是一个在未来某个时刻完成并产生值（或错误）的承诺。

### 创建Future

有多种方式可以创建`Future`：

1. **使用Future构造函数**

```dart
Future<String> createFuture() {
  return Future<String>(() {
    // 模拟耗时操作
    return "操作完成";
  });
}
```

2. **使用Future.value**

```dart
Future<String> createImmediateFuture() {
  return Future.value("立即完成");
}
```

3. **使用Future.delayed**

```dart
Future<String> createDelayedFuture() {
  return Future.delayed(Duration(seconds: 2), () {
    return "延迟2秒后完成";
  });
}
```

4. **使用async关键字**

```dart
Future<String> createAsyncFuture() async {
  // 使用async关键字标记的函数自动返回Future
  await Future.delayed(Duration(seconds: 1));
  return "异步函数完成";
}
```

### 处理Future

处理`Future`的结果有几种方式：

1. **使用then方法**

```dart
Future<String> fetchData() async {
  await Future.delayed(Duration(seconds: 2));
  return "数据获取成功";
}

void usingThen() {
  fetchData().then((value) {
    print(value); // 输出: 数据获取成功
  });
  print("继续执行其他代码"); // 这行会先执行
}
```

2. **使用async/await**

```dart
void usingAsyncAwait() async {
  print("开始获取数据");
  String result = await fetchData(); // 等待Future完成
  print(result); // 输出: 数据获取成功
  print("数据处理完成"); // 这行会在获取数据后执行
}
```

`async/await`使异步代码看起来更像同步代码，提高了可读性。使用`await`时，函数必须用`async`标记。

### Future错误处理

处理`Future`中的错误：

1. **使用catchError**

```dart
Future<String> riskyOperation() async {
  await Future.delayed(Duration(seconds: 1));
  throw Exception("操作失败");
}

void handleErrorWithCatchError() {
  riskyOperation()
    .then((value) => print(value))
    .catchError((error) => print("捕获到错误: $error"));
}
```

2. **使用try/catch与async/await**

```dart
void handleErrorWithTryCatch() async {
  try {
    String result = await riskyOperation();
    print(result);
  } catch (e) {
    print("捕获到错误: $e");
  } finally {
    print("无论成功失败都会执行");
  }
}
```

### Future组合

有时需要处理多个`Future`：

1. **顺序执行多个Future**

```dart
void sequentialFutures() async {
  String result1 = await fetchData();
  String result2 = await processData(result1);
  String result3 = await saveData(result2);
  print("所有操作完成: $result3");
}
```

2. **并行执行多个Future**

```dart
void parallelFutures() async {
  // 同时启动多个Future
  Future<String> future1 = fetchUserData();
  Future<List<String>> future2 = fetchUserPosts();
  
  // 等待所有Future完成
  var results = await Future.wait([future1, future2]);
  
  String userData = results[0];
  List<String> userPosts = results[1];
  
  print("用户数据: $userData");
  print("用户帖子: $userPosts");
}
```

## Stream

`Stream`表示一系列异步事件，可以看作是多个`Future`的序列。适用于处理连续的数据流，如文件读取、网络响应或用户输入。

### 创建Stream

1. **使用StreamController**

```dart
import 'dart:async';

StreamController<int> createCounterStream() {
  StreamController<int> controller = StreamController<int>();
  
  // 模拟数据源
  int counter = 0;
  Timer.periodic(Duration(seconds: 1), (timer) {
    counter++;
    controller.add(counter); // 向流添加数据
    
    if (counter >= 5) {
      timer.cancel();
      controller.close(); // 关闭流
    }
  });
  
  return controller;
}

void useStreamController() {
  final controller = createCounterStream();
  controller.stream.listen(
    (data) => print("收到数据: $data"),
    onError: (error) => print("错误: $error"),
    onDone: () => print("流已关闭"),
  );
}
```

2. **使用Stream.periodic**

```dart
Stream<int> createPeriodicStream() {
  return Stream.periodic(Duration(seconds: 1), (count) => count).take(5);
}
```

3. **使用async***

```dart
Stream<int> countStream(int max) async* {
  for (int i = 1; i <= max; i++) {
    await Future.delayed(Duration(seconds: 1));
    yield i; // 产生一个值
  }
}

void useAsyncGenerator() {
  countStream(5).listen((data) => print("计数: $data"));
}
```

### 监听Stream

1. **使用listen方法**

```dart
void listenToStream() {
  final stream = countStream(3);
  
  final subscription = stream.listen(
    (data) => print("数据: $data"),
    onError: (error) => print("错误: $error"),
    onDone: () => print("完成"),
    cancelOnError: false, // 发生错误时是否取消订阅
  );
  
  // 可以稍后取消订阅
  Future.delayed(Duration(seconds: 2), () {
    subscription.cancel();
    print("取消订阅");
  });
}
```

2. **暂停和恢复Stream**

```dart
void pauseAndResumeStream() {
  final stream = countStream(10);
  final subscription = stream.listen((data) => print("数据: $data"));
  
  // 2秒后暂停
  Future.delayed(Duration(seconds: 2), () {
    subscription.pause();
    print("流已暂停");
    
    // 再过2秒后恢复
    Future.delayed(Duration(seconds: 2), () {
      subscription.resume();
      print("流已恢复");
    });
  });
}
```

### 转换Stream

Stream可以通过各种方法进行转换：

```dart
void transformStream() {
  final stream = countStream(10);
  
  // 过滤
  stream.where((event) => event % 2 == 0)
        .listen((data) => print("偶数: $data"));
  
  // 映射
  stream.map((event) => "数字 $event")
        .listen((data) => print("映射后: $data"));
  
  // 累加
  stream.fold(0, (previous, element) => previous + element)
        .then((sum) => print("总和: $sum"));
  
  // 限制数量
  stream.take(3).listen((data) => print("前三个: $data"));
  
  // 跳过
  stream.skip(3).listen((data) => print("跳过三个后: $data"));
}
```

### Stream错误处理

处理Stream中的错误：

```dart
Stream<int> errorStream() async* {
  yield 1;
  yield 2;
  throw Exception("发生错误");
  yield 3; // 这行不会执行
}

void handleStreamError() {
  errorStream().handleError((error) {
    print("处理错误: $error");
  }).listen(
    (data) => print("数据: $data"),
    onDone: () => print("完成"),
  );
}
```

## 异步UI更新

Flutter提供了专门的Widget来处理异步数据。

### FutureBuilder

`FutureBuilder`用于基于`Future`的结果构建UI：

```dart
class FutureExample extends StatelessWidget {
  Future<String> fetchData() async {
    await Future.delayed(Duration(seconds: 2));
    return "加载完成";
  }

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<String>(
      future: fetchData(),
      builder: (context, snapshot) {
        if (snapshot.connectionState == ConnectionState.waiting) {
          return CircularProgressIndicator(); // 加载中显示加载指示器
        } else if (snapshot.hasError) {
          return Text('错误: ${snapshot.error}');
        } else {
          return Text('结果: ${snapshot.data}');
        }
      },
    );
  }
}
```

### StreamBuilder

`StreamBuilder`用于基于`Stream`的结果构建UI：

```dart
class StreamExample extends StatelessWidget {
  Stream<int> countStream() async* {
    for (int i = 1; i <= 10; i++) {
      await Future.delayed(Duration(seconds: 1));
      yield i;
    }
  }

  @override
  Widget build(BuildContext context) {
    return StreamBuilder<int>(
      stream: countStream(),
      builder: (context, snapshot) {
        if (snapshot.connectionState == ConnectionState.waiting) {
          return Text('等待第一个数据...');
        } else if (snapshot.connectionState == ConnectionState.active) {
          return Text('当前数据: ${snapshot.data}');
        } else if (snapshot.connectionState == ConnectionState.done) {
          return Text('流已结束，最终数据: ${snapshot.data}');
        } else if (snapshot.hasError) {
          return Text('错误: ${snapshot.error}');
        } else {
          return Text('未知状态');
        }
      },
    );
  }
}
```

## 异步编程模式

### 生产者-消费者模式

Stream非常适合实现生产者-消费者模式：

```dart
class DataProducer {
  final _controller = StreamController<String>();
  
  Stream<String> get dataStream => _controller.stream;
  
  void produceData(String data) {
    _controller.add(data);
  }
  
  void close() {
    _controller.close();
  }
}

class DataConsumer {
  void consumeData(Stream<String> dataStream) {
    dataStream.listen(
      (data) => print("消费数据: $data"),
      onDone: () => print("数据流结束"),
    );
  }
}

void producerConsumerExample() {
  final producer = DataProducer();
  final consumer = DataConsumer();
  
  consumer.consumeData(producer.dataStream);
  
  // 生产数据
  producer.produceData("数据1");
  producer.produceData("数据2");
  producer.produceData("数据3");
  
  // 完成后关闭
  producer.close();
}
```

### 事件驱动编程

Flutter的整个UI框架都是基于事件驱动的。使用Stream可以轻松实现事件总线：

```dart
class EventBus {
  // 单例模式
  static final EventBus _instance = EventBus._internal();
  factory EventBus() => _instance;
  EventBus._internal();
  
  final _streamControllers = <String, StreamController>{};
  
  // 获取特定事件的流
  Stream<T> on<T>() {
    if (!_streamControllers.containsKey(T.toString())) {
      _streamControllers[T.toString()] = StreamController<T>.broadcast();
    }
    return _streamControllers[T.toString()]!.stream as Stream<T>;
  }
  
  // 发送事件
  void fire<T>(T event) {
    if (_streamControllers.containsKey(T.toString())) {
      _streamControllers[T.toString()]!.add(event);
    }
  }
  
  // 销毁
  void dispose() {
    _streamControllers.forEach((_, controller) => controller.close());
    _streamControllers.clear();
  }
}

// 使用示例
class UserLoggedInEvent {
  final String username;
  UserLoggedInEvent(this.username);
}

void eventBusExample() {
  final eventBus = EventBus();
  
  // 订阅事件
  eventBus.on<UserLoggedInEvent>().listen((event) {
    print("用户登录: ${event.username}");
  });
  
  // 发送事件
  eventBus.fire(UserLoggedInEvent("张三"));
}
```

## 最佳实践

1. **合理使用async/await**
   - 使用async/await使代码更易读
   - 不要在不需要等待结果的地方使用await

2. **错误处理**
   - 始终处理异步操作中的错误
   - 使用try-catch或catchError捕获异常

3. **避免Future嵌套**
   - 避免回调地狱，使用async/await扁平化代码

4. **取消不再需要的订阅**
   - 在不需要时取消Stream订阅，避免内存泄漏
   - 在Widget的dispose方法中取消订阅

5. **使用适当的Stream类型**
   - 单一订阅流：只能被监听一次
   - 广播流：可以有多个监听者

```dart
// 在StatefulWidget中正确管理Stream订阅
class StreamDemoWidget extends StatefulWidget {
  @override
  _StreamDemoWidgetState createState() => _StreamDemoWidgetState();
}

class _StreamDemoWidgetState extends State<StreamDemoWidget> {
  StreamSubscription? _subscription;
  
  @override
  void initState() {
    super.initState();
    _subscription = someStream().listen((data) {
      // 处理数据
    });
  }
  
  @override
  void dispose() {
    _subscription?.cancel(); // 取消订阅
    super.dispose();
  }
  
  @override
  Widget build(BuildContext context) {
    // 构建UI
    return Container();
  }
}
```

## 常见问题

### 1. Future与Isolate的区别？

- **Future**：表示异步操作的结果，但仍在主线程上执行
- **Isolate**：真正的并行执行，在单独的线程中运行代码

```dart
import 'dart:isolate';

void computeInIsolate() async {
  // 创建一个接收端口
  final receivePort = ReceivePort();
  
  // 启动isolate
  await Isolate.spawn(
    heavyComputation,
    receivePort.sendPort,
  );
  
  // 获取结果
  final result = await receivePort.first;
  print("计算结果: $result");
}

void heavyComputation(SendPort sendPort) {
  // 执行耗时计算
  int sum = 0;
  for (int i = 0; i < 1000000000; i++) {
    sum += i;
  }
  
  // 发送结果回主isolate
  sendPort.send(sum);
}
```

### 2. 如何处理并发请求限制？

使用`SemaphoreCompleter`或自定义队列：

```dart
class RequestLimiter {
  final int maxConcurrent;
  int _currentRequests = 0;
  final _queue = <Completer>[];
  
  RequestLimiter({this.maxConcurrent = 5});
  
  Future<void> acquire() async {
    if (_currentRequests < maxConcurrent) {
      _currentRequests++;
      return Future.value();
    }
    
    final completer = Completer();
    _queue.add(completer);
    return completer.future;
  }
  
  void release() {
    _currentRequests--;
    
    if (_queue.isNotEmpty) {
      final completer = _queue.removeAt(0);
      _currentRequests++;
      completer.complete();
    }
  }
}

// 使用示例
Future<void> limitedRequests() async {
  final limiter = RequestLimiter(maxConcurrent: 2);
  
  Future<void> makeRequest(int id) async {
    await limiter.acquire();
    print("开始请求 $id");
    
    try {
      await Future.delayed(Duration(seconds: 2));
      print("完成请求 $id");
    } finally {
      limiter.release();
    }
  }
  
  // 同时发起5个请求，但最多只有2个并发执行
  await Future.wait([
    makeRequest(1),
    makeRequest(2),
    makeRequest(3),
    makeRequest(4),
    makeRequest(5),
  ]);
}
```

### 3. 如何处理超时？

```dart
Future<String> fetchWithTimeout() async {
  return await Future.any([
    fetchData(), // 实际操作
    Future.delayed(Duration(seconds: 5)).then((_) => 
      throw TimeoutException('请求超时')),
  ]);
}

// 或使用timeout扩展方法
Future<String> fetchWithTimeoutMethod() {
  return fetchData().timeout(
    Duration(seconds: 5),
    onTimeout: () => throw TimeoutException('请求超时'),
  );
}
```

## 参考资源

- [Dart异步编程官方文档](https://dart.dev/codelabs/async-await)
- [Flutter中的异步编程](https://flutter.dev/docs/cookbook/networking/fetch-data)
- [Dart Stream API文档](https://api.dart.dev/stable/dart-async/Stream-class.html)
- [Flutter异步编程最佳实践](https://flutter.dev/docs/cookbook#networking)
