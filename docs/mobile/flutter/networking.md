# 网络请求

在移动应用开发中，网络请求是连接应用与后端服务的关键环节。Flutter提供了多种进行网络通信的方式，从内置的`http`包到功能强大的第三方库如`Dio`。本文档将详细介绍如何在Flutter应用中实现网络请求、处理响应以及集成API服务。

## 基础概念

在深入具体的网络请求库之前，了解一些基础概念很重要：

### HTTP请求方法

- **GET**: 获取资源
- **POST**: 创建资源
- **PUT**: 更新资源
- **PATCH**: 部分更新资源
- **DELETE**: 删除资源

### 常见状态码

- **2xx**: 成功 (如200 OK, 201 Created)
- **3xx**: 重定向
- **4xx**: 客户端错误 (如400 Bad Request, 404 Not Found)
- **5xx**: 服务器错误

### 请求/响应格式

常见的数据交换格式：
- **JSON** (JavaScript Object Notation)
- **XML** (eXtensible Markup Language)
- **Form-data** (表单数据)
- **Binary** (二进制数据，如文件上传/下载)

## Dio 网络库

[Dio](https://pub.dev/packages/dio) 是一个强大的Flutter HTTP客户端，支持全局配置、拦截器、FormData、请求取消、文件下载、超时等功能。

### 安装

在`pubspec.yaml`文件中添加依赖：

```yaml
dependencies:
  dio: ^5.3.0
```

### 基本用法

```dart
import 'package:dio/dio.dart';

void main() async {
  // 创建Dio实例
  final dio = Dio();
  
  try {
    // 发送GET请求
    final response = await dio.get('https://api.example.com/data');
    print('数据获取成功：${response.data}');
    
    // 发送带参数的GET请求
    final response2 = await dio.get(
      'https://api.example.com/users',
      queryParameters: {'page': 1, 'limit': 10},
    );
    print('用户列表：${response2.data}');
    
    // 发送POST请求
    final response3 = await dio.post(
      'https://api.example.com/users',
      data: {'name': '张三', 'email': 'zhangsan@example.com'},
    );
    print('用户创建成功：${response3.data}');
    
  } catch (e) {
    // 错误处理
    if (e is DioException) {
      print('Dio错误: ${e.message}');
      // 可以根据e.type来处理不同类型的错误
      if (e.type == DioExceptionType.connectionTimeout) {
        print('连接超时');
      }
    } else {
      print('其他错误: $e');
    }
  }
}
```

### Dio配置

可以在创建Dio实例时设置全局配置：

```dart
final dio = Dio(
  BaseOptions(
    baseUrl: 'https://api.example.com',
    connectTimeout: Duration(seconds: 5),
    receiveTimeout: Duration(seconds: 3),
    headers: {
      'Authorization': 'Bearer token',
      'Content-Type': 'application/json',
    },
    responseType: ResponseType.json,
  ),
);
```

### 请求拦截器

拦截器可以在请求发送前或响应接收后进行处理：

```dart
// 添加拦截器
dio.interceptors.add(
  InterceptorsWrapper(
    // 请求拦截
    onRequest: (options, handler) {
      print('发送请求: ${options.method} ${options.uri}');
      // 如果需要，可以修改options
      options.headers['token'] = '获取最新的token';
      return handler.next(options);
    },
    // 响应拦截
    onResponse: (response, handler) {
      print('接收响应: ${response.statusCode}');
      // 可以修改response
      return handler.next(response);
    },
    // 错误拦截
    onError: (DioException error, handler) {
      print('请求错误: ${error.message}');
      // 可以尝试恢复错误
      if (error.response?.statusCode == 401) {
        // 处理认证错误
        print('需要重新登录');
      }
      return handler.next(error);
    },
  ),
);
```

### 表单提交与文件上传

```dart
import 'package:dio/dio.dart';
import 'dart:io';

Future<void> uploadFile() async {
  final dio = Dio();
  
  // 创建FormData
  final formData = FormData.fromMap({
    'name': '张三',
    'age': 25,
    // 上传文件
    'avatar': await MultipartFile.fromFile(
      '/path/to/file.jpg',
      filename: 'avatar.jpg',
    ),
    // 或者从字节数组创建
    'document': MultipartFile.fromBytes(
      [/* 字节数据 */],
      filename: 'doc.pdf',
    ),
    // 添加多个文件
    'photos': [
      await MultipartFile.fromFile('/path/to/photo1.jpg'),
      await MultipartFile.fromFile('/path/to/photo2.jpg'),
    ],
  });
  
  try {
    final response = await dio.post(
      'https://api.example.com/upload',
      data: formData,
      onSendProgress: (sent, total) {
        print('上传进度: ${(sent / total * 100).toStringAsFixed(0)}%');
      },
    );
    
    print('上传成功: ${response.data}');
    
  } catch (e) {
    print('上传失败: $e');
  }
}
```

### 文件下载

```dart
Future<void> downloadFile() async {
  final dio = Dio();
  
  try {
    await dio.download(
      'https://example.com/files/large_file.zip',
      '/path/to/save/large_file.zip',
      onReceiveProgress: (received, total) {
        if (total != -1) {
          print('下载进度: ${(received / total * 100).toStringAsFixed(0)}%');
        }
      },
    );
    
    print('下载完成');
    
  } catch (e) {
    print('下载失败: $e');
  }
}
```

### 取消请求

```dart
void cancelRequest() {
  final dio = Dio();
  
  // 创建取消令牌
  final cancelToken = CancelToken();
  
  // 发起请求
  dio.get(
    'https://api.example.com/slow-request',
    cancelToken: cancelToken,
  ).then((response) {
    print('请求成功: ${response.data}');
  }).catchError((error) {
    if (CancelToken.isCancel(error)) {
      print('请求已取消: ${error.message}');
    } else {
      print('请求失败: $error');
    }
  });
  
  // 稍后取消请求
  Future.delayed(Duration(seconds: 2), () {
    cancelToken.cancel('用户取消了请求');
    print('请求已取消');
  });
}
```

### 超时和重试

```dart
Future<Response> requestWithRetry({
  required String url,
  int maxRetries = 3,
  Duration timeout = const Duration(seconds: 5),
}) async {
  final dio = Dio(BaseOptions(connectTimeout: timeout));
  int attempts = 0;
  
  while (attempts < maxRetries) {
    try {
      return await dio.get(url);
    } on DioException catch (e) {
      attempts++;
      if (e.type == DioExceptionType.connectionTimeout ||
          e.type == DioExceptionType.receiveTimeout) {
        print('请求超时，尝试重试 $attempts/$maxRetries');
        if (attempts >= maxRetries) rethrow;
        await Future.delayed(Duration(milliseconds: 500 * attempts));
      } else {
        rethrow;
      }
    }
  }
  
  throw Exception('超出最大重试次数');
}
```

## Flutter内置的http包

除了Dio，Flutter还提供了一个官方的[http](https://pub.dev/packages/http)包，它简单且易用，适合基本的网络需求。

### 安装

```yaml
dependencies:
  http: ^1.1.0
```

### 基本用法

```dart
import 'package:http/http.dart' as http;
import 'dart:convert';

Future<void> fetchData() async {
  try {
    // GET请求
    final response = await http.get(Uri.parse('https://api.example.com/data'));
    
    if (response.statusCode == 200) {
      // 解析JSON
      final data = jsonDecode(response.body);
      print('获取数据成功: $data');
    } else {
      print('请求失败: ${response.statusCode}');
    }
    
    // POST请求
    final postResponse = await http.post(
      Uri.parse('https://api.example.com/users'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'name': '张三', 'email': 'zhangsan@example.com'}),
    );
    
    if (postResponse.statusCode == 201) {
      print('创建成功: ${jsonDecode(postResponse.body)}');
    } else {
      print('创建失败: ${postResponse.statusCode}');
    }
    
  } catch (e) {
    print('网络错误: $e');
  }
}
```

### http与Dio的对比

| 特性 | http | Dio |
|------|------|-----|
| 易用性 | 简单直接 | 功能丰富，需要更多代码 |
| 功能 | 基础HTTP操作 | 完整的网络功能集 |
| 拦截器 | 不支持 | 支持请求/响应拦截 |
| 文件上传 | 基础支持 | 完整支持，包括进度监听 |
| 取消请求 | 不支持 | 支持 |
| 超时控制 | 基础支持 | 完整支持 |
| 错误处理 | 基础 | 详细错误分类 |
| 依赖大小 | 轻量级 | 较大 |

## REST API集成

在实际应用中，我们通常需要与后端REST API进行交互。下面介绍如何将网络请求封装为结构化的API服务。

### API服务层设计

一个良好的API服务层设计应包括：

1. API客户端类 - 处理基础网络请求
2. 模型类 - 定义数据结构
3. 仓库类 - 封装业务逻辑
4. 错误处理策略

#### 基本模型定义

首先，定义模型类来表示API数据：

```dart
// 用户模型
class User {
  final int id;
  final String name;
  final String email;
  final String? avatar;
  
  User({
    required this.id,
    required this.name,
    required this.email,
    this.avatar,
  });
  
  // 从JSON创建模型
  factory User.fromJson(Map<String, dynamic> json) {
    return User(
      id: json['id'],
      name: json['name'],
      email: json['email'],
      avatar: json['avatar'],
    );
  }
  
  // 转换为JSON
  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'name': name,
      'email': email,
      'avatar': avatar,
    };
  }
}
```

#### API客户端

创建一个API客户端类来处理所有网络请求：

```dart
import 'package:dio/dio.dart';

class ApiClient {
  final Dio _dio;
  
  // API基础URL
  static const String baseUrl = 'https://api.example.com';
  
  // API端点
  static const String usersEndpoint = '/users';
  static const String authEndpoint = '/auth';
  
  // 单例模式
  static final ApiClient _instance = ApiClient._internal();
  
  factory ApiClient() {
    return _instance;
  }
  
  // 私有构造函数
  ApiClient._internal()
      : _dio = Dio(BaseOptions(
          baseUrl: baseUrl,
          connectTimeout: Duration(seconds: 5),
          receiveTimeout: Duration(seconds: 3),
          contentType: 'application/json',
        )) {
    // 初始化拦截器
    _initializeInterceptors();
  }
  
  // 初始化拦截器
  void _initializeInterceptors() {
    _dio.interceptors.add(
      InterceptorsWrapper(
        onRequest: (options, handler) {
          // 添加认证头
          final token = _getToken();
          if (token != null) {
            options.headers['Authorization'] = 'Bearer $token';
          }
          return handler.next(options);
        },
        onResponse: (response, handler) {
          return handler.next(response);
        },
        onError: (DioException error, handler) {
          // 处理错误
          if (error.response?.statusCode == 401) {
            // 处理授权错误，例如刷新token或引导用户登录
            _refreshToken().then((_) {
              // 重试原始请求
              _retryRequest(error.requestOptions);
            }).catchError((e) {
              // 刷新token失败，需要重新登录
              _handleAuthError();
              return handler.next(error);
            });
          } else {
            return handler.next(error);
          }
        },
      ),
    );
    
    // 日志拦截器
    _dio.interceptors.add(LogInterceptor(
      request: true,
      requestHeader: true,
      requestBody: true,
      responseHeader: true,
      responseBody: true,
      error: true,
    ));
  }
  
  // 获取存储的token
  String? _getToken() {
    // 从本地存储获取token
    // 实际应用中可能使用SharedPreferences或安全存储
    return null; // 示例
  }
  
  // 刷新token
  Future<void> _refreshToken() async {
    // 刷新token的逻辑
    // ...
  }
  
  // 重试请求
  Future<void> _retryRequest(RequestOptions requestOptions) async {
    // 使用新token重试原始请求
    final options = Options(
      method: requestOptions.method,
      headers: requestOptions.headers,
    );
    
    await _dio.request<dynamic>(
      requestOptions.path,
      data: requestOptions.data,
      queryParameters: requestOptions.queryParameters,
      options: options,
    );
  }
  
  // 处理认证错误
  void _handleAuthError() {
    // 处理认证错误，例如导航到登录页面
    // ...
  }
  
  // GET请求方法
  Future<T> get<T>(
    String path, {
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
  }) async {
    try {
      final response = await _dio.get<T>(
        path,
        queryParameters: queryParameters,
        options: options,
        cancelToken: cancelToken,
      );
      return response.data as T;
    } catch (e) {
      throw _handleError(e);
    }
  }
  
  // POST请求方法
  Future<T> post<T>(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
    ProgressCallback? onSendProgress,
  }) async {
    try {
      final response = await _dio.post<T>(
        path,
        data: data,
        queryParameters: queryParameters,
        options: options,
        cancelToken: cancelToken,
        onSendProgress: onSendProgress,
      );
      return response.data as T;
    } catch (e) {
      throw _handleError(e);
    }
  }
  
  // PUT请求方法
  Future<T> put<T>(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
  }) async {
    try {
      final response = await _dio.put<T>(
        path,
        data: data,
        queryParameters: queryParameters,
        options: options,
        cancelToken: cancelToken,
      );
      return response.data as T;
    } catch (e) {
      throw _handleError(e);
    }
  }
  
  // DELETE请求方法
  Future<T> delete<T>(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
  }) async {
    try {
      final response = await _dio.delete<T>(
        path,
        data: data,
        queryParameters: queryParameters,
        options: options,
        cancelToken: cancelToken,
      );
      return response.data as T;
    } catch (e) {
      throw _handleError(e);
    }
  }
  
  // 处理错误
  Exception _handleError(dynamic error) {
    if (error is DioException) {
      // 处理Dio错误
      switch (error.type) {
        case DioExceptionType.connectionTimeout:
        case DioExceptionType.sendTimeout:
        case DioExceptionType.receiveTimeout:
          return TimeoutException('网络请求超时');
        case DioExceptionType.badResponse:
          return ApiException(
            error.response?.statusCode ?? 0,
            error.response?.statusMessage ?? '未知错误',
            error.response?.data,
          );
        case DioExceptionType.cancel:
          return RequestCanceledException('请求被取消');
        case DioExceptionType.connectionError:
          return NetworkException('网络连接错误');
        default:
          return UnknownException('未知网络错误');
      }
    }
    return UnknownException('未知错误: $error');
  }
}

// 自定义异常类
class ApiException implements Exception {
  final int statusCode;
  final String message;
  final dynamic data;
  
  ApiException(this.statusCode, this.message, this.data);
  
  @override
  String toString() {
    return 'ApiException: $statusCode - $message';
  }
}

class TimeoutException implements Exception {
  final String message;
  
  TimeoutException(this.message);
  
  @override
  String toString() {
    return 'TimeoutException: $message';
  }
}

class NetworkException implements Exception {
  final String message;
  
  NetworkException(this.message);
  
  @override
  String toString() {
    return 'NetworkException: $message';
  }
}

class RequestCanceledException implements Exception {
  final String message;
  
  RequestCanceledException(this.message);
  
  @override
  String toString() {
    return 'RequestCanceledException: $message';
  }
}

class UnknownException implements Exception {
  final String message;
  
  UnknownException(this.message);
  
  @override
  String toString() {
    return 'UnknownException: $message';
  }
}
```

#### 用户服务

创建特定的服务类来处理用户相关操作：

```dart
class UserService {
  final ApiClient _apiClient = ApiClient();
  
  // 获取用户列表
  Future<List<User>> getUsers({int page = 1, int limit = 10}) async {
    try {
      final response = await _apiClient.get<Map<String, dynamic>>(
        ApiClient.usersEndpoint,
        queryParameters: {'page': page, 'limit': limit},
      );
      
      // 解析响应数据
      final List<dynamic> usersJson = response['data'];
      return usersJson.map((json) => User.fromJson(json)).toList();
    } catch (e) {
      print('获取用户失败: $e');
      rethrow;
    }
  }
  
  // 获取单个用户
  Future<User> getUserById(int userId) async {
    try {
      final response = await _apiClient.get<Map<String, dynamic>>(
        '${ApiClient.usersEndpoint}/$userId',
      );
      
      return User.fromJson(response['data']);
    } catch (e) {
      print('获取用户失败: $e');
      rethrow;
    }
  }
  
  // 创建用户
  Future<User> createUser(User user) async {
    try {
      final response = await _apiClient.post<Map<String, dynamic>>(
        ApiClient.usersEndpoint,
        data: user.toJson(),
      );
      
      return User.fromJson(response['data']);
    } catch (e) {
      print('创建用户失败: $e');
      rethrow;
    }
  }
  
  // 更新用户
  Future<User> updateUser(User user) async {
    try {
      final response = await _apiClient.put<Map<String, dynamic>>(
        '${ApiClient.usersEndpoint}/${user.id}',
        data: user.toJson(),
      );
      
      return User.fromJson(response['data']);
    } catch (e) {
      print('更新用户失败: $e');
      rethrow;
    }
  }
  
  // 删除用户
  Future<void> deleteUser(int userId) async {
    try {
      await _apiClient.delete<Map<String, dynamic>>(
        '${ApiClient.usersEndpoint}/$userId',
      );
    } catch (e) {
      print('删除用户失败: $e');
      rethrow;
    }
  }
}
```

### 与UI集成

将API服务与Flutter UI集成：

```dart
import 'package:flutter/material.dart';

class UserListScreen extends StatefulWidget {
  const UserListScreen({Key? key}) : super(key: key);

  @override
  _UserListScreenState createState() => _UserListScreenState();
}

class _UserListScreenState extends State<UserListScreen> {
  final UserService _userService = UserService();
  List<User> _users = [];
  bool _isLoading = false;
  String _errorMessage = '';

  @override
  void initState() {
    super.initState();
    _loadUsers();
  }

  Future<void> _loadUsers() async {
    setState(() {
      _isLoading = true;
      _errorMessage = '';
    });

    try {
      final users = await _userService.getUsers();
      setState(() {
        _users = users;
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        _isLoading = false;
        _errorMessage = '加载用户失败: $e';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('用户列表'),
        actions: [
          IconButton(
            icon: Icon(Icons.refresh),
            onPressed: _loadUsers,
          ),
        ],
      ),
      body: _buildBody(),
      floatingActionButton: FloatingActionButton(
        child: Icon(Icons.add),
        onPressed: () {
          // 导航到添加用户页面
        },
      ),
    );
  }

  Widget _buildBody() {
    if (_isLoading) {
      return Center(child: CircularProgressIndicator());
    }

    if (_errorMessage.isNotEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Text(_errorMessage, style: TextStyle(color: Colors.red)),
            SizedBox(height: 16),
            ElevatedButton(
              child: Text('重试'),
              onPressed: _loadUsers,
            ),
          ],
        ),
      );
    }

    if (_users.isEmpty) {
      return Center(child: Text('没有用户数据'));
    }

    return ListView.builder(
      itemCount: _users.length,
      itemBuilder: (context, index) {
        final user = _users[index];
        return ListTile(
          leading: user.avatar != null
              ? CircleAvatar(backgroundImage: NetworkImage(user.avatar!))
              : CircleAvatar(child: Text(user.name[0])),
          title: Text(user.name),
          subtitle: Text(user.email),
          onTap: () {
            // 导航到用户详情页
          },
        );
      },
    );
  }
}
```

### 使用Repository模式

采用Repository模式可以进一步抽象数据源：

```dart
// 用户仓库接口
abstract class UserRepository {
  Future<List<User>> getUsers({int page, int limit});
  Future<User> getUserById(int userId);
  Future<User> createUser(User user);
  Future<User> updateUser(User user);
  Future<void> deleteUser(int userId);
}

// 远程API实现
class ApiUserRepository implements UserRepository {
  final UserService _userService = UserService();
  
  @override
  Future<List<User>> getUsers({int page = 1, int limit = 10}) {
    return _userService.getUsers(page: page, limit: limit);
  }
  
  @override
  Future<User> getUserById(int userId) {
    return _userService.getUserById(userId);
  }
  
  @override
  Future<User> createUser(User user) {
    return _userService.createUser(user);
  }
  
  @override
  Future<User> updateUser(User user) {
    return _userService.updateUser(user);
  }
  
  @override
  Future<void> deleteUser(int userId) {
    return _userService.deleteUser(userId);
  }
}

// 本地数据库实现
class LocalUserRepository implements UserRepository {
  // 实现本地数据库操作...
  // ...
}

// 缓存仓库（组合远程和本地）
class CachedUserRepository implements UserRepository {
  final UserRepository _remoteRepository;
  final UserRepository _localRepository;
  
  CachedUserRepository(this._remoteRepository, this._localRepository);
  
  @override
  Future<List<User>> getUsers({int page = 1, int limit = 10}) async {
    try {
      // 先从远程获取
      final users = await _remoteRepository.getUsers(page: page, limit: limit);
      // 缓存到本地
      _cacheUsers(users);
      return users;
    } catch (e) {
      // 远程获取失败，从本地获取
      return _localRepository.getUsers(page: page, limit: limit);
    }
  }
  
  // 缓存用户到本地
  Future<void> _cacheUsers(List<User> users) async {
    // 实现缓存逻辑
    // ...
  }
  
  // 实现其他方法...
  // ...
}
```

## 最佳实践

### 错误处理

良好的错误处理是API集成的关键部分：

```dart
Future<T> safeApiCall<T>(Future<T> Function() apiCall) async {
  try {
    return await apiCall();
  } on ApiException catch (e) {
    // 处理API错误
    if (e.statusCode == 400) {
      // 处理请求错误
    } else if (e.statusCode == 401 || e.statusCode == 403) {
      // 处理授权错误
    } else if (e.statusCode == 404) {
      // 处理资源不存在
    } else if (e.statusCode >= 500) {
      // 处理服务器错误
    }
    rethrow;
  } on TimeoutException {
    // 处理超时
    throw TimeoutException('请求超时，请检查您的网络连接');
  } on NetworkException {
    // 处理网络错误
    throw NetworkException('网络连接错误，请检查您的网络设置');
  } catch (e) {
    // 处理其他错误
    throw UnknownException('未知错误: $e');
  }
}

// 使用示例
Future<List<User>> getUsers() async {
  return safeApiCall(() => _userService.getUsers());
}
```

### 依赖注入

使用依赖注入可以更好地管理服务依赖：

```dart
// 使用Provider包进行依赖注入
void main() {
  runApp(
    MultiProvider(
      providers: [
        Provider<ApiClient>(
          create: (_) => ApiClient(),
        ),
        Provider<UserService>(
          create: (context) => UserService(context.read<ApiClient>()),
        ),
        Provider<UserRepository>(
          create: (context) => ApiUserRepository(context.read<UserService>()),
        ),
      ],
      child: MyApp(),
    ),
  );
}

// 在组件中使用
class UserListScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final userRepository = context.read<UserRepository>();
    
    return FutureBuilder<List<User>>(
      future: userRepository.getUsers(),
      builder: (context, snapshot) {
        // 构建UI...
      },
    );
  }
}
```

### 响应式编程

使用StreamController或BLoC模式处理API响应：

```dart
class UserBloc {
  final UserRepository _repository;
  final _usersController = StreamController<List<User>>.broadcast();
  
  Stream<List<User>> get users => _usersController.stream;
  
  UserBloc(this._repository);
  
  Future<void> loadUsers() async {
    try {
      final users = await _repository.getUsers();
      _usersController.sink.add(users);
    } catch (e) {
      _usersController.sink.addError(e);
    }
  }
  
  void dispose() {
    _usersController.close();
  }
}

// 在UI中使用
class UserListScreen extends StatefulWidget {
  @override
  _UserListScreenState createState() => _UserListScreenState();
}

class _UserListScreenState extends State<UserListScreen> {
  late UserBloc _userBloc;
  
  @override
  void initState() {
    super.initState();
    _userBloc = UserBloc(context.read<UserRepository>());
    _userBloc.loadUsers();
  }
  
  @override
  void dispose() {
    _userBloc.dispose();
    super.dispose();
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('用户列表')),
      body: StreamBuilder<List<User>>(
        stream: _userBloc.users,
        builder: (context, snapshot) {
          if (snapshot.hasError) {
            return Center(child: Text('错误: ${snapshot.error}'));
          }
          
          if (!snapshot.hasData) {
            return Center(child: CircularProgressIndicator());
          }
          
          final users = snapshot.data!;
          return ListView.builder(
            itemCount: users.length,
            itemBuilder: (context, index) => UserListItem(user: users[index]),
          );
        },
      ),
    );
  }
}
```

## 总结

本文档介绍了Flutter中网络请求的实现方式，包括：

1. 使用Dio进行网络请求，处理各种高级场景如文件上传下载、请求拦截和取消请求
2. 使用Flutter内置的http包进行简单的网络请求
3. 构建结构化的REST API服务层，包括API客户端、服务类和仓库模式
4. 网络错误处理和最佳实践

在选择网络方案时，考虑应用的复杂性、性能需求以及可维护性。对于简单应用，内置的http包可能足够；对于复杂应用，建议使用Dio并结合仓库模式构建更健壮的网络层。

## 下一步

- 学习[状态管理](state-management.md)来有效管理API数据
- 探索[数据持久化](data-persistence.md)方案来缓存API结果
- 了解[应用架构](architecture.md)设计