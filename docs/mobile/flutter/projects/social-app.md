# Flutter社交媒体客户端开发指南

## 目录

- [项目概述](#项目概述)
- [技术栈选择](#技术栈选择)
- [项目结构](#项目结构)
- [用户认证模块](#用户认证模块)
- [社交Feed模块](#社交feed模块)
- [用户资料模块](#用户资料模块)
- [聊天消息模块](#聊天消息模块)
- [通知系统](#通知系统)
- [性能优化](#性能优化)
- [部署与发布](#部署与发布)

## 项目概述

本指南将详细介绍如何使用Flutter构建一个功能完善的社交媒体客户端应用。该应用将具备以下主要功能：

- 用户注册与登录
- 个人资料管理
- 社交动态流(Feed)展示与交互
- 好友关系管理
- 私信聊天
- 通知系统
- 图片和视频分享
- 点赞、评论和分享功能

## 技术栈选择

### 前端技术

- **Flutter SDK**: 跨平台UI框架
- **Provider/Riverpod**: 状态管理
- **Dio**: 网络请求
- **Hive/SharedPreferences**: 本地存储
- **Firebase Auth**: 用户认证
- **Socket.IO**: 实时通信

### 后端技术

- **Firebase**: 提供认证、云存储和实时数据库
- **REST API**: 与自定义后端服务通信
- **WebSockets**: 实现实时通信功能

## 项目结构

采用基于特性(Feature-first)的项目结构:

```
lib/
├── main.dart                 # 应用入口文件
├── app.dart                  # 应用根组件
├── config/                   # 配置文件
│   ├── app_config.dart       # 应用配置
│   ├── theme.dart            # 主题配置
│   └── routes.dart           # 路由配置
├── core/                     # 核心模块
│   ├── api/                  # API客户端
│   ├── errors/               # 错误处理
│   ├── localization/         # 国际化
│   ├── utils/                # 工具类
│   └── widgets/              # 共享组件
└── features/                 # 功能模块
    ├── auth/                 # 认证模块
    ├── feed/                 # 社交流模块
    ├── profile/              # 个人资料模块
    ├── chat/                 # 聊天模块
    └── notifications/        # 通知模块
```

每个功能模块目录包含:

```
features/auth/
├── data/                     # 数据层
│   ├── datasources/          # 数据源
│   ├── models/               # 数据模型
│   └── repositories/         # 仓库实现
├── domain/                   # 领域层
│   ├── entities/             # 实体
│   ├── repositories/         # 仓库接口
│   └── usecases/             # 用例
└── presentation/             # 表现层
    ├── pages/                # 页面
    ├── widgets/              # 组件
    ├── blocs/                # 状态管理
    └── utils/                # 工具方法
```

## 用户认证模块

### 数据模型

创建用户认证相关的数据模型:

```dart
// lib/features/auth/data/models/user_model.dart
class UserModel {
  final String id;
  final String username;
  final String email;
  final String? avatar;
  final DateTime createdAt;

  UserModel({
    required this.id,
    required this.username,
    required this.email,
    this.avatar,
    required this.createdAt,
  });

  factory UserModel.fromJson(Map<String, dynamic> json) {
    return UserModel(
      id: json['id'],
      username: json['username'],
      email: json['email'],
      avatar: json['avatar'],
      createdAt: DateTime.parse(json['created_at']),
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'username': username,
      'email': email,
      'avatar': avatar,
      'created_at': createdAt.toIso8601String(),
    };
  }
}
```

### 认证仓库

定义认证仓库接口和实现:

```dart
// lib/features/auth/domain/repositories/auth_repository.dart
abstract class AuthRepository {
  Future<UserModel> signIn(String email, String password);
  Future<UserModel> signUp(String username, String email, String password);
  Future<void> signOut();
  Future<UserModel?> getCurrentUser();
}

// lib/features/auth/data/repositories/auth_repository_impl.dart
class AuthRepositoryImpl implements AuthRepository {
  final FirebaseAuth _firebaseAuth;
  final HttpClient _httpClient;
  final SharedPreferences _prefs;

  AuthRepositoryImpl(this._firebaseAuth, this._httpClient, this._prefs);

  @override
  Future<UserModel> signIn(String email, String password) async {
    try {
      // Firebase认证
      final userCredential = await _firebaseAuth.signInWithEmailAndPassword(
        email: email, 
        password: password,
      );
      
      // 获取用户信息
      final response = await _httpClient.get('/users/${userCredential.user!.uid}');
      final userData = response.data;
      
      // 保存token
      await _prefs.setString('auth_token', userData['token']);
      
      return UserModel.fromJson(userData['user']);
    } catch (e) {
      throw AuthException('登录失败: $e');
    }
  }

  @override
  Future<UserModel> signUp(String username, String email, String password) async {
    try {
      // Firebase创建账号
      final userCredential = await _firebaseAuth.createUserWithEmailAndPassword(
        email: email, 
        password: password,
      );
      
      // 创建用户资料
      final response = await _httpClient.post(
        '/users',
        data: {
          'id': userCredential.user!.uid,
          'username': username,
          'email': email,
        },
      );
      
      // 保存token
      await _prefs.setString('auth_token', response.data['token']);
      
      return UserModel.fromJson(response.data['user']);
    } catch (e) {
      throw AuthException('注册失败: $e');
    }
  }

  @override
  Future<void> signOut() async {
    await _firebaseAuth.signOut();
    await _prefs.remove('auth_token');
  }

  @override
  Future<UserModel?> getCurrentUser() async {
    try {
      final currentUser = _firebaseAuth.currentUser;
      if (currentUser == null) return null;
      
      final response = await _httpClient.get('/users/${currentUser.uid}');
      return UserModel.fromJson(response.data['user']);
    } catch (e) {
      return null;
    }
  }
}
```

### 状态管理

使用Provider管理认证状态:

```dart
// lib/features/auth/presentation/providers/auth_provider.dart
class AuthProvider extends ChangeNotifier {
  final AuthRepository _authRepository;
  
  UserModel? _currentUser;
  bool _isLoading = false;
  String? _error;
  
  AuthProvider(this._authRepository) {
    _initialize();
  }
  
  UserModel? get currentUser => _currentUser;
  bool get isLoading => _isLoading;
  String? get error => _error;
  bool get isAuthenticated => _currentUser != null;
  
  Future<void> _initialize() async {
    _isLoading = true;
    notifyListeners();
    
    _currentUser = await _authRepository.getCurrentUser();
    
    _isLoading = false;
    notifyListeners();
  }
  
  Future<bool> signIn(String email, String password) async {
    _isLoading = true;
    _error = null;
    notifyListeners();
    
    try {
      _currentUser = await _authRepository.signIn(email, password);
      _isLoading = false;
      notifyListeners();
      return true;
    } catch (e) {
      _error = e.toString();
      _isLoading = false;
      notifyListeners();
      return false;
    }
  }
  
  Future<bool> signUp(String username, String email, String password) async {
    _isLoading = true;
    _error = null;
    notifyListeners();
    
    try {
      _currentUser = await _authRepository.signUp(username, email, password);
      _isLoading = false;
      notifyListeners();
      return true;
    } catch (e) {
      _error = e.toString();
      _isLoading = false;
      notifyListeners();
      return false;
    }
  }
  
  Future<void> signOut() async {
    await _authRepository.signOut();
    _currentUser = null;
    notifyListeners();
  }
}
```

### 登录页面

创建登录界面:

```dart
// lib/features/auth/presentation/pages/login_page.dart
class LoginPage extends StatefulWidget {
  @override
  _LoginPageState createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> {
  final _formKey = GlobalKey<FormState>();
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Consumer<AuthProvider>(
        builder: (context, authProvider, _) {
          return SafeArea(
            child: Padding(
              padding: const EdgeInsets.all(24.0),
              child: Form(
                key: _formKey,
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Text(
                      '欢迎回来',
                      style: Theme.of(context).textTheme.headlineMedium,
                      textAlign: TextAlign.center,
                    ),
                    const SizedBox(height: 32),
                    TextFormField(
                      controller: _emailController,
                      decoration: InputDecoration(
                        labelText: '邮箱',
                        prefixIcon: Icon(Icons.email),
                      ),
                      validator: (value) {
                        if (value == null || !value.contains('@')) {
                          return '请输入有效的邮箱地址';
                        }
                        return null;
                      },
                      keyboardType: TextInputType.emailAddress,
                    ),
                    const SizedBox(height: 16),
                    TextFormField(
                      controller: _passwordController,
                      decoration: InputDecoration(
                        labelText: '密码',
                        prefixIcon: Icon(Icons.lock),
                      ),
                      validator: (value) {
                        if (value == null || value.length < 6) {
                          return '密码至少需要6个字符';
                        }
                        return null;
                      },
                      obscureText: true,
                    ),
                    const SizedBox(height: 24),
                    if (authProvider.error != null)
                      Text(
                        authProvider.error!,
                        style: TextStyle(color: Colors.red),
                        textAlign: TextAlign.center,
                      ),
                    const SizedBox(height: 24),
                    ElevatedButton(
                      onPressed: authProvider.isLoading
                          ? null
                          : () async {
                              if (_formKey.currentState!.validate()) {
                                final success = await authProvider.signIn(
                                  _emailController.text.trim(),
                                  _passwordController.text,
                                );
                                
                                if (success) {
                                  Navigator.of(context).pushReplacementNamed('/home');
                                }
                              }
                            },
                      child: authProvider.isLoading
                          ? CircularProgressIndicator(color: Colors.white)
                          : Text('登录'),
                      style: ElevatedButton.styleFrom(
                        padding: EdgeInsets.symmetric(vertical: 12),
                      ),
                    ),
                    const SizedBox(height: 16),
                    TextButton(
                      onPressed: () => Navigator.pushNamed(context, '/register'),
                      child: Text('没有账号? 立即注册'),
                    ),
                  ],
                ),
              ),
            ),
          );
        },
      ),
    );
  }
  
  @override
  void dispose() {
    _emailController.dispose();
    _passwordController.dispose();
    super.dispose();
  }
}
```

### 注册页面

创建注册界面:

```dart
// lib/features/auth/presentation/pages/register_page.dart
class RegisterPage extends StatefulWidget {
  @override
  _RegisterPageState createState() => _RegisterPageState();
}

class _RegisterPageState extends State<RegisterPage> {
  final _formKey = GlobalKey<FormState>();
  final _usernameController = TextEditingController();
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  final _confirmPasswordController = TextEditingController();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('创建新账号'),
        backgroundColor: Colors.transparent,
        elevation: 0,
      ),
      body: Consumer<AuthProvider>(
        builder: (context, authProvider, _) {
          return SafeArea(
            child: Padding(
              padding: const EdgeInsets.all(24.0),
              child: Form(
                key: _formKey,
                child: SingleChildScrollView(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      TextFormField(
                        controller: _usernameController,
                        decoration: InputDecoration(
                          labelText: '用户名',
                          prefixIcon: Icon(Icons.person),
                        ),
                        validator: (value) {
                          if (value == null || value.length < 3) {
                            return '用户名至少需要3个字符';
                          }
                          return null;
                        },
                      ),
                      const SizedBox(height: 16),
                      TextFormField(
                        controller: _emailController,
                        decoration: InputDecoration(
                          labelText: '邮箱',
                          prefixIcon: Icon(Icons.email),
                        ),
                        validator: (value) {
                          if (value == null || !value.contains('@')) {
                            return '请输入有效的邮箱地址';
                          }
                          return null;
                        },
                        keyboardType: TextInputType.emailAddress,
                      ),
                      const SizedBox(height: 16),
                      TextFormField(
                        controller: _passwordController,
                        decoration: InputDecoration(
                          labelText: '密码',
                          prefixIcon: Icon(Icons.lock),
                        ),
                        validator: (value) {
                          if (value == null || value.length < 6) {
                            return '密码至少需要6个字符';
                          }
                          return null;
                        },
                        obscureText: true,
                      ),
                      const SizedBox(height: 16),
                      TextFormField(
                        controller: _confirmPasswordController,
                        decoration: InputDecoration(
                          labelText: '确认密码',
                          prefixIcon: Icon(Icons.lock_outline),
                        ),
                        validator: (value) {
                          if (value != _passwordController.text) {
                            return '两次输入的密码不匹配';
                          }
                          return null;
                        },
                        obscureText: true,
                      ),
                      const SizedBox(height: 24),
                      if (authProvider.error != null)
                        Text(
                          authProvider.error!,
                          style: TextStyle(color: Colors.red),
                          textAlign: TextAlign.center,
                        ),
                      const SizedBox(height: 24),
                      ElevatedButton(
                        onPressed: authProvider.isLoading
                            ? null
                            : () async {
                                if (_formKey.currentState!.validate()) {
                                  final success = await authProvider.signUp(
                                    _usernameController.text.trim(),
                                    _emailController.text.trim(),
                                    _passwordController.text,
                                  );
                                  
                                  if (success) {
                                    Navigator.of(context).pushReplacementNamed('/home');
                                  }
                                }
                              },
                        child: authProvider.isLoading
                            ? CircularProgressIndicator(color: Colors.white)
                            : Text('注册'),
                        style: ElevatedButton.styleFrom(
                          padding: EdgeInsets.symmetric(vertical: 12),
                        ),
                      ),
                      const SizedBox(height: 16),
                      TextButton(
                        onPressed: () => Navigator.pop(context),
                        child: Text('已有账号? 返回登录'),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          );
        },
      ),
    );
  }
  
  @override
  void dispose() {
    _usernameController.dispose();
    _emailController.dispose();
    _passwordController.dispose();
    _confirmPasswordController.dispose();
    super.dispose();
  }
}
```

## 社交Feed模块

### Feed数据模型

```dart
// lib/features/feed/data/models/post_model.dart
class PostModel {
  final String id;
  final String userId;
  final String username;
  final String? userAvatar;
  final String content;
  final List<String>? mediaUrls;
  final int likesCount;
  final int commentsCount;
  final DateTime createdAt;
  final bool isLiked;

  PostModel({
    required this.id,
    required this.userId,
    required this.username,
    this.userAvatar,
    required this.content,
    this.mediaUrls,
    required this.likesCount,
    required this.commentsCount,
    required this.createdAt,
    this.isLiked = false,
  });

  factory PostModel.fromJson(Map<String, dynamic> json) {
    return PostModel(
      id: json['id'],
      userId: json['user_id'],
      username: json['username'],
      userAvatar: json['user_avatar'],
      content: json['content'],
      mediaUrls: json['media_urls'] != null 
          ? List<String>.from(json['media_urls']) 
          : null,
      likesCount: json['likes_count'],
      commentsCount: json['comments_count'],
      createdAt: DateTime.parse(json['created_at']),
      isLiked: json['is_liked'] ?? false,
    );
  }
}

// lib/features/feed/data/models/comment_model.dart
class CommentModel {
  final String id;
  final String postId;
  final String userId;
  final String username;
  final String? userAvatar;
  final String content;
  final DateTime createdAt;

  CommentModel({
    required this.id,
    required this.postId,
    required this.userId,
    required this.username,
    this.userAvatar,
    required this.content,
    required this.createdAt,
  });

  factory CommentModel.fromJson(Map<String, dynamic> json) {
    return CommentModel(
      id: json['id'],
      postId: json['post_id'],
      userId: json['user_id'],
      username: json['username'],
      userAvatar: json['user_avatar'],
      content: json['content'],
      createdAt: DateTime.parse(json['created_at']),
    );
  }
}
```

### Feed仓库

```dart
// lib/features/feed/domain/repositories/feed_repository.dart
abstract class FeedRepository {
  Future<List<PostModel>> getFeedPosts({int page = 1, int limit = 10});
  Future<PostModel> createPost(String content, List<File>? media);
  Future<void> likePost(String postId);
  Future<void> unlikePost(String postId);
  Future<List<CommentModel>> getComments(String postId);
  Future<CommentModel> addComment(String postId, String content);
}

// lib/features/feed/data/repositories/feed_repository_impl.dart
class FeedRepositoryImpl implements FeedRepository {
  final HttpClient _httpClient;
  final AuthProvider _authProvider;

  FeedRepositoryImpl(this._httpClient, this._authProvider);

  @override
  Future<List<PostModel>> getFeedPosts({int page = 1, int limit = 10}) async {
    try {
      final response = await _httpClient.get(
        '/posts',
        queryParameters: {
          'page': page,
          'limit': limit,
        },
      );
      
      final List<dynamic> postsData = response.data['posts'];
      return postsData.map((json) => PostModel.fromJson(json)).toList();
    } catch (e) {
      throw FeedException('获取动态失败: $e');
    }
  }

  @override
  Future<PostModel> createPost(String content, List<File>? media) async {
    try {
      // 上传媒体文件
      List<String>? mediaUrls;
      if (media != null && media.isNotEmpty) {
        mediaUrls = await _uploadMedia(media);
      }
      
      // 创建帖子
      final response = await _httpClient.post(
        '/posts',
        data: {
          'content': content,
          'media_urls': mediaUrls,
        },
      );
      
      return PostModel.fromJson(response.data['post']);
    } catch (e) {
      throw FeedException('创建动态失败: $e');
    }
  }

  Future<List<String>> _uploadMedia(List<File> files) async {
    final mediaUrls = <String>[];
    
    for (final file in files) {
      final formData = FormData.fromMap({
        'file': await MultipartFile.fromFile(
          file.path,
          filename: path.basename(file.path),
        ),
      });
      
      final response = await _httpClient.post('/upload', data: formData);
      mediaUrls.add(response.data['url']);
    }
    
    return mediaUrls;
  }

  @override
  Future<void> likePost(String postId) async {
    try {
      await _httpClient.post('/posts/$postId/like');
    } catch (e) {
      throw FeedException('点赞失败: $e');
    }
  }

  @override
  Future<void> unlikePost(String postId) async {
    try {
      await _httpClient.delete('/posts/$postId/like');
    } catch (e) {
      throw FeedException('取消点赞失败: $e');
    }
  }

  @override
  Future<List<CommentModel>> getComments(String postId) async {
    try {
      final response = await _httpClient.get('/posts/$postId/comments');
      
      final List<dynamic> commentsData = response.data['comments'];
      return commentsData.map((json) => CommentModel.fromJson(json)).toList();
    } catch (e) {
      throw FeedException('获取评论失败: $e');
    }
  }

  @override
  Future<CommentModel> addComment(String postId, String content) async {
    try {
      final response = await _httpClient.post(
        '/posts/$postId/comments',
        data: {'content': content},
      );
      
      return CommentModel.fromJson(response.data['comment']);
    } catch (e) {
      throw FeedException('添加评论失败: $e');
    }
  }
}
```
