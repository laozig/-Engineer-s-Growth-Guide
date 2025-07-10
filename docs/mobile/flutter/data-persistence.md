# 数据持久化

在移动应用开发中，数据持久化是一个关键需求，它允许应用在重启后仍然保留用户数据和应用状态。Flutter提供了多种数据持久化解决方案，从简单的键值存储到复杂的关系型数据库。本文档将介绍Flutter中最常用的三种数据持久化方案：SharedPreferences、Hive和SQLite。

## SharedPreferences

SharedPreferences是一个轻量级的键值对存储系统，适用于存储少量的简单数据，如用户设置、登录状态等。

### 安装

在`pubspec.yaml`文件中添加依赖：

```yaml
dependencies:
  shared_preferences: ^2.2.0
```

### 基本用法

```dart
import 'package:shared_preferences/shared_preferences.dart';

// 存储数据
Future<void> saveData() async {
  // 获取SharedPreferences实例
  final prefs = await SharedPreferences.getInstance();
  
  // 存储各种类型的数据
  await prefs.setString('username', '张三');
  await prefs.setInt('age', 25);
  await prefs.setBool('isLoggedIn', true);
  await prefs.setDouble('height', 175.5);
  await prefs.setStringList('hobbies', ['读书', '游泳', '旅行']);
}

// 读取数据
Future<void> loadData() async {
  final prefs = await SharedPreferences.getInstance();
  
  // 读取数据，提供默认值防止空值
  final username = prefs.getString('username') ?? '游客';
  final age = prefs.getInt('age') ?? 0;
  final isLoggedIn = prefs.getBool('isLoggedIn') ?? false;
  final height = prefs.getDouble('height') ?? 0.0;
  final hobbies = prefs.getStringList('hobbies') ?? [];
  
  print('用户名: $username');
  print('年龄: $age');
  print('登录状态: $isLoggedIn');
  print('身高: $height');
  print('爱好: $hobbies');
}

// 删除数据
Future<void> removeData() async {
  final prefs = await SharedPreferences.getInstance();
  
  // 删除特定键
  await prefs.remove('username');
  
  // 检查键是否存在
  final hasUsername = prefs.containsKey('username');
  print('是否存在用户名: $hasUsername');
  
  // 清除所有数据
  await prefs.clear();
}
```

### 存储复杂对象

SharedPreferences只能直接存储基本类型（字符串、数字、布尔值、字符串列表），但可以通过JSON序列化来存储复杂对象：

```dart
import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';

// 定义用户类
class User {
  final String name;
  final int age;
  final String email;
  
  User({required this.name, required this.age, required this.email});
  
  // 从JSON创建用户对象
  factory User.fromJson(Map<String, dynamic> json) {
    return User(
      name: json['name'] as String,
      age: json['age'] as int,
      email: json['email'] as String,
    );
  }
  
  // 将用户对象转换为JSON
  Map<String, dynamic> toJson() {
    return {
      'name': name,
      'age': age,
      'email': email,
    };
  }
}

// 存储用户对象
Future<void> saveUser(User user) async {
  final prefs = await SharedPreferences.getInstance();
  
  // 将用户对象转换为JSON字符串
  final userJson = jsonEncode(user.toJson());
  
  // 存储JSON字符串
  await prefs.setString('user', userJson);
}

// 读取用户对象
Future<User?> loadUser() async {
  final prefs = await SharedPreferences.getInstance();
  
  // 读取JSON字符串
  final userJson = prefs.getString('user');
  
  if (userJson == null) {
    return null;
  }
  
  // 将JSON字符串转换回用户对象
  final userMap = jsonDecode(userJson) as Map<String, dynamic>;
  return User.fromJson(userMap);
}
```

### SharedPreferences的优缺点

**优点：**
- 简单易用，API直观
- 适合存储少量简单数据
- Flutter官方支持
- 跨平台一致性

**缺点：**
- 不适合存储大量数据
- 不支持复杂查询
- 性能有限
- 不适合频繁读写操作

## Hive

Hive是一个轻量级、高性能的键值对数据库，专为Flutter设计。它完全用Dart编写，不依赖任何原生平台代码，提供了比SharedPreferences更强大的功能和更好的性能。

### 安装

在`pubspec.yaml`文件中添加依赖：

```yaml
dependencies:
  hive: ^2.2.3
  hive_flutter: ^1.1.0

dev_dependencies:
  hive_generator: ^2.0.1
  build_runner: ^2.4.6
```

### 基本用法

```dart
import 'package:hive/hive.dart';
import 'package:hive_flutter/hive_flutter.dart';

// 初始化Hive
Future<void> initHive() async {
  // 初始化Hive并设置应用文档目录
  await Hive.initFlutter();
  
  // 打开一个Box
  await Hive.openBox('settings');
}

// 存储数据
void saveSettings() {
  final settingsBox = Hive.box('settings');
  
  // 存储各种类型的数据
  settingsBox.put('username', '张三');
  settingsBox.put('age', 25);
  settingsBox.put('isLoggedIn', true);
  settingsBox.put('height', 175.5);
  settingsBox.put('hobbies', ['读书', '游泳', '旅行']);
  
  // 存储多个键值对
  settingsBox.putAll({
    'darkMode': true,
    'fontSize': 16,
    'language': 'zh_CN',
  });
}

// 读取数据
void loadSettings() {
  final settingsBox = Hive.box('settings');
  
  // 读取数据，提供默认值防止空值
  final username = settingsBox.get('username', defaultValue: '游客');
  final age = settingsBox.get('age', defaultValue: 0);
  final isLoggedIn = settingsBox.get('isLoggedIn', defaultValue: false);
  
  print('用户名: $username');
  print('年龄: $age');
  print('登录状态: $isLoggedIn');
  
  // 检查键是否存在
  final hasDarkMode = settingsBox.containsKey('darkMode');
  print('是否存在暗黑模式设置: $hasDarkMode');
}

// 删除数据
void removeSettings() {
  final settingsBox = Hive.box('settings');
  
  // 删除特定键
  settingsBox.delete('username');
  
  // 删除多个键
  settingsBox.deleteAll(['age', 'height']);
  
  // 清空Box
  settingsBox.clear();
}
```

### 类型适配器和复杂对象

Hive可以通过类型适配器存储自定义对象：

```dart
import 'package:hive/hive.dart';

part 'user.g.dart'; // 将由build_runner生成

@HiveType(typeId: 0) // 每个类型必须有唯一的typeId
class User {
  @HiveField(0) // 每个字段必须有唯一的索引
  final String name;
  
  @HiveField(1)
  final int age;
  
  @HiveField(2)
  final String email;
  
  User({required this.name, required this.age, required this.email});
}

// 在main.dart中
Future<void> initHive() async {
  await Hive.initFlutter();
  
  // 注册适配器
  Hive.registerAdapter(UserAdapter()); // 由build_runner生成的适配器
  
  // 打开用户Box
  await Hive.openBox<User>('users');
}

// 存储用户对象
void saveUser() {
  final usersBox = Hive.box<User>('users');
  
  final user = User(
    name: '张三',
    age: 25,
    email: 'zhangsan@example.com',
  );
  
  // 存储对象
  usersBox.put('user1', user);
  
  // 添加对象（自动生成键）
  final userId = usersBox.add(user);
  print('用户ID: $userId');
}

// 读取用户对象
void loadUser() {
  final usersBox = Hive.box<User>('users');
  
  // 通过键读取
  final user = usersBox.get('user1');
  
  if (user != null) {
    print('用户名: ${user.name}');
    print('年龄: ${user.age}');
    print('邮箱: ${user.email}');
  }
  
  // 读取所有用户
  final allUsers = usersBox.values.toList();
  print('用户数量: ${allUsers.length}');
}
```

生成适配器代码：

```bash
flutter pub run build_runner build
```

### 懒加载Box

对于大型数据集，Hive提供了懒加载Box：

```dart
// 打开懒加载Box
final lazyBox = await Hive.openLazyBox('bigData');

// 存储数据
await lazyBox.put('key1', '大量数据...');

// 异步读取数据
final value = await lazyBox.get('key1');
```

### 数据加密

Hive支持数据加密：

```dart
import 'package:hive/hive.dart';
import 'package:crypto/crypto.dart';
import 'dart:convert';

Future<void> openEncryptedBox() async {
  // 创建加密密钥
  final key = Hive.generateSecureKey();
  
  // 或者使用自定义密钥
  final password = 'my_secure_password';
  final bytes = utf8.encode(password);
  final key2 = sha256.convert(bytes).bytes;
  
  // 打开加密Box
  final encryptedBox = await Hive.openBox(
    'encryptedData',
    encryptionCipher: HiveAesCipher(key),
  );
  
  // 存储加密数据
  encryptedBox.put('secret', '这是加密数据');
}
```

### Hive的优缺点

**优点：**
- 高性能，比SharedPreferences和SQLite更快
- 支持复杂对象存储
- 纯Dart实现，无原生依赖
- 支持数据加密
- API简洁易用

**缺点：**
- 不支持复杂查询和关系
- 类型适配器需要代码生成
- 不适合大规模结构化数据
- 缺乏某些高级数据库功能

## SQLite

SQLite是一个功能完整的关系型数据库，适用于需要结构化数据存储和复杂查询的应用。在Flutter中，通常使用`sqflite`包来操作SQLite数据库。

### 安装

在`pubspec.yaml`文件中添加依赖：

```yaml
dependencies:
  sqflite: ^2.3.0
  path: ^1.8.3
```

### 基本用法

```dart
import 'package:sqflite/sqflite.dart';
import 'package:path/path.dart';

// 数据库帮助类
class DatabaseHelper {
  static final DatabaseHelper _instance = DatabaseHelper._internal();
  static Database? _database;
  
  factory DatabaseHelper() {
    return _instance;
  }
  
  DatabaseHelper._internal();
  
  Future<Database> get database async {
    if (_database != null) return _database!;
    
    _database = await _initDatabase();
    return _database!;
  }
  
  Future<Database> _initDatabase() async {
    // 获取数据库路径
    final databasesPath = await getDatabasesPath();
    final path = join(databasesPath, 'my_database.db');
    
    // 打开数据库
    return await openDatabase(
      path,
      version: 1,
      onCreate: _createDatabase,
    );
  }
  
  Future<void> _createDatabase(Database db, int version) async {
    // 创建表
    await db.execute('''
      CREATE TABLE users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        age INTEGER,
        email TEXT
      )
    ''');
    
    await db.execute('''
      CREATE TABLE tasks(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        isDone INTEGER DEFAULT 0,
        userId INTEGER,
        FOREIGN KEY (userId) REFERENCES users (id)
      )
    ''');
  }
  
  // 关闭数据库
  Future<void> close() async {
    final db = await database;
    db.close();
  }
}
```

### CRUD操作

```dart
// 用户模型类
class User {
  final int? id;
  final String name;
  final int age;
  final String email;
  
  User({
    this.id,
    required this.name,
    required this.age,
    required this.email,
  });
  
  // 将用户对象转换为Map
  Map<String, dynamic> toMap() {
    return {
      'id': id,
      'name': name,
      'age': age,
      'email': email,
    };
  }
  
  // 从Map创建用户对象
  factory User.fromMap(Map<String, dynamic> map) {
    return User(
      id: map['id'] as int,
      name: map['name'] as String,
      age: map['age'] as int,
      email: map['email'] as String,
    );
  }
}

// 用户数据访问对象
class UserDao {
  final dbHelper = DatabaseHelper();
  
  // 插入用户
  Future<int> insertUser(User user) async {
    final db = await dbHelper.database;
    return await db.insert(
      'users',
      user.toMap(),
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }
  
  // 更新用户
  Future<int> updateUser(User user) async {
    final db = await dbHelper.database;
    return await db.update(
      'users',
      user.toMap(),
      where: 'id = ?',
      whereArgs: [user.id],
    );
  }
  
  // 删除用户
  Future<int> deleteUser(int id) async {
    final db = await dbHelper.database;
    return await db.delete(
      'users',
      where: 'id = ?',
      whereArgs: [id],
    );
  }
  
  // 获取所有用户
  Future<List<User>> getUsers() async {
    final db = await dbHelper.database;
    final List<Map<String, dynamic>> maps = await db.query('users');
    
    return List.generate(maps.length, (i) {
      return User.fromMap(maps[i]);
    });
  }
  
  // 根据ID获取用户
  Future<User?> getUserById(int id) async {
    final db = await dbHelper.database;
    final List<Map<String, dynamic>> maps = await db.query(
      'users',
      where: 'id = ?',
      whereArgs: [id],
    );
    
    if (maps.isEmpty) {
      return null;
    }
    
    return User.fromMap(maps.first);
  }
}
```

### 事务处理

```dart
Future<void> performTransaction() async {
  final db = await dbHelper.database;
  
  await db.transaction((txn) async {
    // 在事务中执行多个操作
    await txn.insert(
      'users',
      User(name: '李四', age: 30, email: 'lisi@example.com').toMap(),
    );
    
    await txn.update(
      'users',
      {'age': 26},
      where: 'name = ?',
      whereArgs: ['张三'],
    );
    
    await txn.delete(
      'users',
      where: 'age > ?',
      whereArgs: [40],
    );
  });
}
```

### 批量操作

```dart
Future<void> performBatchOperations() async {
  final db = await dbHelper.database;
  
  final batch = db.batch();
  
  // 添加多个操作到批处理
  batch.insert(
    'users',
    User(name: '王五', age: 35, email: 'wangwu@example.com').toMap(),
  );
  
  batch.insert(
    'users',
    User(name: '赵六', age: 28, email: 'zhaoliu@example.com').toMap(),
  );
  
  batch.update(
    'users',
    {'age': 29},
    where: 'name = ?',
    whereArgs: ['李四'],
  );
  
  // 执行批处理
  await batch.commit();
}
```

### 复杂查询

```dart
Future<void> performComplexQueries() async {
  final db = await dbHelper.database;
  
  // 使用WHERE子句
  final usersOver30 = await db.query(
    'users',
    where: 'age > ?',
    whereArgs: [30],
  );
  
  // 排序
  final usersByAgeDesc = await db.query(
    'users',
    orderBy: 'age DESC',
  );
  
  // 限制结果数量
  final top5Users = await db.query(
    'users',
    limit: 5,
  );
  
  // 分页查询
  final page2Users = await db.query(
    'users',
    limit: 10,
    offset: 10, // 跳过前10条记录
  );
  
  // 使用JOIN查询
  final usersWithTasks = await db.rawQuery('''
    SELECT users.*, tasks.title
    FROM users
    JOIN tasks ON users.id = tasks.userId
    WHERE tasks.isDone = 0
  ''');
  
  // 聚合查询
  final ageStats = await db.rawQuery('''
    SELECT 
      AVG(age) as average_age,
      MIN(age) as min_age,
      MAX(age) as max_age
    FROM users
  ''');
}
```

### 数据库迁移

```dart
Future<Database> _initDatabase() async {
  final databasesPath = await getDatabasesPath();
  final path = join(databasesPath, 'my_database.db');
  
  return await openDatabase(
    path,
    version: 2, // 增加版本号
    onCreate: _createDatabase,
    onUpgrade: _upgradeDatabase,
  );
}

Future<void> _upgradeDatabase(Database db, int oldVersion, int newVersion) async {
  if (oldVersion < 2) {
    // 版本1升级到版本2
    await db.execute('''
      ALTER TABLE users ADD COLUMN phone TEXT
    ''');
  }
  
  if (oldVersion < 3) {
    // 版本2升级到版本3
    await db.execute('''
      CREATE TABLE categories(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL
      )
    ''');
  }
}
```

### SQLite的优缺点

**优点：**
- 支持完整的SQL查询
- 适合复杂的结构化数据
- 支持事务和ACID属性
- 成熟稳定，广泛使用

**缺点：**
- 相比键值存储，API较为复杂
- 需要手动管理数据库架构
- 性能可能低于Hive等键值存储
- 需要更多的样板代码

## 选择合适的持久化方案

根据应用需求选择合适的持久化方案：

### SharedPreferences
- **适用场景**：存储简单的用户设置、标志和小量数据
- **数据量**：小（通常<1MB）
- **数据结构**：简单键值对
- **查询需求**：简单的键查找

### Hive
- **适用场景**：存储中等复杂度的数据，需要良好性能
- **数据量**：中等（可处理较大数据，但不适合GB级别）
- **数据结构**：支持复杂对象
- **查询需求**：基于键的查找，简单过滤

### SQLite
- **适用场景**：存储复杂的结构化数据，需要关系和复杂查询
- **数据量**：大（可处理GB级别数据）
- **数据结构**：表格、关系和约束
- **查询需求**：复杂查询、排序、过滤和连接

## 最佳实践

### 数据层抽象

创建抽象数据层，隔离存储实现细节：

```dart
// 数据源接口
abstract class UserDataSource {
  Future<User?> getUser(String userId);
  Future<List<User>> getAllUsers();
  Future<void> saveUser(User user);
  Future<void> deleteUser(String userId);
}

// SharedPreferences实现
class SharedPrefsUserDataSource implements UserDataSource {
  @override
  Future<User?> getUser(String userId) async {
    final prefs = await SharedPreferences.getInstance();
    final userJson = prefs.getString('user_$userId');
    if (userJson == null) return null;
    return User.fromJson(jsonDecode(userJson));
  }
  
  @override
  Future<List<User>> getAllUsers() async {
    // 实现获取所有用户的逻辑
    // ...
  }
  
  @override
  Future<void> saveUser(User user) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('user_${user.id}', jsonEncode(user.toJson()));
  }
  
  @override
  Future<void> deleteUser(String userId) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('user_$userId');
  }
}

// Hive实现
class HiveUserDataSource implements UserDataSource {
  @override
  Future<User?> getUser(String userId) async {
    final box = await Hive.openBox<User>('users');
    return box.get(userId);
  }
  
  @override
  Future<List<User>> getAllUsers() async {
    final box = await Hive.openBox<User>('users');
    return box.values.toList();
  }
  
  @override
  Future<void> saveUser(User user) async {
    final box = await Hive.openBox<User>('users');
    await box.put(user.id, user);
  }
  
  @override
  Future<void> deleteUser(String userId) async {
    final box = await Hive.openBox<User>('users');
    await box.delete(userId);
  }
}

// SQLite实现
class SqliteUserDataSource implements UserDataSource {
  final DatabaseHelper _dbHelper = DatabaseHelper();
  
  @override
  Future<User?> getUser(String userId) async {
    final db = await _dbHelper.database;
    final maps = await db.query(
      'users',
      where: 'id = ?',
      whereArgs: [userId],
    );
    
    if (maps.isEmpty) return null;
    return User.fromMap(maps.first);
  }
  
  @override
  Future<List<User>> getAllUsers() async {
    final db = await _dbHelper.database;
    final maps = await db.query('users');
    
    return maps.map((map) => User.fromMap(map)).toList();
  }
  
  @override
  Future<void> saveUser(User user) async {
    final db = await _dbHelper.database;
    await db.insert(
      'users',
      user.toMap(),
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }
  
  @override
  Future<void> deleteUser(String userId) async {
    final db = await _dbHelper.database;
    await db.delete(
      'users',
      where: 'id = ?',
      whereArgs: [userId],
    );
  }
}
```

### 仓库模式

使用仓库模式进一步抽象数据访问：

```dart
class UserRepository {
  final UserDataSource _dataSource;
  
  UserRepository(this._dataSource);
  
  Future<User?> getUser(String userId) => _dataSource.getUser(userId);
  
  Future<List<User>> getAllUsers() => _dataSource.getAllUsers();
  
  Future<void> saveUser(User user) => _dataSource.saveUser(user);
  
  Future<void> deleteUser(String userId) => _dataSource.deleteUser(userId);
}

// 在应用中使用
final userRepository = UserRepository(SqliteUserDataSource());
// 或
final userRepository = UserRepository(HiveUserDataSource());
```

### 数据缓存策略

实现多级缓存策略：

```dart
class CachedUserRepository implements UserRepository {
  final UserRepository _remoteRepository;
  final UserRepository _localRepository;
  final Map<String, User> _memoryCache = {};
  
  CachedUserRepository(this._remoteRepository, this._localRepository);
  
  @override
  Future<User?> getUser(String userId) async {
    // 1. 检查内存缓存
    if (_memoryCache.containsKey(userId)) {
      return _memoryCache[userId];
    }
    
    // 2. 检查本地存储
    final localUser = await _localRepository.getUser(userId);
    if (localUser != null) {
      _memoryCache[userId] = localUser;
      return localUser;
    }
    
    // 3. 从远程获取
    final remoteUser = await _remoteRepository.getUser(userId);
    if (remoteUser != null) {
      // 更新本地存储和内存缓存
      await _localRepository.saveUser(remoteUser);
      _memoryCache[userId] = remoteUser;
    }
    
    return remoteUser;
  }
  
  // 实现其他方法...
}
```

## 总结

Flutter提供了多种数据持久化解决方案，每种方案都有其特定的用例和优势：

- **SharedPreferences**：适用于简单的键值对存储，如用户设置和标志。
- **Hive**：适用于需要高性能的中等复杂度数据存储，支持复杂对象。
- **SQLite**：适用于复杂的结构化数据，需要关系和高级查询功能。

在选择持久化方案时，应考虑数据复杂性、查询需求、性能要求和数据量。对于大多数应用，可能需要结合使用多种持久化方案来满足不同的需求。

## 下一步

- 了解[网络与API通信](networking.md)
- 探索[状态管理](state-management.md)
- 学习[应用架构](architecture.md)
