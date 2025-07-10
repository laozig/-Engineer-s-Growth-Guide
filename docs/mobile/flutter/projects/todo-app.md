# Flutter Todo应用实战

本教程将指导您创建一个完整的Flutter Todo应用，包含添加、编辑、完成和删除任务等功能。这个实战项目将帮助您理解Flutter的核心概念和最佳实践。

## 项目概述

我们将构建的Todo应用具有以下功能：

- 显示任务列表
- 添加新任务
- 标记任务为已完成
- 编辑现有任务
- 删除任务
- 任务持久化存储
- 主题切换(亮色/暗色)

## 技术栈

- Flutter 3.0+
- Dart 2.17+
- Provider(状态管理)
- Hive(本地存储)
- Flutter Material Design组件

## 项目结构

```
todo_app/
├── lib/
│   ├── main.dart                 # 应用入口点
│   ├── app.dart                  # 应用根组件
│   ├── models/
│   │   └── task.dart             # Task模型类
│   ├── providers/
│   │   ├── task_provider.dart    # 任务状态管理
│   │   └── theme_provider.dart   # 主题状态管理
│   ├── screens/
│   │   ├── home_screen.dart      # 主屏幕
│   │   ├── task_screen.dart      # 任务详情/编辑屏幕
│   │   └── settings_screen.dart  # 设置屏幕
│   ├── services/
│   │   └── storage_service.dart  # 本地存储服务
│   ├── widgets/
│   │   ├── task_list.dart        # 任务列表组件
│   │   ├── task_tile.dart        # 单个任务组件
│   │   └── add_task_modal.dart   # 添加任务底部模态框
│   └── utils/
│       └── constants.dart        # 常量和工具类
└── test/
    └── task_provider_test.dart   # 单元测试
```

## 第1步：项目初始化

首先，创建一个新的Flutter项目：

```bash
flutter create todo_app
cd todo_app
```

在`pubspec.yaml`文件中添加依赖：

```yaml
dependencies:
  flutter:
    sdk: flutter
  provider: ^6.0.5       # 状态管理
  hive: ^2.2.3           # 本地数据库
  hive_flutter: ^1.1.0   # Hive的Flutter绑定
  path_provider: ^2.0.15 # 路径提供程序
  intl: ^0.18.1          # 日期格式化
  uuid: ^3.0.7           # 生成唯一ID

dev_dependencies:
  flutter_test:
    sdk: flutter
  hive_generator: ^2.0.0 # Hive代码生成
  build_runner: ^2.3.3   # 代码生成工具
```

然后运行以下命令安装依赖：

```bash
flutter pub get
```

## 第2步：创建数据模型

首先，我们需要创建任务模型。创建文件`lib/models/task.dart`：

```dart
import 'package:hive/hive.dart';
import 'package:uuid/uuid.dart';

part 'task.g.dart';

@HiveType(typeId: 0)
class Task {
  @HiveField(0)
  final String id;

  @HiveField(1)
  String title;

  @HiveField(2)
  String? description;

  @HiveField(3)
  bool isCompleted;

  @HiveField(4)
  DateTime createdAt;

  @HiveField(5)
  DateTime? updatedAt;

  Task({
    String? id,
    required this.title,
    this.description,
    this.isCompleted = false,
    DateTime? createdAt,
  })  : id = id ?? const Uuid().v4(),
        createdAt = createdAt ?? DateTime.now();

  void toggleCompleted() {
    isCompleted = !isCompleted;
    updatedAt = DateTime.now();
  }

  void updateTask({
    required String title,
    String? description,
  }) {
    this.title = title;
    this.description = description;
    updatedAt = DateTime.now();
  }
}
```

生成Hive适配器代码：

```bash
flutter pub run build_runner build
```

## 第3步：设置本地存储

创建`lib/services/storage_service.dart`文件来处理Hive的初始化和数据持久化：

```dart
import 'package:flutter/foundation.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'package:path_provider/path_provider.dart';
import '../models/task.dart';

class StorageService {
  static const String _tasksBoxName = 'tasks';
  static const String _settingsBoxName = 'settings';

  static Future<void> init() async {
    final appDocumentDirectory = await getApplicationDocumentsDirectory();
    await Hive.initFlutter(appDocumentDirectory.path);
    
    Hive.registerAdapter(TaskAdapter());
    
    await Hive.openBox<Task>(_tasksBoxName);
    await Hive.openBox<dynamic>(_settingsBoxName);
  }

  // 任务相关方法
  static Box<Task> get tasksBox => Hive.box<Task>(_tasksBoxName);

  static List<Task> getAllTasks() {
    return tasksBox.values.toList();
  }

  static Future<void> saveTask(Task task) async {
    await tasksBox.put(task.id, task);
  }

  static Future<void> deleteTask(String id) async {
    await tasksBox.delete(id);
  }

  // 设置相关方法
  static Box get settingsBox => Hive.box(_settingsBoxName);

  static bool get isDarkMode {
    return settingsBox.get('darkMode', defaultValue: false);
  }

  static Future<void> setDarkMode(bool value) async {
    await settingsBox.put('darkMode', value);
  }
}
```

## 第4步：创建状态管理提供者

创建任务状态管理提供者`lib/providers/task_provider.dart`：

```dart
import 'package:flutter/foundation.dart';
import '../models/task.dart';
import '../services/storage_service.dart';

class TaskProvider with ChangeNotifier {
  List<Task> _tasks = [];

  List<Task> get tasks => _tasks;
  List<Task> get completedTasks => _tasks.where((task) => task.isCompleted).toList();
  List<Task> get pendingTasks => _tasks.where((task) => !task.isCompleted).toList();

  TaskProvider() {
    _loadTasks();
  }

  Future<void> _loadTasks() async {
    _tasks = StorageService.getAllTasks();
    notifyListeners();
  }

  Future<void> addTask(Task task) async {
    await StorageService.saveTask(task);
    _tasks.add(task);
    notifyListeners();
  }

  Future<void> updateTask(Task task) async {
    await StorageService.saveTask(task);
    final index = _tasks.indexWhere((t) => t.id == task.id);
    if (index != -1) {
      _tasks[index] = task;
      notifyListeners();
    }
  }

  Future<void> toggleTaskCompleted(String id) async {
    final index = _tasks.indexWhere((task) => task.id == id);
    if (index != -1) {
      _tasks[index].toggleCompleted();
      await StorageService.saveTask(_tasks[index]);
      notifyListeners();
    }
  }

  Future<void> deleteTask(String id) async {
    await StorageService.deleteTask(id);
    _tasks.removeWhere((task) => task.id == id);
    notifyListeners();
  }

  Task? getTaskById(String id) {
    try {
      return _tasks.firstWhere((task) => task.id == id);
    } catch (e) {
      return null;
    }
  }
}
```

创建主题状态管理提供者`lib/providers/theme_provider.dart`：

```dart
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import '../services/storage_service.dart';

class ThemeProvider with ChangeNotifier {
  bool _isDarkMode = false;

  bool get isDarkMode => _isDarkMode;

  ThemeMode get themeMode => _isDarkMode ? ThemeMode.dark : ThemeMode.light;

  ThemeProvider() {
    _loadThemeMode();
  }

  Future<void> _loadThemeMode() async {
    _isDarkMode = StorageService.isDarkMode;
    notifyListeners();
  }

  Future<void> toggleTheme() async {
    _isDarkMode = !_isDarkMode;
    await StorageService.setDarkMode(_isDarkMode);
    notifyListeners();
  }
}
```

## 第5步：创建UI组件

首先，创建应用程序根组件`lib/app.dart`：

```dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'providers/theme_provider.dart';
import 'screens/home_screen.dart';

class TodoApp extends StatelessWidget {
  const TodoApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Consumer<ThemeProvider>(
      builder: (context, themeProvider, _) {
        return MaterialApp(
          title: 'Flutter Todo App',
          debugShowCheckedModeBanner: false,
          themeMode: themeProvider.themeMode,
          theme: ThemeData(
            primarySwatch: Colors.blue,
            brightness: Brightness.light,
            useMaterial3: true,
          ),
          darkTheme: ThemeData(
            primarySwatch: Colors.blue,
            brightness: Brightness.dark,
            useMaterial3: true,
          ),
          home: const HomeScreen(),
        );
      },
    );
  }
}
```

创建主屏幕`lib/screens/home_screen.dart`：

```dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../providers/task_provider.dart';
import '../providers/theme_provider.dart';
import '../widgets/task_list.dart';
import '../widgets/add_task_modal.dart';
import 'settings_screen.dart';

class HomeScreen extends StatelessWidget {
  const HomeScreen({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return DefaultTabController(
      length: 3,
      child: Scaffold(
        appBar: AppBar(
          title: const Text('Todo App'),
          actions: [
            IconButton(
              icon: const Icon(Icons.settings),
              onPressed: () {
                Navigator.push(
                  context, 
                  MaterialPageRoute(builder: (_) => const SettingsScreen()),
                );
              },
            ),
            IconButton(
              icon: Icon(
                Provider.of<ThemeProvider>(context).isDarkMode
                    ? Icons.light_mode
                    : Icons.dark_mode,
              ),
              onPressed: () {
                Provider.of<ThemeProvider>(context, listen: false).toggleTheme();
              },
            ),
          ],
          bottom: const TabBar(
            tabs: [
              Tab(text: 'All'),
              Tab(text: 'Pending'),
              Tab(text: 'Completed'),
            ],
          ),
        ),
        body: Consumer<TaskProvider>(
          builder: (context, taskProvider, _) {
            return TabBarView(
              children: [
                TaskList(tasks: taskProvider.tasks),
                TaskList(tasks: taskProvider.pendingTasks),
                TaskList(tasks: taskProvider.completedTasks),
              ],
            );
          },
        ),
        floatingActionButton: FloatingActionButton(
          child: const Icon(Icons.add),
          onPressed: () {
            showModalBottomSheet(
              context: context,
              isScrollControlled: true,
              builder: (_) => const AddTaskModal(),
            );
          },
        ),
      ),
    );
  }
}
```

创建任务列表组件`lib/widgets/task_list.dart`：

```dart
import 'package:flutter/material.dart';
import '../models/task.dart';
import 'task_tile.dart';

class TaskList extends StatelessWidget {
  final List<Task> tasks;

  const TaskList({Key? key, required this.tasks}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    if (tasks.isEmpty) {
      return const Center(
        child: Text('No tasks found'),
      );
    }

    return ListView.builder(
      itemCount: tasks.length,
      padding: const EdgeInsets.all(16.0),
      itemBuilder: (context, index) {
        return TaskTile(task: tasks[index]);
      },
    );
  }
}
```

创建任务项组件`lib/widgets/task_tile.dart`：

```dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:intl/intl.dart';
import '../models/task.dart';
import '../providers/task_provider.dart';
import '../screens/task_screen.dart';

class TaskTile extends StatelessWidget {
  final Task task;
  
  const TaskTile({Key? key, required this.task}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.only(bottom: 16.0),
      elevation: 2.0,
      child: ListTile(
        contentPadding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
        title: Text(
          task.title,
          style: TextStyle(
            decoration: task.isCompleted ? TextDecoration.lineThrough : null,
            fontWeight: FontWeight.bold,
          ),
        ),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (task.description != null && task.description!.isNotEmpty)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 4.0),
                child: Text(task.description!),
              ),
            Text(
              'Created: ${DateFormat.yMMMd().format(task.createdAt)}',
              style: const TextStyle(fontSize: 12.0),
            ),
            if (task.updatedAt != null)
              Text(
                'Updated: ${DateFormat.yMMMd().format(task.updatedAt!)}',
                style: const TextStyle(fontSize: 12.0),
              ),
          ],
        ),
        leading: Checkbox(
          value: task.isCompleted,
          onChanged: (_) {
            Provider.of<TaskProvider>(context, listen: false)
                .toggleTaskCompleted(task.id);
          },
        ),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            IconButton(
              icon: const Icon(Icons.edit),
              onPressed: () {
                Navigator.push(
                  context,
                  MaterialPageRoute(
                    builder: (_) => TaskScreen(taskId: task.id),
                  ),
                );
              },
            ),
            IconButton(
              icon: const Icon(Icons.delete),
              onPressed: () {
                showDialog(
                  context: context,
                  builder: (_) => AlertDialog(
                    title: const Text('Delete Task'),
                    content: const Text('Are you sure you want to delete this task?'),
                    actions: [
                      TextButton(
                        onPressed: () => Navigator.pop(context),
                        child: const Text('Cancel'),
                      ),
                      TextButton(
                        onPressed: () {
                          Provider.of<TaskProvider>(context, listen: false)
                              .deleteTask(task.id);
                          Navigator.pop(context);
                        },
                        child: const Text('Delete'),
                      ),
                    ],
                  ),
                );
              },
            ),
          ],
        ),
        isThreeLine: true,
      ),
    );
  }
}
```

创建添加任务模态框`lib/widgets/add_task_modal.dart`：

```dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../models/task.dart';
import '../providers/task_provider.dart';

class AddTaskModal extends StatefulWidget {
  const AddTaskModal({Key? key}) : super(key: key);

  @override
  _AddTaskModalState createState() => _AddTaskModalState();
}

class _AddTaskModalState extends State<AddTaskModal> {
  final _formKey = GlobalKey<FormState>();
  late TextEditingController _titleController;
  late TextEditingController _descriptionController;

  @override
  void initState() {
    super.initState();
    _titleController = TextEditingController();
    _descriptionController = TextEditingController();
  }

  @override
  void dispose() {
    _titleController.dispose();
    _descriptionController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: EdgeInsets.only(
        bottom: MediaQuery.of(context).viewInsets.bottom,
        left: 16.0,
        right: 16.0,
        top: 16.0,
      ),
      child: Form(
        key: _formKey,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              'Add New Task',
              style: Theme.of(context).textTheme.headline6,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 16.0),
            TextFormField(
              controller: _titleController,
              decoration: const InputDecoration(
                labelText: 'Title',
                border: OutlineInputBorder(),
              ),
              validator: (value) {
                if (value == null || value.trim().isEmpty) {
                  return 'Please enter a title';
                }
                return null;
              },
            ),
            const SizedBox(height: 16.0),
            TextFormField(
              controller: _descriptionController,
              decoration: const InputDecoration(
                labelText: 'Description (optional)',
                border: OutlineInputBorder(),
              ),
              maxLines: 3,
            ),
            const SizedBox(height: 16.0),
            ElevatedButton(
              onPressed: _saveTask,
              child: const Text('Save'),
            ),
            const SizedBox(height: 16.0),
          ],
        ),
      ),
    );
  }

  void _saveTask() {
    if (_formKey.currentState!.validate()) {
      final task = Task(
        title: _titleController.text.trim(),
        description: _descriptionController.text.trim().isEmpty
            ? null
            : _descriptionController.text.trim(),
      );

      Provider.of<TaskProvider>(context, listen: false).addTask(task);
      Navigator.pop(context);
    }
  }
}
```

创建任务详情/编辑屏幕`lib/screens/task_screen.dart`：

```dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../models/task.dart';
import '../providers/task_provider.dart';

class TaskScreen extends StatefulWidget {
  final String taskId;
  
  const TaskScreen({Key? key, required this.taskId}) : super(key: key);
  
  @override
  _TaskScreenState createState() => _TaskScreenState();
}

class _TaskScreenState extends State<TaskScreen> {
  final _formKey = GlobalKey<FormState>();
  late TextEditingController _titleController;
  late TextEditingController _descriptionController;
  Task? _task;
  
  @override
  void initState() {
    super.initState();
    _titleController = TextEditingController();
    _descriptionController = TextEditingController();
    
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _loadTask();
    });
  }
  
  @override
  void dispose() {
    _titleController.dispose();
    _descriptionController.dispose();
    super.dispose();
  }
  
  void _loadTask() {
    final taskProvider = Provider.of<TaskProvider>(context, listen: false);
    _task = taskProvider.getTaskById(widget.taskId);
    
    if (_task != null) {
      _titleController.text = _task!.title;
      _descriptionController.text = _task!.description ?? '';
    }
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Task Details'),
      ),
      body: _task == null 
          ? const Center(child: CircularProgressIndicator())
          : Padding(
              padding: const EdgeInsets.all(16.0),
              child: Form(
                key: _formKey,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    TextFormField(
                      controller: _titleController,
                      decoration: const InputDecoration(
                        labelText: 'Title',
                        border: OutlineInputBorder(),
                      ),
                      validator: (value) {
                        if (value == null || value.trim().isEmpty) {
                          return 'Please enter a title';
                        }
                        return null;
                      },
                    ),
                    const SizedBox(height: 16.0),
                    TextFormField(
                      controller: _descriptionController,
                      decoration: const InputDecoration(
                        labelText: 'Description',
                        border: OutlineInputBorder(),
                      ),
                      maxLines: 5,
                    ),
                    const SizedBox(height: 16.0),
                    Row(
                      children: [
                        const Text('Completed: '),
                        Switch(
                          value: _task!.isCompleted,
                          onChanged: (value) {
                            setState(() {
                              _task!.toggleCompleted();
                            });
                          },
                        ),
                      ],
                    ),
                    const Spacer(),
                    ElevatedButton(
                      onPressed: _saveTask,
                      child: const Text('Save Changes'),
                    ),
                  ],
                ),
              ),
            ),
    );
  }
  
  void _saveTask() {
    if (_formKey.currentState!.validate() && _task != null) {
      _task!.updateTask(
        title: _titleController.text.trim(),
        description: _descriptionController.text.trim().isEmpty
            ? null
            : _descriptionController.text.trim(),
      );
      
      Provider.of<TaskProvider>(context, listen: false).updateTask(_task!);
      Navigator.pop(context);
    }
  }
}
```

创建设置屏幕`lib/screens/settings_screen.dart`：

```dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../providers/theme_provider.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings'),
      ),
      body: ListView(
        children: [
          Consumer<ThemeProvider>(
            builder: (context, themeProvider, _) {
              return SwitchListTile(
                title: const Text('Dark Mode'),
                subtitle: const Text('Toggle between light and dark theme'),
                value: themeProvider.isDarkMode,
                onChanged: (_) => themeProvider.toggleTheme(),
              );
            },
          ),
          const Divider(),
          const ListTile(
            title: Text('About'),
            subtitle: Text('Flutter Todo App v1.0.0'),
          ),
        ],
      ),
    );
  }
}
```

## 第6步：创建应用入口

最后，修改`lib/main.dart`文件：

```dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'app.dart';
import 'providers/task_provider.dart';
import 'providers/theme_provider.dart';
import 'services/storage_service.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  // 初始化本地存储
  await StorageService.init();
  
  runApp(
    MultiProvider(
      providers: [
        ChangeNotifierProvider(create: (_) => ThemeProvider()),
        ChangeNotifierProvider(create: (_) => TaskProvider()),
      ],
      child: const TodoApp(),
    ),
  );
}
```

## 第7步：运行应用

运行应用程序：

```bash
flutter run
```

## 项目扩展建议

完成基本的Todo应用后，可以考虑以下扩展功能：

1. **任务分类/标签**：添加标签系统，对任务进行分类
2. **优先级**：为任务添加优先级(低、中、高)
3. **截止日期**：添加任务截止日期和提醒功能
4. **搜索功能**：实现任务搜索功能
5. **任务排序**：根据不同条件(截止日期、优先级等)对任务进行排序
6. **导入/导出**：支持将任务导入/导出为文件
7. **用户认证**：添加用户登录功能，支持在云端同步任务
8. **统计图表**：添加任务完成情况的统计和图表
9. **小部件支持**：添加主屏幕小部件，显示待办任务
10. **多主题支持**：添加更多颜色主题选项

## 单元测试

创建文件`test/task_provider_test.dart`：

```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import '../lib/models/task.dart';
import '../lib/providers/task_provider.dart';

// 简单的测试示例
void main() {
  group('TaskProvider Tests', () {
    late TaskProvider taskProvider;
    
    setUp(() {
      taskProvider = TaskProvider();
    });
    
    test('Initial tasks list should be empty', () {
      expect(taskProvider.tasks, isEmpty);
    });
    
    test('Add task should work correctly', () async {
      final task = Task(title: 'Test Task');
      await taskProvider.addTask(task);
      
      expect(taskProvider.tasks.length, 1);
      expect(taskProvider.tasks.first.title, 'Test Task');
    });
    
    test('Toggle task completed should work', () async {
      final task = Task(title: 'Test Task');
      await taskProvider.addTask(task);
      
      await taskProvider.toggleTaskCompleted(task.id);
      expect(taskProvider.tasks.first.isCompleted, true);
      
      await taskProvider.toggleTaskCompleted(task.id);
      expect(taskProvider.tasks.first.isCompleted, false);
    });
    
    test('Delete task should work', () async {
      final task = Task(title: 'Test Task');
      await taskProvider.addTask(task);
      
      await taskProvider.deleteTask(task.id);
      expect(taskProvider.tasks, isEmpty);
    });
  });
}
```

## 总结

在本项目中，我们构建了一个功能齐全的Flutter Todo应用，包括以下技术点：

1. **状态管理**：使用Provider进行状态管理
2. **本地存储**：使用Hive进行数据持久化
3. **UI设计**：实现Material Design用户界面
4. **主题切换**：支持亮色和暗色主题
5. **代码组织**：采用合理的文件结构和代码组织方式
6. **测试**：编写单元测试

这个项目可以作为您进一步学习Flutter的基础，您可以在此基础上添加更多功能，或者将其作为参考构建自己的应用程序。 