# Flutter 架构模式 - MVC、MVVM、Clean Architecture

在Flutter应用开发中，选择合适的架构模式对于代码的可维护性、可测试性和可扩展性至关重要。本文将深入探讨三种主流的架构模式：MVC、MVVM和Clean Architecture，并通过实例演示如何在Flutter项目中实现这些架构。

## 目录

- [架构模式的重要性](#架构模式的重要性)
- [MVC模式](#mvc模式)
- [MVVM模式](#mvvm模式)
- [Clean Architecture](#clean-architecture)
- [架构选择指南](#架构选择指南)
- [最佳实践](#最佳实践)
- [测试策略](#测试策略)
- [混合架构模式](#混合架构模式)
- [实际案例分析](#实际案例分析)

## 架构模式的重要性

为什么架构模式如此重要？合适的架构模式能带来以下好处：

1. **关注点分离**：将UI、业务逻辑和数据层清晰分开
2. **代码复用**：通过合理抽象实现逻辑复用
3. **可测试性**：便于单元测试和集成测试
4. **团队协作**：明确的架构让团队成员更容易协作
5. **维护性**：随着应用复杂度增加，便于维护和重构
6. **可扩展性**：便于添加新功能和适应需求变更

## MVC模式

### MVC基本概念

MVC（Model-View-Controller）是最经典的架构模式之一，将应用分为三个核心组件：

1. **Model（模型）**：负责数据和业务逻辑
2. **View（视图）**：负责UI展示
3. **Controller（控制器）**：连接Model和View，处理用户输入并更新Model

在Flutter中，MVC的实现通常会有一些调整以适应Flutter的组件模型。

### Flutter中的MVC实现

下面是一个简单的待办事项应用的MVC实现示例：

#### Model

```dart
// todo_model.dart
class Todo {
  final int id;
  final String title;
  bool completed;

  Todo({
    required this.id,
    required this.title,
    this.completed = false,
  });

  Todo copyWith({
    int? id,
    String? title,
    bool? completed,
  }) {
    return Todo(
      id: id ?? this.id,
      title: title ?? this.title,
      completed: completed ?? this.completed,
    );
  }
}

class TodoModel {
  List<Todo> _todos = [];

  // 获取所有待办事项
  List<Todo> get todos => List.unmodifiable(_todos);

  // 添加待办事项
  void addTodo(String title) {
    final id = _todos.isEmpty ? 1 : _todos.last.id + 1;
    _todos.add(Todo(id: id, title: title));
  }

  // 切换待办事项状态
  void toggleTodo(int id) {
    final index = _todos.indexWhere((todo) => todo.id == id);
    if (index >= 0) {
      final todo = _todos[index];
      _todos[index] = todo.copyWith(completed: !todo.completed);
    }
  }

  // 删除待办事项
  void deleteTodo(int id) {
    _todos.removeWhere((todo) => todo.id == id);
  }
}
```

#### Controller

```dart
// todo_controller.dart
import 'package:flutter/material.dart';
import 'todo_model.dart';

class TodoController {
  final TodoModel model;
  final Function(TodoModel) onUpdate;

  TodoController({
    required this.model,
    required this.onUpdate,
  });

  void addTodo(String title) {
    if (title.trim().isNotEmpty) {
      model.addTodo(title);
      onUpdate(model);
    }
  }

  void toggleTodo(int id) {
    model.toggleTodo(id);
    onUpdate(model);
  }

  void deleteTodo(int id) {
    model.deleteTodo(id);
    onUpdate(model);
  }
}
```

#### View

```dart
// todo_view.dart
import 'package:flutter/material.dart';
import 'todo_model.dart';
import 'todo_controller.dart';

class TodoView extends StatefulWidget {
  @override
  _TodoViewState createState() => _TodoViewState();
}

class _TodoViewState extends State<TodoView> {
  final TodoModel _model = TodoModel();
  late TodoController _controller;
  final TextEditingController _textController = TextEditingController();

  @override
  void initState() {
    super.initState();
    _controller = TodoController(
      model: _model,
      onUpdate: (model) {
        setState(() {});
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('MVC待办事项'),
      ),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.all(8.0),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _textController,
                    decoration: InputDecoration(
                      hintText: '添加新待办事项',
                      border: OutlineInputBorder(),
                    ),
                  ),
                ),
                SizedBox(width: 8),
                ElevatedButton(
                  onPressed: () {
                    _controller.addTodo(_textController.text);
                    _textController.clear();
                  },
                  child: Text('添加'),
                ),
              ],
            ),
          ),
          Expanded(
            child: ListView.builder(
              itemCount: _model.todos.length,
              itemBuilder: (context, index) {
                final todo = _model.todos[index];
                return ListTile(
                  title: Text(
                    todo.title,
                    style: TextStyle(
                      decoration: todo.completed
                          ? TextDecoration.lineThrough
                          : TextDecoration.none,
                    ),
                  ),
                  leading: Checkbox(
                    value: todo.completed,
                    onChanged: (_) {
                      _controller.toggleTodo(todo.id);
                    },
                  ),
                  trailing: IconButton(
                    icon: Icon(Icons.delete),
                    onPressed: () {
                      _controller.deleteTodo(todo.id);
                    },
                  ),
                );
              },
            ),
          ),
        ],
      ),
    );
  }

  @override
  void dispose() {
    _textController.dispose();
    super.dispose();
  }
}
```

#### 主应用

```dart
// main.dart
import 'package:flutter/material.dart';
import 'todo_view.dart';

void main() {
  runApp(MyApp());
}

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter MVC Demo',
      theme: ThemeData(
        primarySwatch: Colors.blue,
      ),
      home: TodoView(),
    );
  }
}
```

### MVC的优缺点

**优点：**
- 简单易懂，容易上手
- 对于小型应用非常适合
- 明确的责任分离

**缺点：**
- 随着应用复杂度增加，Controller可能变得臃肿
- View和Controller的耦合度较高
- 在Flutter中，View和Controller的边界有时不够清晰

### MVC改进方案

针对MVC的缺点，我们可以通过以下方式改进：

1. **使用回调函数减少耦合**：通过回调函数而非直接引用减少组件间的耦合

```dart
// 改进后的Controller
class TodoController {
  final TodoModel model;
  
  TodoController({required this.model});
  
  void addTodo(String title) {
    if (title.trim().isNotEmpty) {
      model.addTodo(title);
    }
  }
  
  // 其他方法...
}

// 改进后的Model
class TodoModel extends ChangeNotifier {
  List<Todo> _todos = [];
  
  List<Todo> get todos => List.unmodifiable(_todos);
  
  void addTodo(String title) {
    final id = _todos.isEmpty ? 1 : _todos.last.id + 1;
    _todos.add(Todo(id: id, title: title));
    notifyListeners(); // 通知监听者状态已更新
  }
  
  // 其他方法...
}
```

2. **使用依赖注入**：使组件更加松耦合，便于测试

```dart
// 依赖注入示例
class TodoView extends StatefulWidget {
  final TodoModel model;
  final TodoController controller;
  
  const TodoView({
    Key? key,
    required this.model,
    required this.controller,
  }) : super(key: key);
  
  @override
  _TodoViewState createState() => _TodoViewState();
}
```

这种改进方式让MVC更适合中等规模的Flutter应用，但对于复杂应用，我们可能需要考虑其他架构模式。

## MVVM模式

### MVVM基本概念

MVVM（Model-View-ViewModel）是在MVC基础上发展而来的架构模式，由以下部分组成：

1. **Model（模型）**：负责数据和业务逻辑
2. **View（视图）**：负责UI展示
3. **ViewModel（视图模型）**：作为View和Model之间的桥梁，转换Model数据为View可用的格式

MVVM的核心特点是通过数据绑定实现View和ViewModel的自动同步，减少手动更新UI的代码。

### Flutter中的MVVM实现

Flutter中实现MVVM通常会用到状态管理库如Provider、Riverpod或GetX。以下是使用Provider实现的待办事项应用示例：

#### Model

```dart
// todo_model.dart
class Todo {
  final int id;
  final String title;
  bool completed;

  Todo({
    required this.id,
    required this.title,
    this.completed = false,
  });

  Todo copyWith({
    int? id,
    String? title,
    bool? completed,
  }) {
    return Todo(
      id: id ?? this.id,
      title: title ?? this.title,
      completed: completed ?? this.completed,
    );
  }
}

// 数据仓库
class TodoRepository {
  // 模拟远程数据源
  Future<List<Todo>> fetchTodos() async {
    // 在实际应用中，这里会调用API
    await Future.delayed(Duration(seconds: 1));
    return [
      Todo(id: 1, title: '学习Flutter'),
      Todo(id: 2, title: '学习MVVM架构'),
      Todo(id: 3, title: '构建示例应用'),
    ];
  }

  Future<void> saveTodo(Todo todo) async {
    // 模拟保存操作
    await Future.delayed(Duration(milliseconds: 500));
    print('保存待办事项: ${todo.title}');
  }

  Future<void> deleteTodo(int id) async {
    // 模拟删除操作
    await Future.delayed(Duration(milliseconds: 500));
    print('删除待办事项ID: $id');
  }
}
```

#### ViewModel

```dart
// todo_view_model.dart
import 'package:flutter/material.dart';
import 'todo_model.dart';

class TodoViewModel extends ChangeNotifier {
  final TodoRepository repository;
  List<Todo> _todos = [];
  bool _isLoading = false;
  String? _error;

  TodoViewModel({required this.repository});

  // 获取状态
  List<Todo> get todos => List.unmodifiable(_todos);
  bool get isLoading => _isLoading;
  String? get error => _error;
  
  // 加载待办事项
  Future<void> loadTodos() async {
    _isLoading = true;
    _error = null;
    notifyListeners();
    
    try {
      _todos = await repository.fetchTodos();
    } catch (e) {
      _error = '加载失败: ${e.toString()}';
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  // 添加待办事项
  Future<void> addTodo(String title) async {
    if (title.trim().isEmpty) return;

    final id = _todos.isEmpty ? 1 : _todos.last.id + 1;
    final todo = Todo(id: id, title: title);
    
    // 乐观更新UI
    _todos.add(todo);
    notifyListeners();
    
    try {
      await repository.saveTodo(todo);
    } catch (e) {
      // 操作失败，回滚UI状态
      _todos.removeLast();
      _error = '添加失败: ${e.toString()}';
      notifyListeners();
    }
  }

  // 切换待办事项状态
  Future<void> toggleTodo(int id) async {
    final index = _todos.indexWhere((todo) => todo.id == id);
    if (index < 0) return;

    final todo = _todos[index];
    final updatedTodo = todo.copyWith(completed: !todo.completed);
    
    // 乐观更新UI
    _todos[index] = updatedTodo;
    notifyListeners();
    
    try {
      await repository.saveTodo(updatedTodo);
    } catch (e) {
      // 操作失败，回滚UI状态
      _todos[index] = todo;
      _error = '更新失败: ${e.toString()}';
      notifyListeners();
    }
  }

  // 删除待办事项
  Future<void> deleteTodo(int id) async {
    final index = _todos.indexWhere((todo) => todo.id == id);
    if (index < 0) return;

    final todo = _todos[index];
    
    // 乐观更新UI
    _todos.removeAt(index);
    notifyListeners();
    
    try {
      await repository.deleteTodo(id);
    } catch (e) {
      // 操作失败，回滚UI状态
      _todos.insert(index, todo);
      _error = '删除失败: ${e.toString()}';
      notifyListeners();
    }
  }
}
```

#### View

```dart
// todo_view.dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'todo_view_model.dart';

class TodoScreen extends StatefulWidget {
  @override
  _TodoScreenState createState() => _TodoScreenState();
}

class _TodoScreenState extends State<TodoScreen> {
  final TextEditingController _textController = TextEditingController();

  @override
  void initState() {
    super.initState();
    // 初始化时加载数据
    WidgetsBinding.instance.addPostFrameCallback((_) {
      context.read<TodoViewModel>().loadTodos();
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('MVVM待办事项'),
      ),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.all(8.0),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _textController,
                    decoration: InputDecoration(
                      hintText: '添加新待办事项',
                      border: OutlineInputBorder(),
                    ),
                  ),
                ),
                SizedBox(width: 8),
                Consumer<TodoViewModel>(
                  builder: (context, viewModel, child) {
                    return ElevatedButton(
                      onPressed: () {
                        viewModel.addTodo(_textController.text);
                        _textController.clear();
                      },
                      child: Text('添加'),
                    );
                  },
                ),
              ],
            ),
          ),
          Expanded(
            child: Consumer<TodoViewModel>(
              builder: (context, viewModel, child) {
                if (viewModel.isLoading) {
                  return Center(child: CircularProgressIndicator());
                }
                
                if (viewModel.error != null) {
                  return Center(child: Text(viewModel.error!));
                }

                if (viewModel.todos.isEmpty) {
                  return Center(child: Text('没有待办事项'));
                }
                
                return ListView.builder(
                  itemCount: viewModel.todos.length,
                  itemBuilder: (context, index) {
                    final todo = viewModel.todos[index];
                    return ListTile(
                      title: Text(
                        todo.title,
                        style: TextStyle(
                          decoration: todo.completed
                              ? TextDecoration.lineThrough
                              : TextDecoration.none,
                        ),
                      ),
                      leading: Checkbox(
                        value: todo.completed,
                        onChanged: (_) {
                          viewModel.toggleTodo(todo.id);
                        },
                      ),
                      trailing: IconButton(
                        icon: Icon(Icons.delete),
                        onPressed: () {
                          viewModel.deleteTodo(todo.id);
                        },
                      ),
                    );
                  },
                );
              },
            ),
          ),
        ],
      ),
    );
  }

  @override
  void dispose() {
    _textController.dispose();
    super.dispose();
  }
}
```

#### 主应用

```dart
// main.dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'todo_model.dart';
import 'todo_view_model.dart';
import 'todo_view.dart';

void main() {
  runApp(MyApp());
}

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter MVVM Demo',
      theme: ThemeData(
        primarySwatch: Colors.blue,
      ),
      home: ChangeNotifierProvider(
        create: (_) => TodoViewModel(
          repository: TodoRepository(),
        ),
        child: TodoScreen(),
      ),
    );
  }
}
```

### MVVM的优缺点

**优点：**
- 双向数据绑定减少样板代码
- 视图与业务逻辑完全分离
- 便于UI状态管理
- 高度可测试性
- ViewModel可在不同View中复用

**缺点：**
- 对于简单应用可能过于复杂
- 状态管理可能变得复杂
- 需要引入额外的库和依赖
- 学习曲线较陡峭

### MVVM实践技巧

1. **保持ViewModel足够薄**：ViewModel不应包含复杂的业务逻辑，而应将其委托给专门的服务或用例

```dart
// 业务逻辑抽离示例
class TodoService {
  final TodoRepository repository;
  
  TodoService(this.repository);
  
  Future<List<Todo>> getFilteredTodos(TodoFilter filter) async {
    final todos = await repository.fetchTodos();
    // 复杂的业务逻辑处理
    switch (filter) {
      case TodoFilter.all:
        return todos;
      case TodoFilter.completed:
        return todos.where((todo) => todo.completed).toList();
      case TodoFilter.active:
        return todos.where((todo) => !todo.completed).toList();
    }
  }
}

// 精简的ViewModel
class TodoViewModel extends ChangeNotifier {
  final TodoService _service;
  TodoViewModel(this._service);
  
  // 使用服务处理业务逻辑
  Future<void> loadFilteredTodos(TodoFilter filter) async {
    _isLoading = true;
    notifyListeners();
    
    try {
      _todos = await _service.getFilteredTodos(filter);
    } catch (e) {
      _error = e.toString();
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }
}
```

2. **状态不可变性**：保持状态的不可变性，避免直接修改状态

```dart
void updateTodos(List<Todo> newTodos) {
  // 不要直接修改列表
  // _todos = newTodos; ❌
  
  // 而是创建新的列表副本
  _todos = List<Todo>.from(newTodos); ✅
  notifyListeners();
}
```

## Clean Architecture

### Clean Architecture基本概念

Clean Architecture是由Robert C. Martin（Uncle Bob）提出的架构模式，其核心理念是关注点分离和依赖规则，确保内层不依赖于外层。这种架构分为多个同心圆层：

1. **实体层（Entities）**：包含业务规则和数据结构
2. **用例层（Use Cases）**：包含应用特定的业务规则
3. **接口适配层（Interface Adapters）**：包含将用例转换为外部可用格式的代码
4. **框架与驱动层（Frameworks & Drivers）**：包含框架、工具和外部接口

依赖规则：所有依赖都应该指向内层（更抽象的层）。

### Flutter中的Clean Architecture实现

在Flutter应用中实现Clean Architecture，通常会按照以下层级组织代码：

1. **领域层（Domain）**：包含实体和用例（业务逻辑）
2. **数据层（Data）**：包含数据源和仓库实现
3. **表示层（Presentation）**：包含UI组件和状态管理

以下是一个基于Clean Architecture的待办事项应用示例：

#### 领域层

```dart
// domain/entities/todo.dart
class Todo {
  final int id;
  final String title;
  final bool completed;

  Todo({
    required this.id,
    required this.title,
    required this.completed,
  });
}

// domain/repositories/todo_repository.dart
abstract class TodoRepository {
  Future<List<Todo>> getTodos();
  Future<void> addTodo(Todo todo);
  Future<void> updateTodo(Todo todo);
  Future<void> deleteTodo(int id);
}

// domain/usecases/get_todos.dart
class GetTodos {
  final TodoRepository repository;

  GetTodos(this.repository);

  Future<List<Todo>> call() async {
    return await repository.getTodos();
  }
}

// domain/usecases/add_todo.dart
class AddTodo {
  final TodoRepository repository;

  AddTodo(this.repository);

  Future<void> call(String title) async {
    final todo = Todo(
      id: DateTime.now().millisecondsSinceEpoch,
      title: title,
      completed: false,
    );
    
    return await repository.addTodo(todo);
  }
}

// domain/usecases/toggle_todo.dart
class ToggleTodo {
  final TodoRepository repository;

  ToggleTodo(this.repository);

  Future<void> call(Todo todo) async {
    final updatedTodo = Todo(
      id: todo.id,
      title: todo.title,
      completed: !todo.completed,
    );
    
    return await repository.updateTodo(updatedTodo);
  }
}

// domain/usecases/delete_todo.dart
class DeleteTodo {
  final TodoRepository repository;

  DeleteTodo(this.repository);

  Future<void> call(int id) async {
    return await repository.deleteTodo(id);
  }
}
```

#### 数据层

```dart
// data/models/todo_model.dart
import '../../domain/entities/todo.dart';

class TodoModel extends Todo {
  TodoModel({
    required int id,
    required String title,
    required bool completed,
  }) : super(
          id: id,
          title: title,
          completed: completed,
        );

  factory TodoModel.fromJson(Map<String, dynamic> json) {
    return TodoModel(
      id: json['id'],
      title: json['title'],
      completed: json['completed'],
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'title': title,
      'completed': completed,
    };
  }

  factory TodoModel.fromEntity(Todo todo) {
    return TodoModel(
      id: todo.id,
      title: todo.title,
      completed: todo.completed,
    );
  }
}

// data/datasources/todo_remote_data_source.dart
import '../models/todo_model.dart';

abstract class TodoRemoteDataSource {
  Future<List<TodoModel>> getTodos();
  Future<void> addTodo(TodoModel todo);
  Future<void> updateTodo(TodoModel todo);
  Future<void> deleteTodo(int id);
}

class TodoRemoteDataSourceImpl implements TodoRemoteDataSource {
  // 模拟远程API
  @override
  Future<List<TodoModel>> getTodos() async {
    await Future.delayed(Duration(seconds: 1));
    return [
      TodoModel(id: 1, title: '学习Flutter', completed: false),
      TodoModel(id: 2, title: '学习Clean Architecture', completed: false),
      TodoModel(id: 3, title: '实现示例应用', completed: true),
    ];
  }

  @override
  Future<void> addTodo(TodoModel todo) async {
    await Future.delayed(Duration(milliseconds: 500));
    print('添加待办事项: ${todo.title}');
  }

  @override
  Future<void> updateTodo(TodoModel todo) async {
    await Future.delayed(Duration(milliseconds: 500));
    print('更新待办事项: ${todo.title}, 状态: ${todo.completed}');
  }

  @override
  Future<void> deleteTodo(int id) async {
    await Future.delayed(Duration(milliseconds: 500));
    print('删除待办事项ID: $id');
  }
}

// data/repositories/todo_repository_impl.dart
import 'package:dartz/dartz.dart';
import '../../domain/entities/todo.dart';
import '../../domain/repositories/todo_repository.dart';
import '../datasources/todo_remote_data_source.dart';
import '../models/todo_model.dart';

class TodoRepositoryImpl implements TodoRepository {
  final TodoRemoteDataSource remoteDataSource;

  TodoRepositoryImpl(this.remoteDataSource);

  @override
  Future<List<Todo>> getTodos() async {
    try {
      final remoteTodos = await remoteDataSource.getTodos();
      return remoteTodos;
    } catch (e) {
      throw Exception('获取待办事项失败: $e');
    }
  }

  @override
  Future<void> addTodo(Todo todo) async {
    try {
      await remoteDataSource.addTodo(TodoModel.fromEntity(todo));
    } catch (e) {
      throw Exception('添加待办事项失败: $e');
    }
  }

  @override
  Future<void> updateTodo(Todo todo) async {
    try {
      await remoteDataSource.updateTodo(TodoModel.fromEntity(todo));
    } catch (e) {
      throw Exception('更新待办事项失败: $e');
    }
  }

  @override
  Future<void> deleteTodo(int id) async {
    try {
      await remoteDataSource.deleteTodo(id);
    } catch (e) {
      throw Exception('删除待办事项失败: $e');
    }
  }
}
```

#### 表示层

使用Bloc状态管理：

```dart
// presentation/bloc/todo_event.dart
abstract class TodoEvent {}

class LoadTodosEvent extends TodoEvent {}

class AddTodoEvent extends TodoEvent {
  final String title;
  AddTodoEvent(this.title);
}

class ToggleTodoEvent extends TodoEvent {
  final Todo todo;
  ToggleTodoEvent(this.todo);
}

class DeleteTodoEvent extends TodoEvent {
  final int id;
  DeleteTodoEvent(this.id);
}

// presentation/bloc/todo_state.dart
abstract class TodoState {}

class TodoInitial extends TodoState {}

class TodoLoading extends TodoState {}

class TodoLoaded extends TodoState {
  final List<Todo> todos;
  TodoLoaded(this.todos);
}

class TodoError extends TodoState {
  final String message;
  TodoError(this.message);
}

// presentation/bloc/todo_bloc.dart
import 'package:flutter_bloc/flutter_bloc.dart';
import '../../domain/entities/todo.dart';
import '../../domain/usecases/add_todo.dart';
import '../../domain/usecases/delete_todo.dart';
import '../../domain/usecases/get_todos.dart';
import '../../domain/usecases/toggle_todo.dart';

class TodoBloc extends Bloc<TodoEvent, TodoState> {
  final GetTodos getTodos;
  final AddTodo addTodo;
  final ToggleTodo toggleTodo;
  final DeleteTodo deleteTodo;

  TodoBloc({
    required this.getTodos,
    required this.addTodo,
    required this.toggleTodo,
    required this.deleteTodo,
  }) : super(TodoInitial()) {
    on<LoadTodosEvent>(_onLoadTodos);
    on<AddTodoEvent>(_onAddTodo);
    on<ToggleTodoEvent>(_onToggleTodo);
    on<DeleteTodoEvent>(_onDeleteTodo);
  }

  Future<void> _onLoadTodos(LoadTodosEvent event, Emitter<TodoState> emit) async {
    emit(TodoLoading());
    try {
      final todos = await getTodos();
      emit(TodoLoaded(todos));
    } catch (e) {
      emit(TodoError(e.toString()));
    }
  }

  Future<void> _onAddTodo(AddTodoEvent event, Emitter<TodoState> emit) async {
    final currentState = state;
    if (currentState is TodoLoaded) {
      try {
        await addTodo(event.title);
        final updatedTodos = await getTodos();
        emit(TodoLoaded(updatedTodos));
      } catch (e) {
        emit(TodoError(e.toString()));
        emit(currentState); // 回到之前的状态
      }
    }
  }

  Future<void> _onToggleTodo(ToggleTodoEvent event, Emitter<TodoState> emit) async {
    final currentState = state;
    if (currentState is TodoLoaded) {
      try {
        await toggleTodo(event.todo);
        final updatedTodos = await getTodos();
        emit(TodoLoaded(updatedTodos));
      } catch (e) {
        emit(TodoError(e.toString()));
        emit(currentState); // 回到之前的状态
      }
    }
  }

  Future<void> _onDeleteTodo(DeleteTodoEvent event, Emitter<TodoState> emit) async {
    final currentState = state;
    if (currentState is TodoLoaded) {
      try {
        await deleteTodo(event.id);
        final updatedTodos = await getTodos();
        emit(TodoLoaded(updatedTodos));
      } catch (e) {
        emit(TodoError(e.toString()));
        emit(currentState); // 回到之前的状态
      }
    }
  }
}
```

#### UI部分

```dart
// presentation/pages/todo_page.dart
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import '../bloc/todo_bloc.dart';
import '../bloc/todo_event.dart';
import '../bloc/todo_state.dart';
import '../../domain/entities/todo.dart';

class TodoPage extends StatefulWidget {
  @override
  _TodoPageState createState() => _TodoPageState();
}

class _TodoPageState extends State<TodoPage> {
  final TextEditingController _textController = TextEditingController();

  @override
  void initState() {
    super.initState();
    // 加载初始数据
    context.read<TodoBloc>().add(LoadTodosEvent());
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Clean Architecture待办事项'),
      ),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.all(8.0),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _textController,
                    decoration: InputDecoration(
                      hintText: '添加新待办事项',
                      border: OutlineInputBorder(),
                    ),
                  ),
                ),
                SizedBox(width: 8),
                ElevatedButton(
                  onPressed: () {
                    if (_textController.text.isNotEmpty) {
                      context.read<TodoBloc>().add(
                            AddTodoEvent(_textController.text),
                          );
                      _textController.clear();
                    }
                  },
                  child: Text('添加'),
                ),
              ],
            ),
          ),
          Expanded(
            child: BlocBuilder<TodoBloc, TodoState>(
              builder: (context, state) {
                if (state is TodoLoading) {
                  return Center(child: CircularProgressIndicator());
                } else if (state is TodoLoaded) {
                  if (state.todos.isEmpty) {
                    return Center(child: Text('没有待办事项'));
                  }
                  
                  return ListView.builder(
                    itemCount: state.todos.length,
                    itemBuilder: (context, index) {
                      final todo = state.todos[index];
                      return ListTile(
                        title: Text(
                          todo.title,
                          style: TextStyle(
                            decoration: todo.completed
                                ? TextDecoration.lineThrough
                                : TextDecoration.none,
                          ),
                        ),
                        leading: Checkbox(
                          value: todo.completed,
                          onChanged: (_) {
                            context.read<TodoBloc>().add(
                                  ToggleTodoEvent(todo),
                                );
                          },
                        ),
                        trailing: IconButton(
                          icon: Icon(Icons.delete),
                          onPressed: () {
                            context.read<TodoBloc>().add(
                                  DeleteTodoEvent(todo.id),
                                );
                          },
                        ),
                      );
                    },
                  );
                } else if (state is TodoError) {
                  return Center(
                    child: Text(
                      '错误: ${state.message}',
                      style: TextStyle(color: Colors.red),
                    ),
                  );
                }
                
                return Center(child: Text('加载待办事项'));
              },
            ),
          ),
        ],
      ),
    );
  }

  @override
  void dispose() {
    _textController.dispose();
    super.dispose();
  }
}
```

#### 依赖注入

使用get_it进行依赖注入：

```dart
// injection_container.dart
import 'package:get_it/get_it.dart';
import 'data/datasources/todo_remote_data_source.dart';
import 'data/repositories/todo_repository_impl.dart';
import 'domain/repositories/todo_repository.dart';
import 'domain/usecases/add_todo.dart';
import 'domain/usecases/delete_todo.dart';
import 'domain/usecases/get_todos.dart';
import 'domain/usecases/toggle_todo.dart';
import 'presentation/bloc/todo_bloc.dart';

final sl = GetIt.instance;

Future<void> init() async {
  // Bloc
  sl.registerFactory(
    () => TodoBloc(
      getTodos: sl(),
      addTodo: sl(),
      toggleTodo: sl(),
      deleteTodo: sl(),
    ),
  );

  // Use cases
  sl.registerLazySingleton(() => GetTodos(sl()));
  sl.registerLazySingleton(() => AddTodo(sl()));
  sl.registerLazySingleton(() => ToggleTodo(sl()));
  sl.registerLazySingleton(() => DeleteTodo(sl()));

  // Repository
  sl.registerLazySingleton<TodoRepository>(
    () => TodoRepositoryImpl(sl()),
  );

  // Data sources
  sl.registerLazySingleton<TodoRemoteDataSource>(
    () => TodoRemoteDataSourceImpl(),
  );
}
```

#### 主应用

```dart
// main.dart
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'injection_container.dart' as di;
import 'presentation/bloc/todo_bloc.dart';
import 'presentation/pages/todo_page.dart';

void main() async {
  await di.init();
  runApp(MyApp());
}

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Clean Architecture Demo',
      theme: ThemeData(primarySwatch: Colors.blue),
      home: BlocProvider(
        create: (_) => di.sl<TodoBloc>(),
        child: TodoPage(),
      ),
    );
  }
}
```

### Clean Architecture的优缺点

**优点：**
- 高度可测试性
- 关注点彻底分离
- 业务规则与UI和外部框架完全分离
- 灵活性强，便于适应需求变化
- 可维护性和可扩展性强

**缺点：**
- 初始设置复杂
- 对于简单应用来说过于复杂
- 需要编写更多代码
- 团队需要深入理解架构原则

### Clean Architecture实践技巧

1. **坚持依赖规则**：内层不应依赖外层

```dart
// 错误：领域层依赖数据层
import '../../data/models/todo_model.dart'; // ❌

// 正确：数据层依赖领域层
import '../../domain/entities/todo.dart'; // ✅
```

2. **使用抽象接口**：通过接口实现依赖反转

```dart
// 定义仓库接口
abstract class Repository {
  Future<List<Entity>> getAll();
}

// 数据层实现仓库接口
class RepositoryImpl implements Repository {
  @override
  Future<List<Entity>> getAll() async {
    // 实现...
  }
}
```

3. **使用依赖注入**：便于测试和组件替换

```dart
// 而不是直接实例化
final repository = RepositoryImpl(); // ❌

// 使用依赖注入
class UseCase {
  final Repository repository;
  
  UseCase(this.repository); // ✅
}
```

## 架构选择指南

如何为Flutter项目选择合适的架构模式？以下是一些考虑因素：

1. **项目规模**：
   - 小型项目：MVC可能足够
   - 中型项目：MVVM提供更好的状态管理
   - 大型项目：Clean Architecture带来长期维护优势

2. **团队因素**：
   - 团队经验和熟悉度
   - 团队规模和协作需求
   - 开发时间限制

3. **业务复杂度**：
   - 简单业务逻辑：MVC或MVVM
   - 复杂业务规则：Clean Architecture更适合

4. **测试需求**：
   - 较少测试需求：MVC可接受
   - 高测试覆盖率要求：MVVM或Clean Architecture

5. **应用生命周期**：
   - 短期项目：MVC快速开发
   - 长期维护项目：Clean Architecture更有优势

### 架构对比表

| 特性 | MVC | MVVM | Clean Architecture |
|------|-----|------|-------------------|
| 简单性 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐ |
| 代码分离 | ⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| 可测试性 | ⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| 可维护性 | ⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| 开发速度 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| 学习曲线 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| 适用项目规模 | 小型 | 中型 | 大型 |

## 最佳实践

无论选择哪种架构模式，以下是一些通用的最佳实践：

1. **一致性**：项目内保持架构一致
2. **文档**：清晰记录架构决策和规范
3. **依赖注入**：使用依赖注入减少组件耦合
4. **单一职责原则**：每个类应只有一个变更理由
5. **测试覆盖**：编写单元测试和集成测试
6. **渐进式采用**：可以渐进式采用更复杂的架构
7. **避免过度工程**：根据项目需求选择适当的复杂度

在实践中，三种架构模式可以根据项目需求灵活调整和组合使用，没有绝对的最佳选择，重要的是找到适合团队和项目的平衡点。
