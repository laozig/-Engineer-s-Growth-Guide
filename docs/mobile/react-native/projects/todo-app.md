# React Native实战：构建TODO应用

本教程将指导你使用React Native构建一个功能完整的待办事项(TODO)应用。我们将从项目设置开始，逐步实现核心功能，直到最终完成一个具有实用价值的移动应用。

## 目标应用功能

我们将构建的TODO应用具有以下功能：

- 添加新的待办事项
- 标记待办事项为已完成
- 删除待办事项
- 编辑现有待办事项
- 按类别过滤待办事项
- 持久化存储数据
- 优雅的UI设计

## 第1步：项目设置

首先，创建一个新的React Native项目：

```bash
npx react-native init TodoApp --template react-native-template-typescript
cd TodoApp
```

安装项目依赖：

```bash
npm install @react-navigation/native @react-navigation/stack react-native-gesture-handler react-native-reanimated react-native-safe-area-context react-native-screens
npm install @react-native-async-storage/async-storage uuid
npm install --save-dev @types/uuid
```

运行项目确认设置正确：

```bash
npm run android  # 或 npm run ios
```

## 第2步：创建应用结构

让我们创建应用的基本结构，包括必要的文件夹和文件：

```bash
mkdir -p src/{components,screens,hooks,utils,store,types}
touch src/types/index.ts
```

### 定义类型

首先，在`src/types/index.ts`中定义项目中使用的类型：

```typescript
export interface Todo {
  id: string;
  text: string;
  completed: boolean;
  category: string;
  createdAt: number;
}

export type TodoCategory = 'All' | 'Work' | 'Personal' | 'Shopping' | 'Other';
```

## 第3步：创建基础组件

### TodoItem组件

创建`src/components/TodoItem.tsx`：

```typescript
import React from 'react';
import {
  StyleSheet,
  Text,
  View,
  TouchableOpacity,
  Animated,
  Alert,
} from 'react-native';
import Icon from 'react-native-vector-icons/MaterialIcons';
import { Todo } from '../types';

interface TodoItemProps {
  todo: Todo;
  onToggle: (id: string) => void;
  onDelete: (id: string) => void;
  onEdit: (id: string) => void;
}

const TodoItem: React.FC<TodoItemProps> = ({
  todo,
  onToggle,
  onDelete,
  onEdit,
}) => {
  const scaleValue = new Animated.Value(1);

  const animateScale = () => {
    Animated.sequence([
      Animated.timing(scaleValue, {
        toValue: 0.95,
        duration: 100,
        useNativeDriver: true,
      }),
      Animated.timing(scaleValue, {
        toValue: 1,
        duration: 100,
        useNativeDriver: true,
      }),
    ]).start();
  };

  const handleToggle = () => {
    animateScale();
    onToggle(todo.id);
  };

  const confirmDelete = () => {
    Alert.alert(
      'Delete Todo',
      'Are you sure you want to delete this item?',
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Delete', onPress: () => onDelete(todo.id), style: 'destructive' },
      ],
    );
  };

  const getDateString = () => {
    const date = new Date(todo.createdAt);
    return `${date.toLocaleDateString()} ${date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
  };

  return (
    <Animated.View
      style={[
        styles.container,
        { transform: [{ scale: scaleValue }] },
      ]}
    >
      <TouchableOpacity
        style={styles.todoContainer}
        onPress={handleToggle}
        activeOpacity={0.8}
      >
        <View style={styles.checkboxContainer}>
          <View
            style={[
              styles.checkbox,
              todo.completed && styles.checkboxChecked,
            ]}
          >
            {todo.completed && (
              <Icon name="check" size={16} color="#FFFFFF" />
            )}
          </View>
        </View>
        <View style={styles.textContainer}>
          <Text
            style={[
              styles.todoText,
              todo.completed && styles.todoTextCompleted,
            ]}
          >
            {todo.text}
          </Text>
          <View style={styles.metaContainer}>
            <Text style={styles.category}>{todo.category}</Text>
            <Text style={styles.date}>{getDateString()}</Text>
          </View>
        </View>
      </TouchableOpacity>
      <View style={styles.actionsContainer}>
        <TouchableOpacity
          onPress={() => onEdit(todo.id)}
          style={styles.actionButton}
        >
          <Icon name="edit" size={20} color="#007BFF" />
        </TouchableOpacity>
        <TouchableOpacity
          onPress={confirmDelete}
          style={styles.actionButton}
        >
          <Icon name="delete" size={20} color="#FF3B30" />
        </TouchableOpacity>
      </View>
    </Animated.View>
  );
};

const styles = StyleSheet.create({
  container: {
    backgroundColor: '#FFFFFF',
    borderRadius: 8,
    marginVertical: 6,
    marginHorizontal: 16,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 2,
  },
  todoContainer: {
    flexDirection: 'row',
    padding: 16,
  },
  checkboxContainer: {
    justifyContent: 'center',
    marginRight: 12,
  },
  checkbox: {
    width: 24,
    height: 24,
    borderRadius: 12,
    borderWidth: 2,
    borderColor: '#007BFF',
    justifyContent: 'center',
    alignItems: 'center',
  },
  checkboxChecked: {
    backgroundColor: '#007BFF',
  },
  textContainer: {
    flex: 1,
  },
  todoText: {
    fontSize: 16,
    color: '#333333',
  },
  todoTextCompleted: {
    textDecorationLine: 'line-through',
    color: '#888888',
  },
  metaContainer: {
    flexDirection: 'row',
    marginTop: 4,
    justifyContent: 'space-between',
  },
  category: {
    fontSize: 12,
    color: '#007BFF',
    fontWeight: '600',
  },
  date: {
    fontSize: 12,
    color: '#888888',
  },
  actionsContainer: {
    flexDirection: 'row',
    borderTopWidth: 1,
    borderTopColor: '#EEEEEE',
  },
  actionButton: {
    flex: 1,
    padding: 10,
    justifyContent: 'center',
    alignItems: 'center',
  },
});

export default TodoItem;
```

### AddTodo组件

创建`src/components/AddTodo.tsx`：

```typescript
import React, { useState } from 'react';
import {
  View,
  TextInput,
  StyleSheet,
  TouchableOpacity,
  Modal,
  Text,
  KeyboardAvoidingView,
  Platform,
} from 'react-native';
import Icon from 'react-native-vector-icons/MaterialIcons';
import { TodoCategory } from '../types';

interface AddTodoProps {
  visible: boolean;
  onClose: () => void;
  onAdd: (text: string, category: TodoCategory) => void;
  initialText?: string;
  initialCategory?: TodoCategory;
  isEditing?: boolean;
}

const categories: TodoCategory[] = ['All', 'Work', 'Personal', 'Shopping', 'Other'];

const AddTodo: React.FC<AddTodoProps> = ({
  visible,
  onClose,
  onAdd,
  initialText = '',
  initialCategory = 'All',
  isEditing = false,
}) => {
  const [text, setText] = useState(initialText);
  const [category, setCategory] = useState<TodoCategory>(initialCategory);

  const handleSubmit = () => {
    if (text.trim()) {
      onAdd(text.trim(), category === 'All' ? 'Other' : category);
      setText('');
      setCategory('All');
      onClose();
    }
  };

  const handleCancel = () => {
    setText(initialText);
    setCategory(initialCategory);
    onClose();
  };

  return (
    <Modal
      visible={visible}
      transparent
      animationType="fade"
      onRequestClose={handleCancel}
    >
      <KeyboardAvoidingView
        behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
        style={styles.overlay}
      >
        <View style={styles.container}>
          <View style={styles.header}>
            <Text style={styles.title}>{isEditing ? 'Edit Task' : 'Add New Task'}</Text>
            <TouchableOpacity onPress={handleCancel}>
              <Icon name="close" size={24} color="#333" />
            </TouchableOpacity>
          </View>

          <TextInput
            style={styles.input}
            placeholder="What needs to be done?"
            value={text}
            onChangeText={setText}
            autoFocus
            multiline
          />

          <Text style={styles.sectionTitle}>Category</Text>
          <View style={styles.categoryContainer}>
            {categories.filter(cat => cat !== 'All').map((cat) => (
              <TouchableOpacity
                key={cat}
                style={[
                  styles.categoryChip,
                  category === cat && styles.categoryChipSelected,
                ]}
                onPress={() => setCategory(cat)}
              >
                <Text
                  style={[
                    styles.categoryText,
                    category === cat && styles.categoryTextSelected,
                  ]}
                >
                  {cat}
                </Text>
              </TouchableOpacity>
            ))}
          </View>

          <View style={styles.buttonContainer}>
            <TouchableOpacity
              style={[styles.button, styles.cancelButton]}
              onPress={handleCancel}
            >
              <Text style={styles.buttonText}>Cancel</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={[styles.button, styles.addButton, !text.trim() && styles.disabledButton]}
              onPress={handleSubmit}
              disabled={!text.trim()}
            >
              <Text style={[styles.buttonText, styles.addButtonText]}>
                {isEditing ? 'Update' : 'Add Task'}
              </Text>
            </TouchableOpacity>
          </View>
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
};

const styles = StyleSheet.create({
  overlay: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.5)',
    justifyContent: 'center',
    alignItems: 'center',
  },
  container: {
    width: '90%',
    backgroundColor: 'white',
    borderRadius: 10,
    padding: 20,
    maxHeight: '80%',
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 20,
  },
  title: {
    fontSize: 20,
    fontWeight: 'bold',
    color: '#333',
  },
  input: {
    borderWidth: 1,
    borderColor: '#E0E0E0',
    borderRadius: 8,
    padding: 12,
    fontSize: 16,
    minHeight: 100,
    maxHeight: 150,
    textAlignVertical: 'top',
    marginBottom: 16,
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: '600',
    color: '#333',
    marginBottom: 10,
  },
  categoryContainer: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    marginBottom: 20,
  },
  categoryChip: {
    paddingVertical: 6,
    paddingHorizontal: 12,
    borderRadius: 20,
    borderWidth: 1,
    borderColor: '#007BFF',
    marginRight: 8,
    marginBottom: 8,
  },
  categoryChipSelected: {
    backgroundColor: '#007BFF',
  },
  categoryText: {
    color: '#007BFF',
    fontSize: 14,
  },
  categoryTextSelected: {
    color: 'white',
  },
  buttonContainer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  button: {
    paddingVertical: 12,
    paddingHorizontal: 20,
    borderRadius: 8,
    flex: 1,
    alignItems: 'center',
    marginHorizontal: 5,
  },
  cancelButton: {
    backgroundColor: '#F0F0F0',
  },
  addButton: {
    backgroundColor: '#007BFF',
  },
  disabledButton: {
    backgroundColor: '#B0D0FF',
  },
  buttonText: {
    fontWeight: '600',
    fontSize: 16,
  },
  addButtonText: {
    color: 'white',
  },
});

export default AddTodo;
```

### CategoryFilter组件

创建`src/components/CategoryFilter.tsx`：

```typescript
import React from 'react';
import {
  ScrollView,
  StyleSheet,
  TouchableOpacity,
  Text,
  View,
} from 'react-native';
import { TodoCategory } from '../types';

interface CategoryFilterProps {
  categories: TodoCategory[];
  selectedCategory: TodoCategory;
  onSelectCategory: (category: TodoCategory) => void;
}

const CategoryFilter: React.FC<CategoryFilterProps> = ({
  categories,
  selectedCategory,
  onSelectCategory,
}) => {
  return (
    <View style={styles.container}>
      <ScrollView
        horizontal
        showsHorizontalScrollIndicator={false}
        contentContainerStyle={styles.scrollContainer}
      >
        {categories.map((category) => (
          <TouchableOpacity
            key={category}
            style={[
              styles.categoryChip,
              selectedCategory === category && styles.selectedCategoryChip,
            ]}
            onPress={() => onSelectCategory(category)}
          >
            <Text
              style={[
                styles.categoryText,
                selectedCategory === category && styles.selectedCategoryText,
              ]}
            >
              {category}
            </Text>
          </TouchableOpacity>
        ))}
      </ScrollView>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderBottomColor: '#EEEEEE',
  },
  scrollContainer: {
    paddingHorizontal: 16,
  },
  categoryChip: {
    paddingVertical: 8,
    paddingHorizontal: 16,
    borderRadius: 20,
    backgroundColor: '#F0F0F0',
    marginRight: 8,
  },
  selectedCategoryChip: {
    backgroundColor: '#007BFF',
  },
  categoryText: {
    fontSize: 14,
    fontWeight: '500',
    color: '#555555',
  },
  selectedCategoryText: {
    color: '#FFFFFF',
  },
});

export default CategoryFilter;
```

## 第4步：创建存储逻辑

创建`src/hooks/useTodos.ts`用于管理待办事项的状态：

```typescript
import { useState, useEffect } from 'react';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { v4 as uuidv4 } from 'uuid';
import { Todo, TodoCategory } from '../types';

const STORAGE_KEY = '@todo_app_todos';

export const useTodos = () => {
  const [todos, setTodos] = useState<Todo[]>([]);
  const [selectedCategory, setSelectedCategory] = useState<TodoCategory>('All');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadTodos();
  }, []);

  const loadTodos = async () => {
    try {
      const savedTodos = await AsyncStorage.getItem(STORAGE_KEY);
      if (savedTodos) {
        setTodos(JSON.parse(savedTodos));
      }
    } catch (error) {
      console.error('Failed to load todos', error);
    } finally {
      setLoading(false);
    }
  };

  const saveTodos = async (newTodos: Todo[]) => {
    try {
      await AsyncStorage.setItem(STORAGE_KEY, JSON.stringify(newTodos));
    } catch (error) {
      console.error('Failed to save todos', error);
    }
  };

  const addTodo = (text: string, category: TodoCategory) => {
    const newTodo: Todo = {
      id: uuidv4(),
      text,
      completed: false,
      category,
      createdAt: Date.now(),
    };
    
    const newTodos = [...todos, newTodo];
    setTodos(newTodos);
    saveTodos(newTodos);
    return newTodo;
  };

  const toggleTodo = (id: string) => {
    const newTodos = todos.map((todo) =>
      todo.id === id ? { ...todo, completed: !todo.completed } : todo
    );
    setTodos(newTodos);
    saveTodos(newTodos);
  };

  const deleteTodo = (id: string) => {
    const newTodos = todos.filter((todo) => todo.id !== id);
    setTodos(newTodos);
    saveTodos(newTodos);
  };

  const editTodo = (id: string, text: string, category: TodoCategory) => {
    const newTodos = todos.map((todo) =>
      todo.id === id ? { ...todo, text, category } : todo
    );
    setTodos(newTodos);
    saveTodos(newTodos);
  };

  const getTodoById = (id: string) => {
    return todos.find((todo) => todo.id === id);
  };

  const filteredTodos = selectedCategory === 'All'
    ? todos
    : todos.filter((todo) => todo.category === selectedCategory);
  
  const categories: TodoCategory[] = ['All', 'Work', 'Personal', 'Shopping', 'Other'];

  return {
    todos: filteredTodos,
    addTodo,
    toggleTodo,
    deleteTodo,
    editTodo,
    getTodoById,
    loading,
    categories,
    selectedCategory,
    setSelectedCategory,
  };
};
```

## 第5步：创建主屏幕

创建`src/screens/HomeScreen.tsx`：

```typescript
import React, { useState } from 'react';
import {
  View,
  StyleSheet,
  FlatList,
  Text,
  ActivityIndicator,
  TouchableOpacity,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import Icon from 'react-native-vector-icons/MaterialIcons';
import TodoItem from '../components/TodoItem';
import AddTodo from '../components/AddTodo';
import CategoryFilter from '../components/CategoryFilter';
import { useTodos } from '../hooks/useTodos';
import { TodoCategory } from '../types';

const HomeScreen: React.FC = () => {
  const insets = useSafeAreaInsets();
  const {
    todos,
    loading,
    addTodo,
    toggleTodo,
    deleteTodo,
    editTodo,
    getTodoById,
    categories,
    selectedCategory,
    setSelectedCategory,
  } = useTodos();

  const [showAddModal, setShowAddModal] = useState(false);
  const [editingTodo, setEditingTodo] = useState<string | null>(null);

  const handleEdit = (id: string) => {
    setEditingTodo(id);
    setShowAddModal(true);
  };

  const handleAddOrUpdate = (text: string, category: TodoCategory) => {
    if (editingTodo) {
      editTodo(editingTodo, text, category);
      setEditingTodo(null);
    } else {
      addTodo(text, category);
    }
  };

  const renderEmptyList = () => (
    <View style={styles.emptyContainer}>
      <Icon name="check-circle" size={64} color="#DDDDDD" />
      <Text style={styles.emptyText}>
        {selectedCategory === 'All'
          ? 'No tasks yet! Add a new task to get started.'
          : `No tasks in ${selectedCategory} category.`}
      </Text>
    </View>
  );

  const todoToEdit = editingTodo ? getTodoById(editingTodo) : null;

  return (
    <View style={[styles.container, { paddingTop: insets.top }]}>
      <View style={styles.header}>
        <Text style={styles.title}>Todo List</Text>
        <TouchableOpacity
          style={styles.addButton}
          onPress={() => {
            setEditingTodo(null);
            setShowAddModal(true);
          }}
        >
          <Icon name="add" size={24} color="#FFFFFF" />
        </TouchableOpacity>
      </View>
      
      <CategoryFilter
        categories={categories}
        selectedCategory={selectedCategory}
        onSelectCategory={setSelectedCategory}
      />

      {loading ? (
        <ActivityIndicator style={styles.loader} size="large" color="#007BFF" />
      ) : (
        <FlatList
          data={todos}
          keyExtractor={(item) => item.id}
          renderItem={({ item }) => (
            <TodoItem
              todo={item}
              onToggle={toggleTodo}
              onDelete={deleteTodo}
              onEdit={handleEdit}
            />
          )}
          contentContainerStyle={styles.listContent}
          ListEmptyComponent={renderEmptyList}
        />
      )}

      <AddTodo
        visible={showAddModal}
        onClose={() => {
          setShowAddModal(false);
          setEditingTodo(null);
        }}
        onAdd={handleAddOrUpdate}
        initialText={todoToEdit?.text || ''}
        initialCategory={todoToEdit?.category || 'All'}
        isEditing={!!editingTodo}
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#F8F8F8',
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 16,
    paddingVertical: 16,
    backgroundColor: '#FFFFFF',
    borderBottomWidth: 1,
    borderBottomColor: '#EEEEEE',
  },
  title: {
    fontSize: 22,
    fontWeight: 'bold',
    color: '#333333',
  },
  addButton: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: '#007BFF',
    justifyContent: 'center',
    alignItems: 'center',
    elevation: 2,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 2,
  },
  listContent: {
    paddingVertical: 8,
    flexGrow: 1,
  },
  emptyContainer: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: 32,
    marginTop: 100,
  },
  emptyText: {
    fontSize: 16,
    color: '#888888',
    textAlign: 'center',
    marginTop: 16,
  },
  loader: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
});

export default HomeScreen;
```

## 第6步：创建入口组件

更新`App.tsx`：

```typescript
import React from 'react';
import { StatusBar, LogBox } from 'react-native';
import { NavigationContainer } from '@react-navigation/native';
import { createStackNavigator } from '@react-navigation/stack';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import HomeScreen from './src/screens/HomeScreen';

// Ignore log notifications from dependencies
LogBox.ignoreLogs([
  'VirtualizedLists should never be nested',
  'ReactNativeFiberHostComponent: Calling getNode() on the ref of an Animated',
]);

const Stack = createStackNavigator();

const App = () => {
  return (
    <SafeAreaProvider>
      <StatusBar barStyle="dark-content" backgroundColor="#FFFFFF" />
      <NavigationContainer>
        <Stack.Navigator
          screenOptions={{
            headerShown: false,
          }}
        >
          <Stack.Screen name="Home" component={HomeScreen} />
        </Stack.Navigator>
      </NavigationContainer>
    </SafeAreaProvider>
  );
};

export default App;
```

## 第7步：安装矢量图标

我们使用了React Native矢量图标，需要进行配置：

1. 安装图标包：
```bash
npm install react-native-vector-icons
```

2. 链接图标资源（iOS）：
编辑 `ios/Podfile` 并添加:
```ruby
pod 'RNVectorIcons', :path => '../node_modules/react-native-vector-icons'
```

然后运行：
```bash
cd ios && pod install
```

3. 链接图标资源（Android）：
编辑 `android/app/build.gradle`，添加:
```gradle
apply from: "../../node_modules/react-native-vector-icons/fonts.gradle"
```

## 第8步：运行和测试应用

现在可以运行并测试应用：

```bash
npm run android  # 或 npm run ios
```

## 进一步改进

完成基础功能后，可以考虑以下改进：

1. **主题支持**：添加深色和浅色主题
2. **统计数据**：显示已完成/待完成任务的比例
3. **任务提醒**：添加截止日期和本地通知
4. **拖拽排序**：允许用户重新排列任务
5. **搜索功能**：按关键词搜索任务
6. **云同步**：使用Firebase等服务进行多设备同步
7. **动画和手势**：添加更丰富的交互动画

## 结论

恭喜！你已经成功构建了一个功能完整的React Native TODO应用。这个应用展示了React Native的许多核心概念，包括:

- 组件和屏幕结构
- 状态管理和自定义钩子
- 持久化数据存储
- UI设计和交互
- 动画和视觉反馈

你可以将这个项目作为学习React Native的基础，继续扩展功能或将所学知识应用到其他更复杂的项目中。 