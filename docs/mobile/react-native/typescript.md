# 在React Native中使用TypeScript进行类型安全开发

TypeScript是JavaScript的超集，它增加了静态类型和其他功能，可以大大提高代码的可靠性和开发效率。本文将介绍如何在React Native项目中使用TypeScript，帮助你构建更加健壮的移动应用。

## 目录

- [TypeScript简介](#typescript简介)
- [在React Native中设置TypeScript](#在react-native中设置typescript)
- [基本类型定义](#基本类型定义)
- [React组件类型](#react组件类型)
- [状态和属性类型](#状态和属性类型)
- [事件处理类型](#事件处理类型)
- [API响应类型](#api响应类型)
- [导航类型](#导航类型)
- [常见问题与解决方案](#常见问题与解决方案)
- [最佳实践](#最佳实践)

## TypeScript简介

TypeScript是JavaScript的超集，提供了静态类型检查系统，使你能够在开发阶段捕获错误，而不是在运行时。

### TypeScript的主要优势

- **错误检测**：在编译时捕获类型相关的错误
- **智能提示**：提供更好的代码补全和API文档
- **代码可读性**：通过类型注解使代码意图更明确
- **可维护性**：重构时更加安全可靠
- **库支持**：大多数流行的JavaScript库都有TypeScript类型定义

### JavaScript与TypeScript对比

```javascript
// JavaScript
function add(a, b) {
  return a + b; // 如果a和b不是数字，可能产生意外结果
}

console.log(add(5, "10")); // 输出 "510"，字符串拼接而非数字相加
```

```typescript
// TypeScript
function add(a: number, b: number): number {
  return a + b; // 编译器确保a和b都是数字
}

console.log(add(5, "10")); // 编译错误：类型"string"不能赋给类型"number"
```

## 在React Native中设置TypeScript

### 创建新的TypeScript项目

使用React Native CLI创建一个新的TypeScript项目非常简单：

```bash
npx react-native init MyTSProject --template react-native-template-typescript
```

### 将现有项目转换为TypeScript

如果你已经有了一个JavaScript的React Native项目，可以按照以下步骤添加TypeScript支持：

1. **安装所需依赖**

```bash
npm install --save-dev typescript @types/jest @types/react @types/react-native @types/react-test-renderer
```

2. **创建TypeScript配置文件**

在项目根目录创建`tsconfig.json`文件：

```json
{
  "compilerOptions": {
    "allowJs": true,
    "allowSyntheticDefaultImports": true,
    "esModuleInterop": true,
    "isolatedModules": true,
    "jsx": "react-native",
    "lib": ["es2017"],
    "moduleResolution": "node",
    "noEmit": true,
    "strict": true,
    "target": "esnext",
    "baseUrl": "./",
    "paths": {
      "*": ["src/*"],
      "tests": ["tests/*"],
      "@components/*": ["src/components/*"]
    }
  },
  "exclude": [
    "node_modules",
    "babel.config.js",
    "metro.config.js",
    "jest.config.js"
  ]
}
```

3. **创建声明文件**

创建`react-native.d.ts`文件以处理非TypeScript模块：

```typescript
// src/react-native.d.ts
declare module '*.png';
declare module '*.jpg';
declare module '*.json';
declare module '*.svg' {
  import React from 'react';
  import { SvgProps } from 'react-native-svg';
  const content: React.FC<SvgProps>;
  export default content;
}
```

4. **重命名文件扩展名**

将`.js`和`.jsx`文件扩展名更改为`.ts`和`.tsx`。

### 项目结构

一个组织良好的TypeScript React Native项目可能有以下结构：

```
my-app/
├── src/
│   ├── api/           # API调用和类型
│   ├── assets/        # 图片和资源文件
│   ├── components/    # 可重用组件
│   ├── hooks/         # 自定义Hooks
│   ├── navigation/    # 导航配置
│   ├── screens/       # 屏幕组件
│   ├── store/         # 状态管理
│   ├── types/         # 全局类型定义
│   ├── utils/         # 实用工具函数
│   └── App.tsx        # 主App组件
├── tsconfig.json      # TypeScript配置
├── package.json
└── ...
```

## 基本类型定义

TypeScript提供了多种内置类型，以下是在React Native开发中常用的类型：

### 基本数据类型

```typescript
// 基本类型
const name: string = "John Doe";
const age: number = 30;
const isActive: boolean = true;
const scores: number[] = [85, 92, 78]; // 数组类型
const user: { id: number; name: string } = { id: 1, name: "John" }; // 对象类型

// 联合类型
let id: string | number = 101; // 可以是字符串或数字
id = "A101"; // 有效

// 类型别名
type UserId = string | number;
let userId: UserId = 123;

// 枚举
enum UserRole {
  Admin = "ADMIN",
  Editor = "EDITOR",
  Viewer = "VIEWER"
}
const role: UserRole = UserRole.Admin;

// 可选属性
type UserProfile = {
  name: string;
  age: number;
  bio?: string; // 可选属性
};

const profile: UserProfile = {
  name: "Jane",
  age: 25
  // bio是可选的
};
```

### 函数类型

```typescript
// 函数类型
function greet(name: string): string {
  return `Hello, ${name}!`;
}

// 函数参数和返回值类型
const multiply = (a: number, b: number): number => a * b;

// 可选参数
function createUser(name: string, age?: number): void {
  console.log(`Creating user ${name} with age ${age || "unknown"}`);
}

// 带回调的函数类型
function fetchData(callback: (data: any) => void): void {
  // 获取数据...
  callback({ result: "success" });
}
```

### 泛型

泛型允许你创建可重用的组件，对多种类型起作用：

```typescript
// 泛型函数
function getFirstItem<T>(items: T[]): T | undefined {
  return items.length > 0 ? items[0] : undefined;
}

const firstNumber = getFirstItem<number>([1, 2, 3]); // 类型是number
const firstString = getFirstItem<string>(["a", "b", "c"]); // 类型是string

// 泛型接口
interface Repository<T> {
  getAll(): Promise<T[]>;
  getById(id: number): Promise<T>;
  create(item: Omit<T, "id">): Promise<T>;
  update(id: number, item: Partial<T>): Promise<T>;
  delete(id: number): Promise<boolean>;
}

// 使用泛型接口
interface User {
  id: number;
  name: string;
  email: string;
}

class UserRepository implements Repository<User> {
  // 实现Repository<User>接口的方法
  getAll(): Promise<User[]> {
    // 实现...
    return Promise.resolve([]);
  }
  // 其他方法实现...
}
```

## React组件类型

在React Native应用中，我们需要为组件、属性和状态定义类型。以下是React组件常见的类型定义方式：

### 函数组件

```typescript
import React, { FC } from 'react';
import { Text, View, StyleSheet } from 'react-native';

// 定义组件props的类型
interface GreetingProps {
  name: string;
  age?: number; // 可选属性
}

// 使用React.FC类型（包含了children属性）
const Greeting: FC<GreetingProps> = ({ name, age }) => {
  return (
    <View style={styles.container}>
      <Text style={styles.text}>
        Hello, {name}!{age ? ` You are ${age} years old.` : ''}
      </Text>
    </View>
  );
};

// 另一种函数组件定义方式
function GreetingAlt({ name, age }: GreetingProps): React.ReactElement {
  return (
    <View style={styles.container}>
      <Text style={styles.text}>
        Hello, {name}!{age ? ` You are ${age} years old.` : ''}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    padding: 16,
  },
  text: {
    fontSize: 18,
  },
});

export default Greeting;
```

### 类组件

```typescript
import React, { Component } from 'react';
import { Text, View, StyleSheet, Button } from 'react-native';

// 定义组件props的类型
interface CounterProps {
  initialCount: number;
  label: string;
}

// 定义组件state的类型
interface CounterState {
  count: number;
}

// 类组件使用泛型参数指定props和state的类型
class Counter extends Component<CounterProps, CounterState> {
  // 构造函数
  constructor(props: CounterProps) {
    super(props);
    this.state = {
      count: props.initialCount,
    };
  }

  // 类方法
  increment = (): void => {
    this.setState(prevState => ({
      count: prevState.count + 1,
    }));
  };

  decrement = (): void => {
    this.setState(prevState => ({
      count: prevState.count - 1,
    }));
  };

  render(): React.ReactNode {
    return (
      <View style={styles.container}>
        <Text style={styles.label}>{this.props.label}</Text>
        <Text style={styles.count}>Count: {this.state.count}</Text>
        <View style={styles.buttons}>
          <Button title="Increment" onPress={this.increment} />
          <Button title="Decrement" onPress={this.decrement} />
        </View>
      </View>
    );
  }
}

const styles = StyleSheet.create({
  container: {
    padding: 16,
    alignItems: 'center',
  },
  label: {
    fontSize: 16,
    marginBottom: 8,
  },
  count: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 16,
  },
  buttons: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    width: '100%',
  },
});

export default Counter;
```

### React.ReactNode 与 JSX.Element

在定义组件返回类型时，常见的类型有：

- `React.ReactNode`: 可以是任何可以渲染的内容，包括JSX、字符串、数字、数组、null或undefined
- `JSX.Element`: 专指JSX元素
- `React.ReactElement`: 专指React元素（通常由JSX编译而来）

```typescript
// ReactNode示例
function TextOrNumber({ value }: { value: string | number }): React.ReactNode {
  return typeof value === 'string' ? <Text>{value}</Text> : value;
}

// JSX.Element示例
function JustButton(): JSX.Element {
  return <Button title="Click me" onPress={() => {}} />;
}
```

### 默认Props

在TypeScript中设置默认props的方法：

```typescript
import React from 'react';
import { View, Text, StyleSheet } from 'react-native';

interface CardProps {
  title: string;
  subtitle?: string;
  elevation?: number;
  onPress?: () => void;
}

// 方式1：使用默认参数
const Card = ({
  title,
  subtitle = 'No subtitle',
  elevation = 2,
  onPress,
}: CardProps): JSX.Element => {
  return (
    <View style={[styles.card, { elevation }]} onTouchEnd={onPress}>
      <Text style={styles.title}>{title}</Text>
      <Text style={styles.subtitle}>{subtitle}</Text>
    </View>
  );
};

// 方式2：使用静态defaultProps（适用于类组件）
class CardClass extends React.Component<CardProps> {
  static defaultProps = {
    subtitle: 'No subtitle',
    elevation: 2,
  };

  render() {
    const { title, subtitle, elevation, onPress } = this.props;
    return (
      <View style={[styles.card, { elevation }]} onTouchEnd={onPress}>
        <Text style={styles.title}>{title}</Text>
        <Text style={styles.subtitle}>{subtitle}</Text>
      </View>
    );
  }
}

const styles = StyleSheet.create({
  card: {
    padding: 16,
    backgroundColor: '#fff',
    borderRadius: 8,
    marginVertical: 8,
  },
  title: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 8,
  },
  subtitle: {
    fontSize: 14,
    color: '#666',
  },
});

export default Card;
```

## 状态和属性类型

### React Hooks的类型

使用TypeScript与React Hooks需要正确定义类型：

#### useState

```typescript
import React, { useState } from 'react';
import { View, Text, Button, StyleSheet } from 'react-native';

const Counter = (): JSX.Element => {
  // 基本类型
  const [count, setCount] = useState<number>(0);
  
  // 对象类型
  const [user, setUser] = useState<{ name: string; age: number } | null>(null);
  
  // 联合类型
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');

  const incrementCounter = () => {
    setCount(prevCount => prevCount + 1);
  };

  const updateUser = () => {
    setUser({ name: 'Alice', age: 28 });
  };

  const changeStatus = () => {
    setStatus('loading');
    setTimeout(() => {
      setStatus('success');
    }, 2000);
  };

  return (
    <View style={styles.container}>
      <Text style={styles.text}>Count: {count}</Text>
      <Button title="Increment" onPress={incrementCounter} />
      
      {user ? (
        <Text style={styles.text}>User: {user.name}, {user.age}</Text>
      ) : (
        <Button title="Set User" onPress={updateUser} />
      )}
      
      <Text style={styles.text}>Status: {status}</Text>
      <Button title="Change Status" onPress={changeStatus} disabled={status !== 'idle'} />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 16,
  },
  text: {
    fontSize: 18,
    marginVertical: 16,
  },
});

export default Counter;
```

#### useEffect

```typescript
import React, { useState, useEffect } from 'react';
import { View, Text, ActivityIndicator, StyleSheet } from 'react-native';

interface User {
  id: number;
  name: string;
  email: string;
}

const UserProfile = ({ userId }: { userId: number }): JSX.Element => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // 声明一个异步函数
    const fetchUser = async (): Promise<void> => {
      try {
        setLoading(true);
        setError(null);
        
        // 模拟API调用
        const response = await fetch(`https://api.example.com/users/${userId}`);
        if (!response.ok) {
          throw new Error('Failed to fetch user');
        }
        
        const userData: User = await response.json();
        setUser(userData);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'An unknown error occurred');
      } finally {
        setLoading(false);
      }
    };

    fetchUser();
    
    // 清理函数
    return () => {
      // 取消请求或清理资源
    };
  }, [userId]);  // 依赖数组

  if (loading) {
    return (
      <View style={styles.centered}>
        <ActivityIndicator size="large" color="#0000ff" />
      </View>
    );
  }

  if (error) {
    return (
      <View style={styles.centered}>
        <Text style={styles.error}>Error: {error}</Text>
      </View>
    );
  }

  if (!user) {
    return (
      <View style={styles.centered}>
        <Text>No user found</Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <Text style={styles.title}>User Profile</Text>
      <Text style={styles.field}>ID: {user.id}</Text>
      <Text style={styles.field}>Name: {user.name}</Text>
      <Text style={styles.field}>Email: {user.email}</Text>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    padding: 16,
  },
  centered: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  title: {
    fontSize: 22,
    fontWeight: 'bold',
    marginBottom: 16,
  },
  field: {
    fontSize: 16,
    marginBottom: 8,
  },
  error: {
    color: 'red',
    fontSize: 16,
  },
});

export default UserProfile;
```

#### useReducer

```typescript
import React, { useReducer } from 'react';
import { View, Text, Button, StyleSheet } from 'react-native';

// 定义状态类型
interface CounterState {
  count: number;
  lastAction: string;
}

// 定义可能的Action类型
type CounterAction = 
  | { type: 'INCREMENT'; payload: number }
  | { type: 'DECREMENT'; payload: number }
  | { type: 'RESET' };

// Reducer函数
const counterReducer = (state: CounterState, action: CounterAction): CounterState => {
  switch (action.type) {
    case 'INCREMENT':
      return {
        ...state,
        count: state.count + action.payload,
        lastAction: `Incremented by ${action.payload}`
      };
    case 'DECREMENT':
      return {
        ...state,
        count: state.count - action.payload,
        lastAction: `Decremented by ${action.payload}`
      };
    case 'RESET':
      return {
        ...state,
        count: 0,
        lastAction: 'Reset'
      };
    default:
      return state;
  }
};

const AdvancedCounter = (): JSX.Element => {
  // 使用useReducer hook
  const [state, dispatch] = useReducer(counterReducer, {
    count: 0,
    lastAction: 'None'
  });

  return (
    <View style={styles.container}>
      <Text style={styles.count}>Count: {state.count}</Text>
      <Text style={styles.lastAction}>Last Action: {state.lastAction}</Text>
      
      <View style={styles.buttonsRow}>
        <Button
          title="+1"
          onPress={() => dispatch({ type: 'INCREMENT', payload: 1 })}
        />
        <Button
          title="+5"
          onPress={() => dispatch({ type: 'INCREMENT', payload: 5 })}
        />
      </View>
      
      <View style={styles.buttonsRow}>
        <Button
          title="-1"
          onPress={() => dispatch({ type: 'DECREMENT', payload: 1 })}
        />
        <Button
          title="-5"
          onPress={() => dispatch({ type: 'DECREMENT', payload: 5 })}
        />
      </View>
      
      <Button
        title="Reset"
        onPress={() => dispatch({ type: 'RESET' })}
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 16,
  },
  count: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 8,
  },
  lastAction: {
    fontSize: 16,
    marginBottom: 24,
    fontStyle: 'italic',
  },
  buttonsRow: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    width: '60%',
    marginBottom: 16,
  },
});

export default AdvancedCounter;
```

#### useRef

```typescript
import React, { useRef, useState, useEffect } from 'react';
import { TextInput, Button, View, Text, StyleSheet } from 'react-native';

const AutoFocusInput = (): JSX.Element => {
  // 使用泛型参数指定ref的类型
  const inputRef = useRef<TextInput>(null);
  const [text, setText] = useState<string>('');
  const [submittedText, setSubmittedText] = useState<string>('');
  
  // 计时器ref不需要初始化值，因此使用null联合类型
  const timerRef = useRef<NodeJS.Timeout | null>(null);
  
  // 使用ref存储不触发重渲染的值
  const submissionCountRef = useRef<number>(0);

  // 组件挂载时自动聚焦输入框
  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.focus();
    }
    
    // 清理函数
    return () => {
      if (timerRef.current) {
        clearTimeout(timerRef.current);
      }
    };
  }, []);

  const handleSubmit = (): void => {
    setSubmittedText(text);
    setText('');
    submissionCountRef.current += 1;
    
    // 聚焦输入框
    if (inputRef.current) {
      inputRef.current.focus();
    }
    
    // 设置定时器
    timerRef.current = setTimeout(() => {
      console.log(`You have submitted ${submissionCountRef.current} times.`);
    }, 2000);
  };

  return (
    <View style={styles.container}>
      <TextInput
        ref={inputRef}
        style={styles.input}
        value={text}
        onChangeText={setText}
        placeholder="Type something..."
      />
      <Button title="Submit" onPress={handleSubmit} disabled={!text} />
      
      {submittedText ? (
        <Text style={styles.submittedText}>
          You submitted: {submittedText}
        </Text>
      ) : null}
      
      <Text style={styles.counter}>
        Submission count: {submissionCountRef.current}
      </Text>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    padding: 16,
  },
  input: {
    borderWidth: 1,
    borderColor: '#ccc',
    borderRadius: 4,
    padding: 8,
    marginBottom: 16,
  },
  submittedText: {
    marginTop: 16,
    fontSize: 16,
  },
  counter: {
    marginTop: 8,
    fontSize: 14,
    fontStyle: 'italic',
  },
});

export default AutoFocusInput;
```

### 自定义Hooks类型

TypeScript可以很好地与自定义Hooks配合使用：

```typescript
import { useState, useEffect } from 'react';

// 定义Hook的返回类型
interface UseLocalStorageReturn<T> {
  value: T;
  setValue: (value: T) => void;
  error: Error | null;
}

// 通用本地存储钩子
function useLocalStorage<T>(key: string, initialValue: T): UseLocalStorageReturn<T> {
  const [value, setValue] = useState<T>(initialValue);
  const [error, setError] = useState<Error | null>(null);

  // 从本地存储加载数据
  useEffect(() => {
    try {
      const item = localStorage.getItem(key);
      if (item) {
        setValue(JSON.parse(item));
      }
    } catch (e) {
      console.error('Error loading from localStorage:', e);
      setError(e instanceof Error ? e : new Error('Unknown error'));
    }
  }, [key]);

  // 保存数据到本地存储
  const updateValue = (newValue: T): void => {
    try {
      setValue(newValue);
      localStorage.setItem(key, JSON.stringify(newValue));
      setError(null);
    } catch (e) {
      console.error('Error saving to localStorage:', e);
      setError(e instanceof Error ? e : new Error('Unknown error'));
    }
  };

  return { value, setValue: updateValue, error };
}

export default useLocalStorage;
``` 

## 事件处理类型

React Native的事件处理需要适当的类型定义，以确保类型安全。

### 基本事件处理

```typescript
import React, { useState } from 'react';
import { View, Button, Text, TextInput, StyleSheet } from 'react-native';

const EventHandlingExample = (): JSX.Element => {
  const [text, setText] = useState<string>('');
  
  // 简单的事件处理函数
  const handlePress = (): void => {
    console.log('Button pressed!');
    alert('Button was pressed');
  };

  // 带参数的事件处理函数
  const handlePressWithParam = (message: string): void => {
    console.log(message);
    alert(message);
  };

  // 处理文本输入变化
  const handleTextChange = (value: string): void => {
    setText(value);
  };

  return (
    <View style={styles.container}>
      <Button
        title="Press Me"
        onPress={handlePress}
      />
      
      <Button
        title="Press With Param"
        onPress={() => handlePressWithParam('Button with parameter pressed!')}
      />
      
      <TextInput
        style={styles.input}
        onChangeText={handleTextChange}
        value={text}
        placeholder="Type something..."
      />
      
      <Text style={styles.text}>You typed: {text}</Text>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 16,
    justifyContent: 'center',
    gap: 16,
  },
  input: {
    height: 40,
    borderWidth: 1,
    borderColor: '#ccc',
    borderRadius: 4,
    paddingHorizontal: 8,
    marginVertical: 16,
  },
  text: {
    fontSize: 16,
  },
});

export default EventHandlingExample;
```

### React Native触摸事件

```typescript
import React from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  TouchableHighlight,
  GestureResponderEvent,
  StyleSheet,
} from 'react-native';

const TouchableExample = (): JSX.Element => {
  // 基本触摸事件处理函数
  const handlePress = (): void => {
    console.log('Pressed!');
  };

  // 使用事件参数
  const handlePressWithEvent = (event: GestureResponderEvent): void => {
    // 可以访问事件信息
    console.log('Press location:', event.nativeEvent.locationX, event.nativeEvent.locationY);
  };

  // 长按处理函数
  const handleLongPress = (): void => {
    console.log('Long pressed!');
  };

  return (
    <View style={styles.container}>
      <TouchableOpacity
        style={styles.button}
        onPress={handlePress}
        activeOpacity={0.7}
      >
        <Text style={styles.buttonText}>TouchableOpacity</Text>
      </TouchableOpacity>

      <TouchableHighlight
        style={styles.button}
        onPress={handlePressWithEvent}
        onLongPress={handleLongPress}
        underlayColor="#DDDDDD"
      >
        <Text style={styles.buttonText}>TouchableHighlight (with event)</Text>
      </TouchableHighlight>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    padding: 16,
    gap: 16,
  },
  button: {
    backgroundColor: '#007AFF',
    padding: 16,
    borderRadius: 8,
    alignItems: 'center',
  },
  buttonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: 'bold',
  },
});

export default TouchableExample;
```

### 自定义事件Props

你可以创建自定义事件props类型：

```typescript
import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet } from 'react-native';

// 定义自定义事件处理器类型
type PressHandler = () => void;
type ItemPressHandler = (id: number, name: string) => void;

// 组件Props接口
interface CustomButtonProps {
  title: string;
  onPress: PressHandler;
  color?: string;
}

// 简单按钮组件
const CustomButton = ({ title, onPress, color = '#007AFF' }: CustomButtonProps): JSX.Element => (
  <TouchableOpacity
    style={[styles.button, { backgroundColor: color }]}
    onPress={onPress}
  >
    <Text style={styles.buttonText}>{title}</Text>
  </TouchableOpacity>
);

// 列表项组件Props
interface ListItemProps {
  id: number;
  name: string;
  onItemPress: ItemPressHandler;
}

// 列表项组件
const ListItem = ({ id, name, onItemPress }: ListItemProps): JSX.Element => (
  <TouchableOpacity
    style={styles.listItem}
    onPress={() => onItemPress(id, name)}
  >
    <Text style={styles.itemText}>
      {id}: {name}
    </Text>
  </TouchableOpacity>
);

// 使用组件的父组件
const EventPropsExample = (): JSX.Element => {
  const handleButtonPress = (): void => {
    alert('Button pressed!');
  };

  const handleItemPress = (id: number, name: string): void => {
    alert(`Item ${id} (${name}) was pressed!`);
  };

  return (
    <View style={styles.container}>
      <CustomButton title="Press Me" onPress={handleButtonPress} />
      
      <CustomButton 
        title="Secondary Button" 
        onPress={() => console.log('Secondary pressed')} 
        color="#5856D6" 
      />
      
      <Text style={styles.header}>Items List:</Text>
      
      <ListItem id={1} name="Item One" onItemPress={handleItemPress} />
      <ListItem id={2} name="Item Two" onItemPress={handleItemPress} />
      <ListItem id={3} name="Item Three" onItemPress={handleItemPress} />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 16,
    gap: 8,
  },
  button: {
    padding: 12,
    borderRadius: 8,
    alignItems: 'center',
    marginVertical: 8,
  },
  buttonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: 'bold',
  },
  header: {
    fontSize: 20,
    fontWeight: 'bold',
    marginTop: 20,
    marginBottom: 12,
  },
  listItem: {
    padding: 12,
    borderWidth: 1,
    borderColor: '#ccc',
    borderRadius: 6,
    marginBottom: 8,
  },
  itemText: {
    fontSize: 16,
  },
});

export default EventPropsExample;
```

## API响应类型

在React Native应用中，通常需要从API获取数据。使用TypeScript可以更好地处理API响应。

### 基本API类型

```typescript
// types/api.ts
// 定义API响应类型

export interface User {
  id: number;
  name: string;
  email: string;
  avatar: string;
  role: 'admin' | 'user' | 'guest';
  createdAt: string;
}

export interface Post {
  id: number;
  title: string;
  body: string;
  userId: number;
  tags: string[];
  createdAt: string;
  updatedAt: string;
}

export interface Comment {
  id: number;
  postId: number;
  name: string;
  email: string;
  body: string;
}

// 分页响应类型
export interface PaginatedResponse<T> {
  data: T[];
  meta: {
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  };
}

// API错误响应
export interface ApiError {
  message: string;
  code: number;
  errors?: Record<string, string[]>;
}
```

### 使用API类型

```typescript
// api/users.ts
import { User, PaginatedResponse, ApiError } from '../types/api';

interface GetUsersParams {
  page?: number;
  limit?: number;
  search?: string;
}

export async function getUsers(
  params: GetUsersParams = {}
): Promise<PaginatedResponse<User>> {
  try {
    const queryParams = new URLSearchParams();
    
    if (params.page) {
      queryParams.append('page', params.page.toString());
    }
    
    if (params.limit) {
      queryParams.append('limit', params.limit.toString());
    }
    
    if (params.search) {
      queryParams.append('search', params.search);
    }
    
    const url = `https://api.example.com/users?${queryParams.toString()}`;
    const response = await fetch(url);
    
    if (!response.ok) {
      const errorData: ApiError = await response.json();
      throw new Error(errorData.message || 'Failed to fetch users');
    }
    
    const data: PaginatedResponse<User> = await response.json();
    return data;
  } catch (error) {
    throw error instanceof Error
      ? error
      : new Error('An unknown error occurred');
  }
}

export async function getUserById(id: number): Promise<User> {
  try {
    const response = await fetch(`https://api.example.com/users/${id}`);
    
    if (!response.ok) {
      const errorData: ApiError = await response.json();
      throw new Error(errorData.message || `Failed to fetch user ${id}`);
    }
    
    const user: User = await response.json();
    return user;
  } catch (error) {
    throw error instanceof Error
      ? error
      : new Error('An unknown error occurred');
  }
}

// 创建用户参数
export interface CreateUserParams {
  name: string;
  email: string;
  role: 'admin' | 'user' | 'guest';
}

export async function createUser(userData: CreateUserParams): Promise<User> {
  try {
    const response = await fetch('https://api.example.com/users', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(userData),
    });
    
    if (!response.ok) {
      const errorData: ApiError = await response.json();
      throw new Error(errorData.message || 'Failed to create user');
    }
    
    const newUser: User = await response.json();
    return newUser;
  } catch (error) {
    throw error instanceof Error
      ? error
      : new Error('An unknown error occurred');
  }
}
```

### 在组件中使用API

```typescript
import React, { useState, useEffect } from 'react';
import { View, Text, FlatList, ActivityIndicator, StyleSheet } from 'react-native';
import { getUsers } from '../api/users';
import { User, PaginatedResponse } from '../types/api';

const UsersList = (): JSX.Element => {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState<number>(1);
  const [meta, setMeta] = useState<PaginatedResponse<User>['meta'] | null>(null);

  useEffect(() => {
    fetchUsers();
  }, [page]);

  const fetchUsers = async (): Promise<void> => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await getUsers({ page, limit: 10 });
      
      setUsers(prev => page === 1 ? response.data : [...prev, ...response.data]);
      setMeta(response.meta);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred');
    } finally {
      setLoading(false);
    }
  };

  const loadMore = (): void => {
    if (meta && page < meta.totalPages && !loading) {
      setPage(page + 1);
    }
  };

  const renderUserItem = ({ item }: { item: User }): JSX.Element => (
    <View style={styles.userItem}>
      <Text style={styles.userName}>{item.name}</Text>
      <Text style={styles.userEmail}>{item.email}</Text>
      <Text style={styles.userRole}>{item.role}</Text>
    </View>
  );

  if (error) {
    return (
      <View style={styles.centered}>
        <Text style={styles.error}>Error: {error}</Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Users List</Text>
      
      <FlatList
        data={users}
        keyExtractor={(item) => item.id.toString()}
        renderItem={renderUserItem}
        onEndReached={loadMore}
        onEndReachedThreshold={0.2}
        ListFooterComponent={loading ? <ActivityIndicator size="large" color="#0000ff" /> : null}
        ListEmptyComponent={!loading ? <Text style={styles.emptyText}>No users found</Text> : null}
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 16,
  },
  centered: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 16,
  },
  userItem: {
    padding: 12,
    borderBottomWidth: 1,
    borderBottomColor: '#eee',
  },
  userName: {
    fontSize: 18,
    fontWeight: 'bold',
  },
  userEmail: {
    fontSize: 14,
    marginTop: 4,
  },
  userRole: {
    fontSize: 12,
    color: '#666',
    marginTop: 2,
    textTransform: 'capitalize',
  },
  error: {
    color: 'red',
    fontSize: 16,
  },
  emptyText: {
    textAlign: 'center',
    marginTop: 20,
    fontSize: 16,
  },
});

export default UsersList;
```

### 使用泛型API服务

创建通用的API服务类：

```typescript
// api/apiService.ts
import { ApiError } from '../types/api';

class ApiService {
  private baseUrl: string;
  
  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }
  
  // 通用GET方法
  async get<T>(path: string, params?: Record<string, string | number>): Promise<T> {
    try {
      let url = `${this.baseUrl}${path}`;
      
      if (params) {
        const queryParams = new URLSearchParams();
        Object.entries(params).forEach(([key, value]) => {
          queryParams.append(key, value.toString());
        });
        url += `?${queryParams.toString()}`;
      }
      
      const response = await fetch(url);
      
      if (!response.ok) {
        const errorData: ApiError = await response.json();
        throw new Error(errorData.message || `API Error: ${response.status}`);
      }
      
      return await response.json() as T;
    } catch (error) {
      throw error instanceof Error
        ? error
        : new Error('An unknown error occurred');
    }
  }
  
  // 通用POST方法
  async post<T, D = unknown>(path: string, data: D): Promise<T> {
    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      });
      
      if (!response.ok) {
        const errorData: ApiError = await response.json();
        throw new Error(errorData.message || `API Error: ${response.status}`);
      }
      
      return await response.json() as T;
    } catch (error) {
      throw error instanceof Error
        ? error
        : new Error('An unknown error occurred');
    }
  }
  
  // 通用PUT方法
  async put<T, D = unknown>(path: string, data: D): Promise<T> {
    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      });
      
      if (!response.ok) {
        const errorData: ApiError = await response.json();
        throw new Error(errorData.message || `API Error: ${response.status}`);
      }
      
      return await response.json() as T;
    } catch (error) {
      throw error instanceof Error
        ? error
        : new Error('An unknown error occurred');
    }
  }
  
  // 通用DELETE方法
  async delete<T>(path: string): Promise<T> {
    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method: 'DELETE',
      });
      
      if (!response.ok) {
        const errorData: ApiError = await response.json();
        throw new Error(errorData.message || `API Error: ${response.status}`);
      }
      
      return await response.json() as T;
    } catch (error) {
      throw error instanceof Error
        ? error
        : new Error('An unknown error occurred');
    }
  }
}

// 导出一个实例
export const apiService = new ApiService('https://api.example.com');
``` 

## 导航类型

React Navigation是React Native中最流行的导航库，与TypeScript搭配使用需要适当的类型定义。

### 安装与配置

首先安装React Navigation及其TypeScript类型：

```bash
npm install @react-navigation/native react-native-screens react-native-safe-area-context
npm install @react-navigation/stack @react-navigation/bottom-tabs @react-navigation/drawer
npm install react-native-gesture-handler react-native-reanimated
```

### 定义导航参数类型

```typescript
// types/navigation.ts
import { RouteProp } from '@react-navigation/native';
import { StackNavigationProp } from '@react-navigation/stack';

// 定义所有可能的路由参数
export type RootStackParamList = {
  Home: undefined;
  Profile: { userId: number; username: string };
  Settings: undefined;
  PostDetails: { postId: number; title: string };
  CreatePost: { categoryId?: number } | undefined;
};

// 创建特定屏幕的导航属性类型
export type HomeScreenNavigationProp = StackNavigationProp<RootStackParamList, 'Home'>;
export type ProfileScreenNavigationProp = StackNavigationProp<RootStackParamList, 'Profile'>;
export type PostDetailsScreenNavigationProp = StackNavigationProp<RootStackParamList, 'PostDetails'>;

// 创建特定屏幕的路由属性类型
export type ProfileScreenRouteProp = RouteProp<RootStackParamList, 'Profile'>;
export type PostDetailsScreenRouteProp = RouteProp<RootStackParamList, 'PostDetails'>;
export type CreatePostScreenRouteProp = RouteProp<RootStackParamList, 'CreatePost'>;

// 屏幕Props类型
export interface ProfileScreenProps {
  navigation: ProfileScreenNavigationProp;
  route: ProfileScreenRouteProp;
}

export interface PostDetailsScreenProps {
  navigation: PostDetailsScreenNavigationProp;
  route: PostDetailsScreenRouteProp;
}
```

### 设置导航器

```typescript
// navigation/RootNavigator.tsx
import React from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createStackNavigator } from '@react-navigation/stack';
import { RootStackParamList } from '../types/navigation';

// 导入屏幕组件
import HomeScreen from '../screens/HomeScreen';
import ProfileScreen from '../screens/ProfileScreen';
import SettingsScreen from '../screens/SettingsScreen';
import PostDetailsScreen from '../screens/PostDetailsScreen';
import CreatePostScreen from '../screens/CreatePostScreen';

// 创建带类型的导航器
const Stack = createStackNavigator<RootStackParamList>();

export const RootNavigator = (): JSX.Element => {
  return (
    <NavigationContainer>
      <Stack.Navigator initialRouteName="Home">
        <Stack.Screen 
          name="Home" 
          component={HomeScreen} 
          options={{ title: '首页' }}
        />
        <Stack.Screen 
          name="Profile" 
          component={ProfileScreen} 
          options={({ route }) => ({ title: `${route.params.username}的资料` })}
        />
        <Stack.Screen 
          name="Settings" 
          component={SettingsScreen}
          options={{ title: '设置' }}
        />
        <Stack.Screen 
          name="PostDetails" 
          component={PostDetailsScreen}
          options={({ route }) => ({ title: route.params.title })}
        />
        <Stack.Screen 
          name="CreatePost" 
          component={CreatePostScreen}
          options={{ title: '创建文章' }}
        />
      </Stack.Navigator>
    </NavigationContainer>
  );
};
```

### 使用导航类型

```typescript
// screens/HomeScreen.tsx
import React from 'react';
import { View, Button, StyleSheet } from 'react-native';
import { useNavigation } from '@react-navigation/native';
import { HomeScreenNavigationProp } from '../types/navigation';

const HomeScreen = (): JSX.Element => {
  // 使用类型化的导航
  const navigation = useNavigation<HomeScreenNavigationProp>();

  const navigateToProfile = (): void => {
    navigation.navigate('Profile', { userId: 1, username: 'JohnDoe' });
  };

  const navigateToSettings = (): void => {
    navigation.navigate('Settings');
  };

  const navigateToPostDetails = (): void => {
    navigation.navigate('PostDetails', { postId: 101, title: '示例文章标题' });
  };

  const navigateToCreatePost = (): void => {
    navigation.navigate('CreatePost');
  };

  return (
    <View style={styles.container}>
      <Button title="查看个人资料" onPress={navigateToProfile} />
      <Button title="进入设置" onPress={navigateToSettings} />
      <Button title="查看文章详情" onPress={navigateToPostDetails} />
      <Button title="创建新文章" onPress={navigateToCreatePost} />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    padding: 16,
    gap: 16,
  },
});

export default HomeScreen;
```

```typescript
// screens/ProfileScreen.tsx
import React, { useEffect, useState } from 'react';
import { View, Text, Button, StyleSheet } from 'react-native';
import { ProfileScreenProps } from '../types/navigation';

// 使用类型化的Props
const ProfileScreen = ({ navigation, route }: ProfileScreenProps): JSX.Element => {
  const { userId, username } = route.params;
  const [userDetails, setUserDetails] = useState<{ bio: string } | null>(null);

  useEffect(() => {
    // 模拟获取用户数据
    const fetchUserDetails = (): void => {
      // 实际应用中这里会调用API
      setTimeout(() => {
        setUserDetails({ bio: '这是用户的个人简介' });
      }, 500);
    };

    fetchUserDetails();
  }, [userId]);

  return (
    <View style={styles.container}>
      <Text style={styles.username}>{username}</Text>
      <Text style={styles.userId}>用户ID: {userId}</Text>
      
      {userDetails ? (
        <Text style={styles.bio}>{userDetails.bio}</Text>
      ) : (
        <Text>加载中...</Text>
      )}
      
      <Button title="返回首页" onPress={() => navigation.navigate('Home')} />
      <Button title="进入设置" onPress={() => navigation.navigate('Settings')} />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 16,
    gap: 16,
  },
  username: {
    fontSize: 24,
    fontWeight: 'bold',
  },
  userId: {
    fontSize: 16,
    color: '#666',
  },
  bio: {
    fontSize: 16,
    marginTop: 8,
  },
});

export default ProfileScreen;
```

### 选项卡导航类型

```typescript
// types/navigation.ts (添加)
import { BottomTabNavigationProp } from '@react-navigation/bottom-tabs';

export type MainTabParamList = {
  HomeTab: undefined;
  Discover: undefined;
  Messages: undefined;
  Notifications: { hasUnread?: boolean };
  Profile: { userId: number };
};

export type HomeTabScreenNavigationProp = BottomTabNavigationProp<MainTabParamList, 'HomeTab'>;
export type NotificationsScreenNavigationProp = BottomTabNavigationProp<MainTabParamList, 'Notifications'>;
export type NotificationsScreenRouteProp = RouteProp<MainTabParamList, 'Notifications'>;
```

```typescript
// navigation/TabNavigator.tsx
import React from 'react';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import Icon from 'react-native-vector-icons/MaterialIcons';
import { MainTabParamList } from '../types/navigation';

// 导入屏幕组件
import HomeTabScreen from '../screens/HomeTabScreen';
import DiscoverScreen from '../screens/DiscoverScreen';
import MessagesScreen from '../screens/MessagesScreen';
import NotificationsScreen from '../screens/NotificationsScreen';
import ProfileTabScreen from '../screens/ProfileTabScreen';

const Tab = createBottomTabNavigator<MainTabParamList>();

export const TabNavigator = (): JSX.Element => {
  return (
    <Tab.Navigator
      screenOptions={{
        tabBarActiveTintColor: '#007AFF',
      }}
    >
      <Tab.Screen
        name="HomeTab"
        component={HomeTabScreen}
        options={{
          title: '首页',
          tabBarIcon: ({ color, size }) => (
            <Icon name="home" size={size} color={color} />
          ),
        }}
      />
      <Tab.Screen
        name="Discover"
        component={DiscoverScreen}
        options={{
          title: '发现',
          tabBarIcon: ({ color, size }) => (
            <Icon name="explore" size={size} color={color} />
          ),
        }}
      />
      <Tab.Screen
        name="Messages"
        component={MessagesScreen}
        options={{
          title: '消息',
          tabBarIcon: ({ color, size }) => (
            <Icon name="chat" size={size} color={color} />
          ),
        }}
      />
      <Tab.Screen
        name="Notifications"
        component={NotificationsScreen}
        options={{
          title: '通知',
          tabBarIcon: ({ color, size }) => (
            <Icon name="notifications" size={size} color={color} />
          ),
        }}
      />
      <Tab.Screen
        name="Profile"
        component={ProfileTabScreen}
        initialParams={{ userId: 1 }}
        options={{
          title: '我的',
          tabBarIcon: ({ color, size }) => (
            <Icon name="person" size={size} color={color} />
          ),
        }}
      />
    </Tab.Navigator>
  );
};
```

## 常见问题与解决方案

### any类型的使用

TypeScript中的`any`类型会绕过类型检查，应尽量避免使用。下面是一些常见情况的替代方案：

#### 未知数据类型

当不确定数据类型时，使用`unknown`而不是`any`：

```typescript
// 不好的做法
function processData(data: any) {
  data.someProperty.nestedProperty(); // 运行时可能出错
}

// 好的做法
function processData(data: unknown) {
  // 需要类型守卫
  if (
    typeof data === 'object' && 
    data !== null && 
    'someProperty' in data && 
    typeof (data as any).someProperty === 'object'
  ) {
    // 现在可以安全访问
    const prop = (data as { someProperty: object }).someProperty;
    // 进一步处理...
  }
}
```

#### 第三方库无类型定义

对于没有类型定义的库，创建声明文件：

```typescript
// declarations.d.ts
declare module 'untyped-library' {
  export function doSomething(param: string): number;
  export class Helper {
    constructor(options: { debug: boolean });
    public assist(input: string): Promise<string>;
  }
  // ... 其他导出
}
```

### 类型断言

类型断言用于告诉编译器某个值的类型。使用两种语法：

```typescript
// 使用as
const value: unknown = "Hello, TypeScript";
const length: number = (value as string).length;

// 使用<>语法 (JSX中不能使用)
const value: unknown = "Hello, TypeScript";
const length: number = (<string>value).length;
```

但要避免不必要的类型断言，特别是断言为`any`类型：

```typescript
// 不好的做法 - 不安全
const userInput = getUserInput() as any;
sendToServer(userInput.sensitiveField);

// 好的做法 - 使用类型守卫
const userInput = getUserInput();
if (isValidInput(userInput)) {
  sendToServer(userInput.sensitiveField);
}

// 类型守卫函数
function isValidInput(input: unknown): input is { sensitiveField: string } {
  return (
    typeof input === 'object' &&
    input !== null &&
    'sensitiveField' in input &&
    typeof (input as any).sensitiveField === 'string'
  );
}
```

### 配置文件问题

常见的`tsconfig.json`配置问题及解决方案：

#### 路径别名

设置路径别名简化导入语句：

```json
{
  "compilerOptions": {
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"],
      "@components/*": ["src/components/*"],
      "@screens/*": ["src/screens/*"],
      "@utils/*": ["src/utils/*"]
    }
  }
}
```

还需要在Babel配置中添加：

```javascript
// babel.config.js
module.exports = {
  plugins: [
    [
      'module-resolver',
      {
        root: ['./src'],
        extensions: ['.ios.js', '.android.js', '.js', '.ts', '.tsx', '.json'],
        alias: {
          '@': './src',
          '@components': './src/components',
          '@screens': './src/screens',
          '@utils': './src/utils'
        }
      }
    ]
  ]
};
```

#### 严格模式设置

启用严格模式可以发现更多潜在问题：

```json
{
  "compilerOptions": {
    "strict": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "strictFunctionTypes": true,
    "strictBindCallApply": true,
    "strictPropertyInitialization": true,
    "noImplicitThis": true,
    "alwaysStrict": true
  }
}
```

### 第三方库的类型问题

有时第三方库的类型定义不完整或不正确，可以通过模块扩展解决：

```typescript
// types/augmentations.d.ts

// 扩展现有模块
import 'react-native-some-library';

declare module 'react-native-some-library' {
  export interface ComponentProps {
    // 添加缺少的属性
    additionalProp?: string;
  }
  
  // 添加缺少的函数
  export function missingFunction(param: string): void;
}
```

## 最佳实践

### 项目结构

为TypeScript React Native项目推荐的结构：

```
src/
├── api/                 # API调用和服务
├── assets/              # 静态资源
├── components/          # 可重用组件
│   ├── Button/
│   │   ├── Button.tsx
│   │   ├── Button.styles.ts
│   │   └── index.ts
│   └── ...
├── hooks/               # 自定义Hooks
├── navigation/          # 导航配置
├── screens/             # 屏幕组件
├── store/               # 状态管理
│   ├── slices/
│   └── index.ts
├── types/               # 类型定义
│   ├── api.ts
│   ├── navigation.ts
│   └── ...
├── utils/               # 工具函数
└── App.tsx              # 入口组件
```

### 命名约定

使用一致的命名约定增强代码可读性：

- 接口: `IPrefixOrPascalCase` 或简单 `PascalCase`
- 类型: `TPrefixOrPascalCase` 或简单 `PascalCase`
- 枚举: `EPrefixOrPascalCase` 或简单 `PascalCase`
- 常量: `SCREAMING_SNAKE_CASE`
- 函数和变量: `camelCase`
- 组件: `PascalCase`
- 文件命名: 组件使用`PascalCase`，其他使用`camelCase`

### 类型安全技巧

#### 使用字面量类型和联合类型

```typescript
// 定义有限的选项集
type ButtonVariant = 'primary' | 'secondary' | 'outline' | 'ghost';
type ButtonSize = 'small' | 'medium' | 'large';

interface ButtonProps {
  variant: ButtonVariant;
  size: ButtonSize;
}
```

#### 使用泛型增强可重用性

```typescript
// 通用列表组件
interface ListProps<T> {
  items: T[];
  renderItem: (item: T) => React.ReactNode;
  keyExtractor: (item: T) => string;
}

function List<T>({ items, renderItem, keyExtractor }: ListProps<T>) {
  return (
    <>
      {items.map(item => (
        <View key={keyExtractor(item)}>
          {renderItem(item)}
        </View>
      ))}
    </>
  );
}

// 使用
<List
  items={users}
  renderItem={(user) => <UserItem user={user} />}
  keyExtractor={(user) => user.id.toString()}
/>
```

#### 使用Record类型

```typescript
// 定义对象映射
type UserRoles = Record<string, 'admin' | 'editor' | 'viewer'>;

const userRoles: UserRoles = {
  'user1': 'admin',
  'user2': 'editor',
  'user3': 'viewer'
};
```

#### 使用索引签名

```typescript
// 动态属性
interface Config {
  apiUrl: string;
  timeout: number;
  [key: string]: string | number | boolean; // 允许额外的属性
}

const config: Config = {
  apiUrl: 'https://api.example.com',
  timeout: 3000,
  enableCache: true,  // 有效，因为boolean匹配索引签名
  retryCount: 3       // 有效，因为number匹配索引签名
};
```

#### 条件类型

```typescript
// 根据条件选择类型
type IsArray<T> = T extends any[] ? true : false;

type Result1 = IsArray<string[]>;  // true
type Result2 = IsArray<number>;    // false

// 实用条件类型
type NonNullable<T> = T extends null | undefined ? never : T;

type Result3 = NonNullable<string | null | undefined>;  // string
```

### 调试TypeScript

在React Native项目中调试TypeScript：

1. 使用Source Maps
2. 配置VSCode调试
3. 使用TypeScript编译器的`--generateTrace`选项分析编译性能

```json
// tsconfig.json
{
  "compilerOptions": {
    "sourceMap": true
  }
}
```

```json
// .vscode/launch.json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug React Native",
      "request": "launch",
      "type": "reactnative",
      "cwd": "${workspaceFolder}",
      "enableDebug": true,
      "platform": "android"
    }
  ]
}
```

### 性能考虑

TypeScript在开发时可能会影响热重载性能。一些优化技巧：

1. 使用项目引用(Project References)分割大型项目
2. 启用增量编译
3. 优化`tsconfig.json`配置

```json
// tsconfig.json 优化配置
{
  "compilerOptions": {
    "incremental": true,
    "tsBuildInfoFile": "./.tsbuildinfo",
    "skipLibCheck": true
  }
}
```

### 代码质量工具

结合TypeScript使用代码质量工具：

1. **ESLint**
   - 安装: `npm install --save-dev eslint @typescript-eslint/parser @typescript-eslint/eslint-plugin`
   - 配置`.eslintrc.js`

2. **Prettier**
   - 安装: `npm install --save-dev prettier`
   - 配置`.prettierrc`

3. **Husky**和**lint-staged**
   - 安装: `npm install --save-dev husky lint-staged`
   - 配置提交前的代码检查

```json
// package.json
{
  "husky": {
    "hooks": {
      "pre-commit": "lint-staged"
    }
  },
  "lint-staged": {
    "*.{js,ts,tsx}": [
      "eslint --fix",
      "prettier --write",
      "git add"
    ]
  }
}
```

通过遵循这些最佳实践，你可以充分利用TypeScript的优势，编写更加健壮、可维护的React Native应用。 