# React Native入门指南

React Native是一个开源的移动应用开发框架，由Facebook开发，允许使用JavaScript和React构建真正的原生移动应用。本文档提供了React Native的基础知识，包括环境搭建和核心组件的使用。

## 目录

- [React Native简介](#react-native简介)
- [环境搭建](#环境搭建)
- [基础组件](#基础组件)
- [导航与路由](#导航与路由)
- [状态管理](#状态管理)
- [网络请求](#网络请求)
- [性能优化](#性能优化)
- [动画与手势](#动画与手势)
- [本地存储](#本地存储)
- [原生模块集成](#原生模块集成)
- [部署与发布](#部署与发布)

## React Native简介

### 什么是React Native？

React Native是一个允许开发者使用JavaScript和React构建移动应用的框架。它与传统混合应用不同，React Native不使用WebView，而是将JavaScript代码转换为原生视图组件，使应用具有与原生应用相同的外观和性能。

React Native的主要特点：

- **跨平台开发**：一套代码可同时运行在iOS和Android平台
- **原生性能**：渲染真正的原生UI组件，而非WebView
- **热重载**：支持实时预览代码更改，加速开发流程
- **大型社区**：活跃的开发者社区和丰富的第三方库
- **基于React**：使用与React相同的组件化开发模式

### React Native与其他框架对比

| 框架 | 优势 | 劣势 | 适用场景 |
|------|------|------|----------|
| **React Native** | 原生UI组件、开发效率高、社区活跃 | 复杂原生功能需要桥接、学习曲线 | 需要原生体验的跨平台应用 |
| **Flutter** | 高性能、统一UI渲染、热重载 | Dart语言普及度低、包体积较大 | UI密集型应用、品牌定制应用 |
| **原生开发** | 完全访问平台API、最佳性能 | 需要维护两套代码、开发成本高 | 高性能要求、平台特定功能 |
| **PWA/WebView** | 开发简单、跨平台、更新容易 | 性能较差、用户体验有限 | 内容为主的简单应用 |

### React Native的工作原理

React Native的架构基于三个主要部分：

1. **JavaScript线程**：运行React/JavaScript代码
2. **主线程（UI线程）**：负责UI渲染和用户交互
3. **桥接层**：连接JavaScript和原生代码

工作流程：
1. JavaScript代码通过React声明UI结构
2. 这些声明通过桥接层传递给原生平台
3. 原生平台将这些声明转换为真正的原生视图
4. 用户交互从原生视图发送回JavaScript进行处理

React Native正在实施新架构（Fabric和TurboModules），以改进性能和开发体验。

## 环境搭建

### 系统要求

**基础要求**:
- Node.js（推荐v16或更高版本）
- npm或Yarn
- Git

**iOS开发**（仅macOS）:
- macOS
- Xcode（最新版本）
- CocoaPods

**Android开发**:
- Java Development Kit (JDK 11或更高)
- Android Studio
- Android SDK

### 安装方法

React Native提供了两种主要的开发方式：

#### 方法1：使用Expo CLI（推荐新手）

Expo是一个围绕React Native构建的工具集，简化了开发流程：

```bash
# 安装Expo CLI
npm install -g expo-cli

# 创建新项目
expo init MyFirstApp

# 选择模板（如"blank"、"blank (TypeScript)"等）

# 启动项目
cd MyFirstApp
npm start
```

优点：
- 设置简单
- 无需安装Android Studio或Xcode
- 提供额外API和组件
- 可通过Expo Go应用在设备上测试

缺点：
- 对原生模块的支持有限
- 应用体积较大
- 对自定义原生代码的限制

#### 方法2：使用React Native CLI（完整开发环境）

```bash
# 安装React Native CLI
npm install -g react-native-cli

# 创建新项目
npx react-native init MyRNProject
# 使用TypeScript模板
npx react-native init MyTSProject --template react-native-template-typescript

# iOS：在模拟器上运行（仅限macOS）
cd MyRNProject
npx react-native run-ios

# Android：在模拟器或连接的设备上运行
cd MyRNProject
npx react-native run-android
```

### 项目结构

标准React Native项目结构：

```
MyRNProject/
├── __tests__/          # 测试文件
├── android/            # Android项目文件
├── ios/                # iOS项目文件
├── node_modules/       # 依赖模块
├── src/                # 源代码（自创建）
│   ├── components/     # 可复用组件
│   ├── screens/        # 屏幕组件
│   ├── navigation/     # 导航配置
│   ├── assets/         # 静态资源
│   └── utils/          # 辅助函数
├── App.js              # 应用入口组件
├── index.js            # 应用注册入口
├── app.json            # 应用配置
├── babel.config.js     # Babel配置
├── metro.config.js     # Metro打包工具配置
└── package.json        # 项目依赖信息
```

### 开发工具

- **代码编辑器**：Visual Studio Code（推荐安装React Native Tools插件）
- **调试工具**：
  - React Native Debugger
  - Flipper（React Native内置支持）
  - Chrome Developer Tools
- **设备/模拟器**：
  - iOS模拟器（通过Xcode）
  - Android模拟器（通过Android Studio）
  - 实体设备（通过USB连接）

## 基础组件

React Native提供了一套核心组件，它们被映射到各平台对应的原生视图。以下是最常用的组件：

### 核心组件

#### View

`View`是最基础的UI组件，类似于HTML中的`div`，用于构建布局：

```jsx
import { View, StyleSheet } from 'react-native';

export default function App() {
  return (
    <View style={styles.container}>
      <View style={styles.box} />
</View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  box: {
    width: 100,
    height: 100,
    backgroundColor: 'blue',
  }
});
```

#### Text

`Text`组件用于显示文本，是所有文本显示的基础组件：

```jsx
import { Text, StyleSheet } from 'react-native';

export default function TextExample() {
  return (
    <Text style={styles.text}>
      普通文本
      <Text style={styles.bold}>加粗文本</Text>
      <Text style={styles.italic}>斜体文本</Text>
    </Text>
  );
}

const styles = StyleSheet.create({
  text: {
    fontSize: 16,
    color: '#333',
  },
  bold: {
    fontWeight: 'bold',
  },
  italic: {
    fontStyle: 'italic',
  },
});
```

#### Image

`Image`组件用于显示各种图片，支持网络图片、静态资源和本地图片：

```jsx
import { View, Image, StyleSheet } from 'react-native';

export default function ImageExample() {
  return (
    <View style={styles.container}>
      {/* 本地静态资源 */}
      <Image 
        source={require('./assets/logo.png')}
        style={styles.localImage}
      />
      
      {/* 网络图片 */}
      <Image 
        source={{ uri: 'https://reactnative.dev/img/tiny_logo.png' }}
        style={styles.remoteImage}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  localImage: {
    width: 100,
    height: 100,
    marginBottom: 20,
  },
  remoteImage: {
    width: 50,
    height: 50,
  },
});
```

#### TextInput

`TextInput`组件用于文本输入：

```jsx
import { View, TextInput, StyleSheet, Text } from 'react-native';
import { useState } from 'react';

export default function InputExample() {
const [text, setText] = useState('');

  return (
    <View style={styles.container}>
<TextInput
        style={styles.input}
  onChangeText={setText}
  value={text}
        placeholder="请输入文本..."
      />
      <Text>输入的内容: {text}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    padding: 20,
  },
  input: {
    height: 40,
    borderWidth: 1,
    borderColor: '#ccc',
    borderRadius: 5,
    paddingHorizontal: 10,
    marginBottom: 10,
  },
});
```

#### ScrollView

`ScrollView`是可滚动的容器，适用于内容较少的场景：

```jsx
import { ScrollView, View, Text, StyleSheet } from 'react-native';

export default function ScrollExample() {
  return (
    <ScrollView style={styles.container}>
      {[...Array(20)].map((_, index) => (
        <View key={index} style={styles.box}>
          <Text style={styles.text}>Item {index + 1}</Text>
        </View>
      ))}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  box: {
    height: 100,
    marginVertical: 10,
    backgroundColor: '#e0e0e0',
    justifyContent: 'center',
    alignItems: 'center',
    borderRadius: 5,
  },
  text: {
    fontSize: 18,
  },
});
```

#### FlatList

`FlatList`用于高效渲染长列表，只渲染可见项：

```jsx
import { FlatList, View, Text, StyleSheet } from 'react-native';

export default function ListExample() {
  const data = Array(100).fill().map((_, index) => ({ 
    id: `item-${index}`,
    title: `列表项 ${index + 1}` 
  }));

  const renderItem = ({ item }) => (
    <View style={styles.item}>
      <Text style={styles.title}>{item.title}</Text>
    </View>
  );

  return (
    <FlatList
      data={data}
      renderItem={renderItem}
      keyExtractor={item => item.id}
    />
  );
}

const styles = StyleSheet.create({
  item: {
    backgroundColor: '#f9f9f9',
    padding: 20,
    marginVertical: 8,
    marginHorizontal: 16,
    borderRadius: 5,
  },
  title: {
    fontSize: 16,
  },
});
```

#### Button

`Button`组件用于处理点击操作：

```jsx
import { View, Button, StyleSheet, Alert } from 'react-native';

export default function ButtonExample() {
  return (
    <View style={styles.container}>
<Button
        title="普通按钮"
        onPress={() => Alert.alert('按钮点击')}
      />
      
      <View style={styles.space} />
      
      <Button
        title="带颜色按钮"
        color="#841584"
        onPress={() => Alert.alert('紫色按钮点击')}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    padding: 20,
  },
  space: {
    height: 20,
  },
});
```

#### Touchable组件

React Native提供了多种触摸反馈组件：

```jsx
import { View, Text, StyleSheet, TouchableOpacity, TouchableHighlight } from 'react-native';

export default function TouchableExample() {
  return (
    <View style={styles.container}>
      <TouchableOpacity 
        style={styles.button}
        onPress={() => console.log('TouchableOpacity 被点击')}
      >
        <Text style={styles.buttonText}>TouchableOpacity</Text>
      </TouchableOpacity>
      
      <TouchableHighlight 
        style={styles.button}
        underlayColor="#DDDDDD"
        onPress={() => console.log('TouchableHighlight 被点击')}
      >
        <Text style={styles.buttonText}>TouchableHighlight</Text>
      </TouchableHighlight>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    padding: 20,
  },
  button: {
    backgroundColor: '#2196F3',
    padding: 15,
    borderRadius: 5,
    alignItems: 'center',
    marginVertical: 10,
  },
  buttonText: {
    color: 'white',
    fontSize: 16,
  },
});
```

### 样式与布局

React Native使用FlexBox进行布局，类似于Web开发但有一些差异：

```jsx
import { View, Text, StyleSheet } from 'react-native';

export default function LayoutExample() {
  return (
    <View style={styles.container}>
      <View style={styles.box1}>
        <Text style={styles.text}>1</Text>
      </View>
      <View style={styles.box2}>
        <Text style={styles.text}>2</Text>
      </View>
      <View style={styles.box3}>
        <Text style={styles.text}>3</Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    flexDirection: 'row', // 水平方向排列
    backgroundColor: '#F5FCFF',
  },
  box1: {
    flex: 1, // 占用1份空间
    backgroundColor: '#FF5252',
    justifyContent: 'center',
    alignItems: 'center',
  },
  box2: {
    flex: 2, // 占用2份空间
    backgroundColor: '#4CAF50',
    justifyContent: 'center',
    alignItems: 'center',
  },
  box3: {
    flex: 1, // 占用1份空间
    backgroundColor: '#2196F3',
    justifyContent: 'center',
    alignItems: 'center',
  },
  text: {
    color: 'white',
    fontSize: 24,
    fontWeight: 'bold',
  },
});
```

### 常用API

React Native还提供了许多有用的API：

```jsx
import { View, Text, StyleSheet, Alert, Platform } from 'react-native';

export default function APIExample() {
  return (
    <View style={styles.container}>
      <Text style={styles.text}>
        当前平台: {Platform.OS} {Platform.Version}
      </Text>
      
      <Text 
        style={styles.button}
        onPress={() => Alert.alert(
          '提示标题',
          '这是一个提示消息',
          [
            { text: '取消', style: 'cancel' },
            { text: '确认', onPress: () => console.log('确认按钮点击') }
          ]
        )}
      >
        显示提示框
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 20,
  },
  text: {
    fontSize: 16,
    marginBottom: 20,
  },
  button: {
    color: 'blue',
    fontSize: 16,
    padding: 10,
  },
});
```

## 导航与路由

导航是移动应用不可或缺的一部分。React Native生态系统中最流行的导航库是React Navigation。

### 安装React Navigation

```bash
# 安装核心库
npm install @react-navigation/native

# 安装必要依赖
npm install react-native-screens react-native-safe-area-context

# iOS平台还需要
cd ios && pod install && cd ..
```

### 常用导航器类型

#### Stack Navigator (堆栈导航器)

处理应用中的页面间导航，具有原生的转场动画效果。

```bash
npm install @react-navigation/stack
npm install react-native-gesture-handler
```

基本用法:

```jsx
import React from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createStackNavigator } from '@react-navigation/stack';
import HomeScreen from './screens/HomeScreen';
import DetailsScreen from './screens/DetailsScreen';

const Stack = createStackNavigator();

export default function App() {
  return (
    <NavigationContainer>
      <Stack.Navigator initialRouteName="Home">
        <Stack.Screen 
          name="Home" 
          component={HomeScreen} 
          options={{ title: '首页' }}
        />
        <Stack.Screen 
          name="Details" 
          component={DetailsScreen}
          options={{ title: '详情页' }} 
        />
      </Stack.Navigator>
    </NavigationContainer>
  );
}
```

页面之间的导航：

```jsx
// HomeScreen.js
import React from 'react';
import { View, Text, Button } from 'react-native';

export default function HomeScreen({ navigation }) {
  return (
    <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center' }}>
      <Text>首页</Text>
      <Button
        title="前往详情页"
        onPress={() => navigation.navigate('Details', { itemId: 86 })}
      />
    </View>
  );
}

// DetailsScreen.js
export default function DetailsScreen({ route, navigation }) {
  // 获取传递的参数
  const { itemId } = route.params;
  
  return (
    <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center' }}>
      <Text>详情页</Text>
      <Text>物品ID: {itemId}</Text>
      <Button title="返回" onPress={() => navigation.goBack()} />
    </View>
  );
}
```

#### Tab Navigator (标签导航器)

创建带有标签栏的导航界面，通常用于应用的主要导航功能。

```bash
npm install @react-navigation/bottom-tabs
```

```jsx
import { NavigationContainer } from '@react-navigation/native';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import HomeScreen from './screens/HomeScreen';
import SettingsScreen from './screens/SettingsScreen';
import Ionicons from 'react-native-vector-icons/Ionicons';

const Tab = createBottomTabNavigator();

export default function App() {
  return (
    <NavigationContainer>
      <Tab.Navigator
        screenOptions={({ route }) => ({
          tabBarIcon: ({ focused, color, size }) => {
            let iconName;
            
            if (route.name === 'Home') {
              iconName = focused ? 'home' : 'home-outline';
            } else if (route.name === 'Settings') {
              iconName = focused ? 'settings' : 'settings-outline';
            }
            
            return <Ionicons name={iconName} size={size} color={color} />;
          },
        })}
        tabBarOptions={{
          activeTintColor: 'tomato',
          inactiveTintColor: 'gray',
        }}
      >
        <Tab.Screen name="Home" component={HomeScreen} options={{ title: '首页' }} />
        <Tab.Screen name="Settings" component={SettingsScreen} options={{ title: '设置' }} />
      </Tab.Navigator>
    </NavigationContainer>
  );
}
```

#### Drawer Navigator (抽屉导航器)

创建可以从屏幕侧边滑出的抽屉菜单。

```bash
npm install @react-navigation/drawer
npm install react-native-gesture-handler react-native-reanimated
```

```jsx
import { NavigationContainer } from '@react-navigation/native';
import { createDrawerNavigator } from '@react-navigation/drawer';
import HomeScreen from './screens/HomeScreen';
import NotificationsScreen from './screens/NotificationsScreen';

const Drawer = createDrawerNavigator();

export default function App() {
  return (
    <NavigationContainer>
      <Drawer.Navigator initialRouteName="Home">
        <Drawer.Screen name="Home" component={HomeScreen} options={{ title: '首页' }} />
        <Drawer.Screen name="Notifications" component={NotificationsScreen} options={{ title: '通知' }} />
      </Drawer.Navigator>
    </NavigationContainer>
  );
}
```

### 嵌套导航

不同类型的导航器可以嵌套使用，创建复杂的导航结构:

```jsx
function HomeScreen() {
  return (
    <Tab.Navigator>
      <Tab.Screen name="Feed" component={FeedScreen} />
      <Tab.Screen name="Messages" component={MessagesScreen} />
    </Tab.Navigator>
  );
}

function App() {
  return (
    <NavigationContainer>
    <Stack.Navigator>
        <Stack.Screen name="Home" component={HomeScreen} options={{ headerShown: false }} />
      <Stack.Screen name="Profile" component={ProfileScreen} />
      <Stack.Screen name="Settings" component={SettingsScreen} />
      </Stack.Navigator>
    </NavigationContainer>
  );
}
``` 

## 状态管理

React Native提供多种状态管理选项，从简单的React内置状态到复杂的外部库。

### React内置状态管理

#### useState Hook

用于管理组件级状态:

```jsx
import React, { useState } from 'react';
import { View, Text, Button } from 'react-native';

function Counter() {
  const [count, setCount] = useState(0);
  
  return (
    <View style={{ padding: 20 }}>
      <Text style={{ fontSize: 18 }}>计数: {count}</Text>
      <Button title="增加" onPress={() => setCount(count + 1)} />
      <Button title="减少" onPress={() => setCount(count - 1)} />
    </View>
  );
}
```

#### useReducer Hook

适用于复杂的状态逻辑:

```jsx
import React, { useReducer } from 'react';
import { View, Text, Button } from 'react-native';

// 定义reducer函数
function counterReducer(state, action) {
  switch (action.type) {
    case 'increment':
      return { count: state.count + 1 };
    case 'decrement':
      return { count: state.count - 1 };
    case 'reset':
      return { count: 0 };
    default:
      return state;
  }
}

function CounterWithReducer() {
  const [state, dispatch] = useReducer(counterReducer, { count: 0 });
  
  return (
    <View style={{ padding: 20 }}>
      <Text style={{ fontSize: 18 }}>计数: {state.count}</Text>
      <Button title="增加" onPress={() => dispatch({ type: 'increment' })} />
      <Button title="减少" onPress={() => dispatch({ type: 'decrement' })} />
      <Button title="重置" onPress={() => dispatch({ type: 'reset' })} />
    </View>
  );
}
```

#### Context API

用于跨组件共享状态:

```jsx
import React, { createContext, useState, useContext } from 'react';
import { View, Text, Button, StyleSheet } from 'react-native';

// 创建Context
const ThemeContext = createContext();

// 提供Context的组件
function ThemeProvider({ children }) {
  const [isDarkMode, setIsDarkMode] = useState(false);
  
  const toggleTheme = () => {
    setIsDarkMode(prev => !prev);
  };
  
  return (
    <ThemeContext.Provider value={{ isDarkMode, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

// 使用Context的组件
function ThemedContent() {
  const { isDarkMode, toggleTheme } = useContext(ThemeContext);
  
  const styles = StyleSheet.create({
    container: {
      flex: 1,
      justifyContent: 'center',
      alignItems: 'center',
      backgroundColor: isDarkMode ? '#1a1a1a' : '#ffffff',
      padding: 20,
    },
    text: {
      fontSize: 18,
      color: isDarkMode ? '#ffffff' : '#000000',
      marginBottom: 20,
    },
  });
  
  return (
    <View style={styles.container}>
      <Text style={styles.text}>
        当前模式: {isDarkMode ? '深色' : '浅色'}
      </Text>
    <Button
        title="切换主题"
      onPress={toggleTheme}
    />
    </View>
  );
}

// 主应用组件
function App() {
  return (
    <ThemeProvider>
      <ThemedContent />
    </ThemeProvider>
  );
}
```

### Redux

Redux是一个流行的状态管理库，适用于中大型应用。

```bash
npm install redux react-redux @reduxjs/toolkit
```

基本用法:

```jsx
// counterSlice.js
import { createSlice } from '@reduxjs/toolkit';

const counterSlice = createSlice({
  name: 'counter',
  initialState: {
    value: 0,
  },
  reducers: {
    increment: (state) => {
      state.value += 1;
    },
    decrement: (state) => {
      state.value -= 1;
    },
  },
});

export const { increment, decrement } = counterSlice.actions;
export default counterSlice.reducer;

// store.js
import { configureStore } from '@reduxjs/toolkit';
import counterReducer from './counterSlice';

export const store = configureStore({
  reducer: {
    counter: counterReducer,
  },
});

// App.js
import React from 'react';
import { Provider } from 'react-redux';
import { store } from './store';
import CounterScreen from './CounterScreen';

export default function App() {
  return (
    <Provider store={store}>
      <CounterScreen />
    </Provider>
  );
}

// CounterScreen.js
import React from 'react';
import { View, Text, Button, StyleSheet } from 'react-native';
import { useSelector, useDispatch } from 'react-redux';
import { increment, decrement } from './counterSlice';

export default function CounterScreen() {
  const count = useSelector((state) => state.counter.value);
  const dispatch = useDispatch();
  
  return (
    <View style={styles.container}>
      <Text style={styles.text}>计数: {count}</Text>
      <View style={styles.buttonContainer}>
      <Button title="增加" onPress={() => dispatch(increment())} />
      <Button title="减少" onPress={() => dispatch(decrement())} />
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  text: {
    fontSize: 24,
    marginBottom: 20,
  },
  buttonContainer: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    width: '60%',
  },
});
```

## 网络请求

React Native提供了Fetch API和XMLHttpRequest API，同时也支持第三方库如Axios。

### 使用Fetch API

```jsx
import React, { useState, useEffect } from 'react';
import { View, Text, FlatList, StyleSheet, ActivityIndicator } from 'react-native';

export default function FetchExample() {
  const [isLoading, setLoading] = useState(true);
  const [data, setData] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetch('https://jsonplaceholder.typicode.com/posts')
      .then((response) => response.json())
      .then((json) => setData(json))
      .catch((error) => setError(error))
      .finally(() => setLoading(false));
  }, []);

  if (isLoading) {
    return (
      <View style={styles.center}>
        <ActivityIndicator size="large" color="#0000ff" />
      </View>
    );
  }

  if (error) {
    return (
      <View style={styles.center}>
        <Text>发生错误: {error.message}</Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <FlatList
        data={data}
        keyExtractor={({ id }) => id.toString()}
        renderItem={({ item }) => (
          <View style={styles.item}>
            <Text style={styles.title}>{item.title}</Text>
            <Text>{item.body}</Text>
          </View>
        )}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 10,
  },
  center: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  item: {
    backgroundColor: '#f9f9f9',
    padding: 20,
    marginVertical: 8,
    borderRadius: 5,
  },
  title: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 5,
  },
});
```

### 使用Axios

首先安装Axios:

```bash
npm install axios
```

基本用法:

```jsx
import React, { useState, useEffect } from 'react';
import { View, Text, FlatList, StyleSheet, ActivityIndicator } from 'react-native';
import axios from 'axios';

export default function AxiosExample() {
  const [isLoading, setLoading] = useState(true);
  const [data, setData] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    // GET请求
    axios.get('https://jsonplaceholder.typicode.com/users')
      .then(response => {
        setData(response.data);
      })
      .catch(error => {
        setError(error);
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);
  
  // POST请求示例
  const postData = async () => {
    try {
      const response = await axios.post(
        'https://jsonplaceholder.typicode.com/posts',
        {
          title: '新文章',
          body: '这是一篇新文章',
          userId: 1,
        }
      );
      console.log('响应:', response.data);
    } catch (error) {
      console.error('错误:', error);
    }
  };

  if (isLoading) {
    return (
      <View style={styles.center}>
        <ActivityIndicator size="large" color="#0000ff" />
      </View>
    );
  }

  if (error) {
    return (
      <View style={styles.center}>
        <Text>发生错误: {error.message}</Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <FlatList
        data={data}
        keyExtractor={({ id }) => id.toString()}
        renderItem={({ item }) => (
          <View style={styles.item}>
            <Text style={styles.title}>{item.name}</Text>
            <Text>{item.email}</Text>
          </View>
        )}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 10,
  },
  center: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  item: {
    backgroundColor: '#f9f9f9',
    padding: 20,
    marginVertical: 8,
    borderRadius: 5,
  },
  title: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 5,
  },
});
```

### 处理API请求的最佳实践

1. **集中管理API请求**:
   ```jsx
   // api.js
   import axios from 'axios';

   const API = axios.create({
     baseURL: 'https://api.example.com',
     timeout: 10000,
     headers: {
       'Content-Type': 'application/json',
       'Accept': 'application/json',
  },
});

   // 请求拦截器
   API.interceptors.request.use(
     config => {
       // 添加授权令牌等
       const token = localStorage.getItem('token');
       if (token) {
         config.headers.Authorization = `Bearer ${token}`;
       }
       return config;
     },
     error => Promise.reject(error)
   );

   // 响应拦截器
   API.interceptors.response.use(
     response => response,
     error => {
       // 处理401、500等错误
       if (error.response && error.response.status === 401) {
         // 处理未授权
       }
       return Promise.reject(error);
     }
   );

   export const UserAPI = {
     getUsers: () => API.get('/users'),
     getUserById: (id) => API.get(`/users/${id}`),
     createUser: (userData) => API.post('/users', userData),
   };

   export const PostAPI = {
     getPosts: () => API.get('/posts'),
     createPost: (postData) => API.post('/posts', postData),
   };
   ```

2. **使用自定义Hook封装数据获取逻辑**:
   ```jsx
   // useApi.js
   import { useState, useEffect } from 'react';

   export function useApi(apiCall) {
     const [data, setData] = useState(null);
     const [isLoading, setLoading] = useState(true);
     const [error, setError] = useState(null);

     useEffect(() => {
       const fetchData = async () => {
         try {
           setLoading(true);
           const response = await apiCall();
           setData(response.data);
           setError(null);
         } catch (err) {
           setError(err);
           setData(null);
         } finally {
           setLoading(false);
         }
       };

       fetchData();
     }, [apiCall]);

     return { data, isLoading, error };
   }

   // 使用方法
   // const { data, isLoading, error } = useApi(UserAPI.getUsers);
   ```

## 性能优化

### 组件渲染优化

1. **使用PureComponent和memo**

```jsx
import React, { memo } from 'react';
import { Text, StyleSheet } from 'react-native';

// 使用memo包装函数组件
const ExpensiveComponent = memo(({ title }) => {
  console.log('Rendering ExpensiveComponent');
  return (
    <Text style={styles.text}>{title}</Text>
  );
});

// 或者使用类组件
class ExpensiveClassComponent extends React.PureComponent {
  render() {
    console.log('Rendering ExpensiveClassComponent');
    return (
      <Text style={styles.text}>{this.props.title}</Text>
    );
  }
}

const styles = StyleSheet.create({
  text: {
    fontSize: 16,
    padding: 10,
  },
});
```

2. **使用useMemo和useCallback**

```jsx
import React, { useState, useMemo, useCallback } from 'react';
import { View, Text, Button, StyleSheet } from 'react-native';

function OptimizedComponent() {
  const [count, setCount] = useState(0);
  const [text, setText] = useState('Hello');
  
  // 使用useMemo缓存计算结果
  const expensiveCalculation = useMemo(() => {
    console.log('Performing expensive calculation');
    let result = 0;
    for (let i = 0; i < 1000000; i++) {
      result += i;
    }
    return result + count;
  }, [count]); // 只在count变化时重新计算
  
  // 使用useCallback缓存回调函数
  const handleIncrement = useCallback(() => {
    setCount(c => c + 1);
  }, []);
  
  return (
    <View style={styles.container}>
      <Text style={styles.text}>Count: {count}</Text>
      <Text style={styles.text}>Calculation: {expensiveCalculation}</Text>
      <Text style={styles.text}>{text}</Text>
      <Button title="增加" onPress={handleIncrement} />
      <Button title="更改文本" onPress={() => setText('Updated!')} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 20,
  },
  text: {
    fontSize: 18,
    marginVertical: 10,
  },
});
```

### 列表优化

1. **使用FlatList的性能优化属性**

```jsx
import React from 'react';
import { FlatList, View, Text, StyleSheet } from 'react-native';

export default function OptimizedList() {
  const data = Array(500).fill().map((_, index) => ({
    id: `item-${index}`,
    title: `项目 ${index}`,
    description: `这是项目 ${index} 的描述`
  }));
  
  const renderItem = ({ item }) => (
    <View style={styles.item}>
      <Text style={styles.title}>{item.title}</Text>
      <Text>{item.description}</Text>
    </View>
  );
  
  return (
    <FlatList
      data={data}
      renderItem={renderItem}
      keyExtractor={item => item.id}
      // 性能优化属性
      initialNumToRender={10} // 初始渲染的项目数量
      maxToRenderPerBatch={10} // 每批次渲染的最大数量
      windowSize={7} // 可视窗口的项目数量
      updateCellsBatchingPeriod={50} // 批量更新的时间窗口(ms)
      removeClippedSubviews={true} // 移出不在可视区域的视图
      getItemLayout={(data, index) => (
        // 提前计算项目高度，提高滚动性能
        { length: 80, offset: 80 * index, index }
      )}
      ListHeaderComponent={() => <Text style={styles.header}>优化列表</Text>}
      ListFooterComponent={() => <Text style={styles.footer}>列表结束</Text>}
    />
  );
}

const styles = StyleSheet.create({
  item: {
    backgroundColor: '#f9f9f9',
    padding: 20,
    marginVertical: 8,
    marginHorizontal: 16,
    height: 80, // 固定高度，配合getItemLayout使用
  },
  title: {
    fontSize: 18,
    fontWeight: 'bold',
  },
  header: {
    fontSize: 22,
    fontWeight: 'bold',
    textAlign: 'center',
    marginVertical: 10,
  },
  footer: {
    fontSize: 16,
    textAlign: 'center',
    marginVertical: 10,
  },
});
```

### 图像优化

1. **使用FastImage替代Image**

首先安装:
```bash
npm install react-native-fast-image
```

然后使用:
```jsx
import React from 'react';
import { View, StyleSheet } from 'react-native';
import FastImage from 'react-native-fast-image';

export default function OptimizedImage() {
  return (
    <View style={styles.container}>
      <FastImage
        style={styles.image}
        source={{
          uri: 'https://example.com/image.jpg',
          // 缓存控制
          cache: FastImage.cacheControl.immutable,
          // 优先级
          priority: FastImage.priority.high,
        }}
        resizeMode={FastImage.resizeMode.cover}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  image: {
    width: 200,
    height: 200,
    borderRadius: 10,
  },
});
```

### 内存优化

1. **组件卸载时清理资源**

```jsx
import React, { useState, useEffect } from 'react';
import { View, Text, StyleSheet } from 'react-native';

export default function MemoryOptimizedComponent() {
  const [data, setData] = useState(null);
  
  useEffect(() => {
    // 设置定时器
    const timer = setInterval(() => {
      console.log('Timer running...');
    }, 1000);
    
    // 订阅事件
    const subscription = someEventEmitter.addListener('event', handleEvent);
    
    // 获取数据
    let isActive = true;
    fetchData().then(result => {
      // 防止组件卸载后设置状态
      if (isActive) {
        setData(result);
      }
    });
    
    // 清理函数
    return () => {
      clearInterval(timer);
      subscription.remove();
      isActive = false;
    };
  }, []);
  
  return (
    <View style={styles.container}>
      <Text>Memory Optimized Component</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
});
```

### 启用Hermes引擎

Hermes是React Native的JavaScript引擎，可以提高应用性能和减少内存使用。在新项目中默认启用，对于现有项目，可以在`android/app/build.gradle`中启用:

```gradle
project.ext.react = [
    enableHermes: true  // 启用Hermes
]
```

对于iOS，在`ios/Podfile`中启用:

```ruby
use_react_native!(
  :path => config[:reactNativePath],
  # 启用Hermes
  :hermes_enabled => true
)
```

## 动画与手势

流畅的动画和自然的手势交互是优秀移动应用的关键特性。React Native提供了强大的API用于实现各种动画和手势效果。

### Animated API

Animated是React Native内置的动画库，用于创建流畅、强大的动画效果。

#### 基础动画示例

```jsx
import React, { useRef, useEffect } from 'react';
import { Animated, Text, View, StyleSheet, Button } from 'react-native';

export default function FadeInView() {
  const fadeAnim = useRef(new Animated.Value(0)).current; // 透明度初始值设为0

  useEffect(() => {
    Animated.timing(fadeAnim, {
      toValue: 1,           // 目标值
      duration: 1000,       // 动画时长(毫秒)
      useNativeDriver: true // 使用原生驱动提高性能
    }).start();             // 开始动画
  }, [fadeAnim]);
  
  return (
    <View style={styles.container}>
      <Animated.View style={{ ...styles.box, opacity: fadeAnim }}>
        <Text style={styles.text}>淡入效果</Text>
      </Animated.View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  box: {
    width: 200,
    height: 200,
    backgroundColor: 'tomato',
    alignItems: 'center',
    justifyContent: 'center',
  },
  text: {
    color: 'white',
    fontSize: 20,
  },
});
```

#### 组合动画

可以使用`parallel`、`sequence`和`stagger`等方法组合多个动画：

```jsx
import React, { useRef } from 'react';
import { Animated, View, StyleSheet, Button } from 'react-native';

export default function AnimationExample() {
  // 创建多个动画值
  const moveAnim = useRef(new Animated.Value(0)).current;
  const scaleAnim = useRef(new Animated.Value(1)).current;
  const rotateAnim = useRef(new Animated.Value(0)).current;

  // 启动组合动画
  const startAnimation = () => {
    // 重置动画值
    moveAnim.setValue(0);
    scaleAnim.setValue(1);
    rotateAnim.setValue(0);

    // 创建组合动画
    Animated.sequence([
      // 先移动
      Animated.timing(moveAnim, {
        toValue: 150,
        duration: 500,
        useNativeDriver: true,
      }),
      // 然后同时旋转和缩放
      Animated.parallel([
        Animated.timing(scaleAnim, {
          toValue: 1.5,
          duration: 300,
          useNativeDriver: true,
        }),
        Animated.timing(rotateAnim, {
          toValue: 1,
          duration: 700,
          useNativeDriver: true,
        }),
      ]),
      // 最后返回原始大小
      Animated.timing(scaleAnim, {
        toValue: 1,
        duration: 300,
        useNativeDriver: true,
      }),
    ]).start();
  };

  // 使用插值将0-1的值映射到"0deg"-"360deg"
  const rotation = rotateAnim.interpolate({
    inputRange: [0, 1],
    outputRange: ['0deg', '360deg'],
  });

  return (
    <View style={styles.container}>
      <Animated.View
        style={{
          ...styles.box,
          transform: [
            { translateX: moveAnim },
            { scale: scaleAnim },
            { rotate: rotation },
          ],
        }}
      />
      <Button title="开始动画" onPress={startAnimation} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  box: {
    width: 100,
    height: 100,
    backgroundColor: '#3498db',
    marginBottom: 40,
  },
});
```

#### 动画类型

Animated提供了多种动画类型：

- **Animated.timing**: 从时间维度的动画
- **Animated.spring**: 弹簧物理效果的动画
- **Animated.decay**: 以初始速度开始并逐渐减慢的动画

```jsx
// 弹簧动画示例
Animated.spring(scaleAnim, {
  toValue: 1.5,
  friction: 3,     // 摩擦力，较小的值会弹跳更多
  tension: 40,     // 张力，较大的值可使弹簧更刚性
  useNativeDriver: true,
}).start();

// 衰减动画示例
Animated.decay(moveAnim, {
  velocity: 0.5,   // 初始速度
  deceleration: 0.997, // 衰减系数
  useNativeDriver: true,
}).start();
```

### LayoutAnimation

LayoutAnimation允许你在下一次渲染时自动创建视图布局的动画过渡。

```jsx
import React, { useState } from 'react';
import { LayoutAnimation, Platform, UIManager, View, StyleSheet, Button } from 'react-native';

// Android需要额外配置
if (Platform.OS === 'android') {
  if (UIManager.setLayoutAnimationEnabledExperimental) {
    UIManager.setLayoutAnimationEnabledExperimental(true);
  }
}

export default function LayoutAnimationExample() {
  const [expanded, setExpanded] = useState(false);

  const toggleBox = () => {
    // 配置下一次布局更新的动画
    LayoutAnimation.configureNext(LayoutAnimation.Presets.spring);
    setExpanded(!expanded);
  };

  return (
    <View style={styles.container}>
      <View style={[styles.box, expanded && styles.expandedBox]} />
      <Button title={expanded ? "收起" : "展开"} onPress={toggleBox} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  box: {
    width: 100,
    height: 100,
    backgroundColor: '#e74c3c',
    marginBottom: 20,
  },
  expandedBox: {
    width: 200,
    height: 200,
  },
});
```

### 手势响应系统

React Native提供了全面的手势响应系统，主要通过PanResponder API实现。

#### PanResponder基础

```jsx
import React, { useRef } from 'react';
import { View, StyleSheet, PanResponder, Animated } from 'react-native';

export default function DraggableBox() {
  const pan = useRef(new Animated.ValueXY()).current;

  const panResponder = useRef(
    PanResponder.create({
      // 是否成为响应者
      onStartShouldSetPanResponder: () => true,
      onMoveShouldSetPanResponder: () => true,
      
      // 手势开始时的处理
      onPanResponderGrant: () => {
        // 保存初始位置
        pan.setOffset({
          x: pan.x._value,
          y: pan.y._value
        });
        // 重置动画值
        pan.setValue({ x: 0, y: 0 });
      },
      
      // 手势移动时的处理
      onPanResponderMove: Animated.event(
        [null, { dx: pan.x, dy: pan.y }],
        { useNativeDriver: false }
      ),
      
      // 手势结束时的处理
      onPanResponderRelease: () => {
        // 完成手势，设置偏移量
        pan.flattenOffset();
      }
    })
  ).current;

  return (
    <View style={styles.container}>
      <Animated.View
        style={{
          ...styles.box,
          transform: [{ translateX: pan.x }, { translateY: pan.y }]
        }}
        {...panResponder.panHandlers}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center'
  },
  box: {
    width: 100,
    height: 100,
    backgroundColor: '#27ae60',
    borderRadius: 5
  }
});
```

#### 复杂手势 - 捏合缩放

```jsx
import React, { useState, useRef } from 'react';
import { View, StyleSheet, PanResponder, Animated } from 'react-native';

export default function PinchZoomView() {
  // 缩放和旋转的动画值
  const scale = useRef(new Animated.Value(1)).current;
  const rotate = useRef(new Animated.Value(0)).current;
  
  // 保存上一个手势状态
  const lastScale = useRef(1);
  const lastRotation = useRef(0);

  // 计算两指间距
  const distance = (x1, y1, x2, y2) => {
    return Math.sqrt(Math.pow(x2 - x1, 2) + Math.pow(y2 - y1, 2));
  };

  // 计算旋转角度
  const calculateAngle = (x1, y1, x2, y2) => {
    return Math.atan2(y2 - y1, x2 - x1) * 180 / Math.PI;
  };

  const panResponder = useRef(
    PanResponder.create({
      onStartShouldSetPanResponder: () => true,
      onMoveShouldSetPanResponder: () => true,

      onPanResponderMove: (evt, gestureState) => {
        // 只处理多点触摸
        if (evt.nativeEvent.changedTouches.length >= 2) {
          const touches = evt.nativeEvent.changedTouches;
          
          // 计算两指间距
          const currentDistance = distance(
            touches[0].pageX, touches[0].pageY,
            touches[1].pageX, touches[1].pageY
          );
          
          // 计算初始两指间距（如果未设置）
          if (!this.initialDistance) {
            this.initialDistance = currentDistance;
          }
          
          // 计算缩放比
          const currentScale = currentDistance / this.initialDistance * lastScale.current;
          scale.setValue(currentScale);
          
          // 可选：计算旋转角度
          const currentAngle = calculateAngle(
            touches[0].pageX, touches[0].pageY,
            touches[1].pageX, touches[1].pageY
          );
          
          if (!this.initialAngle) {
            this.initialAngle = currentAngle;
          }
          
          const newRotation = currentAngle - this.initialAngle + lastRotation.current;
          rotate.setValue(newRotation);
        }
      },
      
      onPanResponderRelease: () => {
        // 保存当前的缩放和旋转值
        lastScale.current = scale._value;
        lastRotation.current = rotate._value;
        
        // 重置初始值
        this.initialDistance = null;
        this.initialAngle = null;
      }
    })
  ).current;

  const rotation = rotate.interpolate({
    inputRange: [0, 360],
    outputRange: ['0deg', '360deg']
  });

  return (
    <View style={styles.container} {...panResponder.panHandlers}>
      <Animated.Image
        source={require('./assets/image.jpg')}
        style={[
          styles.image,
          {
            transform: [
              { scale: scale },
              { rotate: rotation }
            ]
          }
        ]}
        resizeMode="contain"
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  image: {
    width: 250,
    height: 250,
  },
});
```

### 使用第三方手势库

对于更复杂的手势需求，可以考虑使用第三方库，例如`react-native-gesture-handler`和`react-native-reanimated`。

#### 安装react-native-gesture-handler

```bash
npm install react-native-gesture-handler
```

#### 简单示例

```jsx
import React from 'react';
import { StyleSheet, View, Text } from 'react-native';
import { PanGestureHandler, State } from 'react-native-gesture-handler';
import Animated, { 
  useAnimatedGestureHandler, 
  useAnimatedStyle, 
  useSharedValue,
  withSpring 
} from 'react-native-reanimated';

export default function GestureHandlerExample() {
  // 创建共享值用于动画
  const translateX = useSharedValue(0);
  const translateY = useSharedValue(0);
  
  // 处理手势事件
  const panGestureEvent = useAnimatedGestureHandler({
    // 手势开始
    onStart: (_, context) => {
      context.startX = translateX.value;
      context.startY = translateY.value;
    },
    // 手势进行中
    onActive: (event, context) => {
      translateX.value = context.startX + event.translationX;
      translateY.value = context.startY + event.translationY;
    },
    // 手势结束
    onEnd: (_) => {
      translateX.value = withSpring(0);
      translateY.value = withSpring(0);
    },
  });
  
  // 创建动画样式
  const animatedStyle = useAnimatedStyle(() => {
    return {
      transform: [
        { translateX: translateX.value },
        { translateY: translateY.value },
      ],
    };
  });

  return (
    <View style={styles.container}>
      <PanGestureHandler onGestureEvent={panGestureEvent}>
        <Animated.View style={[styles.box, animatedStyle]}>
          <Text style={styles.text}>拖动我</Text>
        </Animated.View>
      </PanGestureHandler>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  box: {
    width: 150,
    height: 150,
    backgroundColor: '#9b59b6',
    borderRadius: 10,
    alignItems: 'center',
    justifyContent: 'center',
  },
  text: {
    color: 'white',
    fontSize: 16,
  },
});
```

### 动画最佳实践

1. **使用`useNativeDriver: true`**
   - 当动画仅涉及非布局属性时(如transform, opacity)，始终启用原生驱动提高性能

2. **避免在动画中使用JS回调**
   - 尽量使用`Animated.Value.interpolate()`而不是在回调中操作

3. **优化列表动画**
   - 为列表项添加键值，避免不必要的重新渲染
   - 考虑使用`LayoutAnimation`而非逐项动画

4. **理解动画性能瓶颈**
   - 动画帧率低于60fps时，可能是JS线程或UI线程过载
   - 使用Flipper或Chrome开发工具分析性能问题 

## 本地存储

移动应用经常需要在本地保存数据，React Native提供了多种数据存储方案，从简单的键值存储到完整的数据库解决方案。

### AsyncStorage

AsyncStorage是React Native提供的简单、异步、持久化的键值存储系统。从React Native 0.59开始，AsyncStorage已经被移到独立的包中。

#### 安装

```bash
npm install @react-native-async-storage/async-storage
```

#### 基本使用

```jsx
import React, { useState, useEffect } from 'react';
import { View, Text, TextInput, Button, StyleSheet } from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';

export default function AsyncStorageExample() {
  const [name, setName] = useState('');
  const [savedName, setSavedName] = useState('');

  // 获取存储的名字
  const getName = async () => {
    try {
      const value = await AsyncStorage.getItem('@name');
      if (value !== null) {
        setSavedName(value);
      }
    } catch (e) {
      console.error('读取失败', e);
    }
  };

  // 保存名字
  const saveName = async () => {
    try {
      await AsyncStorage.setItem('@name', name);
      getName(); // 重新读取以更新显示
    } catch (e) {
      console.error('保存失败', e);
    }
  };

  // 删除名字
  const removeName = async () => {
    try {
      await AsyncStorage.removeItem('@name');
      setSavedName('');
    } catch (e) {
      console.error('删除失败', e);
    }
  };

  // 初始加载时读取保存的名字
  useEffect(() => {
    getName();
  }, []);

  return (
    <View style={styles.container}>
      <Text style={styles.title}>AsyncStorage示例</Text>
      
      <TextInput
        style={styles.input}
        onChangeText={setName}
        value={name}
        placeholder="输入你的名字"
      />
      
      <View style={styles.buttonContainer}>
        <Button title="保存" onPress={saveName} />
        <Button title="删除" onPress={removeName} />
      </View>
      
      {savedName ? (
        <Text style={styles.savedText}>已保存的名字: {savedName}</Text>
      ) : (
        <Text style={styles.savedText}>没有保存的名字</Text>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
    alignItems: 'center',
    justifyContent: 'center',
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 20,
  },
  input: {
    width: '100%',
    height: 40,
    borderWidth: 1,
    borderColor: '#ccc',
    borderRadius: 5,
    paddingHorizontal: 10,
    marginBottom: 20,
  },
  buttonContainer: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    width: '100%',
    marginBottom: 20,
  },
  savedText: {
    fontSize: 18,
    marginTop: 20,
  },
});
```

#### 存储复杂数据

对于对象和数组，需要先转换为JSON字符串：

```jsx
// 存储对象
const saveObject = async (value) => {
  try {
    const jsonValue = JSON.stringify(value);
    await AsyncStorage.setItem('@storage_Key', jsonValue);
  } catch (e) {
    console.error('保存对象失败', e);
  }
};

// 读取对象
const getObject = async () => {
  try {
    const jsonValue = await AsyncStorage.getItem('@storage_Key');
    return jsonValue != null ? JSON.parse(jsonValue) : null;
  } catch (e) {
    console.error('读取对象失败', e);
  }
};
```

#### 批量操作

AsyncStorage支持批量存储和获取操作：

```jsx
// 批量存储
const multiSet = async () => {
  const firstPair = ['@MyApp_USER', 'user_1']
  const secondPair = ['@MyApp_KEY', 'key_1']
  
  try {
    await AsyncStorage.multiSet([firstPair, secondPair])
  } catch(e) {
    console.error('批量存储失败', e)
  }
};

// 批量获取
const multiGet = async () => {
  let values
  try {
    values = await AsyncStorage.multiGet(['@MyApp_USER', '@MyApp_KEY'])
  } catch(e) {
    console.error('批量获取失败', e)
  }
  
  // 输出结果: 
  // [['@MyApp_USER', 'user_1'], ['@MyApp_KEY', 'key_1']]
  console.log(values)
};
```

### Realm

对于更复杂的存储需求，Realm是一个功能强大的移动数据库，速度快且易于使用。

#### 安装

```bash
npm install realm
```

#### 基本使用

```jsx
import React, { useState, useEffect } from 'react';
import { View, Text, FlatList, TextInput, Button, StyleSheet } from 'react-native';
import Realm from 'realm';

// 定义Task模式
const TaskSchema = {
  name: 'Task',
  properties: {
    _id: 'int',
    name: 'string',
    completed: { type: 'bool', default: false },
    createdAt: 'date'
  },
  primaryKey: '_id',
};

export default function RealmExample() {
  const [taskName, setTaskName] = useState('');
  const [tasks, setTasks] = useState([]);
  const [realm, setRealm] = useState(null);

  // 初始化Realm
  useEffect(() => {
    const initRealm = async () => {
      try {
        const realmInstance = await Realm.open({
          schema: [TaskSchema],
          schemaVersion: 1,
        });
        
        setRealm(realmInstance);
        
        // 加载任务
        const allTasks = realmInstance.objects('Task').sorted('createdAt');
        setTasks([...allTasks]);
        
        // 添加变更监听器
        allTasks.addListener(() => {
          setTasks([...realmInstance.objects('Task').sorted('createdAt')]);
        });
    
    return () => {
          // 组件卸载时关闭Realm并移除监听器
          const allTasks = realmInstance.objects('Task');
          allTasks.removeAllListeners();
          realmInstance.close();
        };
      } catch (error) {
        console.error('Realm初始化失败', error);
      }
    };
    
    initRealm();
  }, []);
  
  // 添加任务
  const addTask = () => {
    if (taskName && realm) {
      realm.write(() => {
        // 查找最大ID
        const tasks = realm.objects('Task');
        const maxId = tasks.length > 0 ? Math.max(...tasks.map(t => t._id)) : 0;
        
        realm.create('Task', {
          _id: maxId + 1,
          name: taskName,
          completed: false,
          createdAt: new Date()
        });
      });
      setTaskName('');
    }
  };

  // 切换任务完成状态
  const toggleTaskStatus = (task) => {
    if (realm) {
      realm.write(() => {
        task.completed = !task.completed;
      });
    }
  };

  // 删除任务
  const deleteTask = (taskId) => {
    if (realm) {
      realm.write(() => {
        const task = realm.objectForPrimaryKey('Task', taskId);
        if (task) {
          realm.delete(task);
        }
      });
    }
  };

  // 渲染任务项
  const renderTaskItem = ({ item }) => (
    <View style={styles.taskItem}>
      <Text 
        style={[
          styles.taskText, 
          item.completed && styles.completedTask
        ]}
        onPress={() => toggleTaskStatus(item)}
      >
        {item.name}
      </Text>
      <Button
        title="删除"
        color="red"
        onPress={() => deleteTask(item._id)}
      />
    </View>
  );
  
  return (
    <View style={styles.container}>
      <Text style={styles.title}>Realm数据库示例</Text>
      
      <View style={styles.inputContainer}>
        <TextInput
          style={styles.input}
          value={taskName}
          onChangeText={setTaskName}
          placeholder="添加新任务"
        />
        <Button title="添加" onPress={addTask} />
      </View>
      
      <FlatList
        data={tasks}
        keyExtractor={(item) => item._id.toString()}
        renderItem={renderTaskItem}
        style={styles.list}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 20,
    textAlign: 'center',
  },
  inputContainer: {
    flexDirection: 'row',
    marginBottom: 20,
  },
  input: {
    flex: 1,
    height: 40,
    borderWidth: 1,
    borderColor: '#ccc',
    borderRadius: 5,
    paddingHorizontal: 10,
    marginRight: 10,
  },
  list: {
    flex: 1,
  },
  taskItem: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 10,
    borderBottomWidth: 1,
    borderBottomColor: '#eee',
  },
  taskText: {
    fontSize: 16,
    flex: 1,
  },
  completedTask: {
    textDecorationLine: 'line-through',
    color: '#888',
  },
});
```

### SQLite

React Native也可以通过第三方库使用SQLite数据库。

#### 安装

```bash
npm install react-native-sqlite-storage
```

然后需要链接原生库：

```bash
# RN >= 0.60，iOS平台
cd ios && pod install

# RN < 0.60
react-native link react-native-sqlite-storage
```

#### 基本使用

```jsx
import React, { useEffect, useState } from 'react';
import { View, Text, FlatList, TextInput, Button, StyleSheet } from 'react-native';
import SQLite from 'react-native-sqlite-storage';

// 启用日志
SQLite.DEBUG(true);
// 设置为默认位置
SQLite.enablePromise(true);

export default function SQLiteExample() {
  const [db, setDb] = useState(null);
  const [products, setProducts] = useState([]);
  const [currentProduct, setCurrentProduct] = useState({ name: '', price: '' });

  // 打开数据库
  const openDatabase = async () => {
    try {
      const database = await SQLite.openDatabase(
        { name: 'ProductDB.db', location: 'default' }
      );
      setDb(database);
      return database;
    } catch (error) {
      console.error('打开数据库错误:', error);
    }
  };

  // 创建表
  const createTable = async (database) => {
    const query = `
      CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        price REAL NOT NULL
      )
    `;

    try {
      await database.executeSql(query);
    } catch (error) {
      console.error('创建表错误:', error);
    }
  };

  // 获取所有产品
  const getProducts = async (database) => {
    try {
      const results = await database.executeSql('SELECT * FROM products');
      const rows = results[0].rows;
      let temp = [];
      
      for (let i = 0; i < rows.length; i++) {
        temp.push(rows.item(i));
      }
      
      setProducts(temp);
    } catch (error) {
      console.error('获取产品错误:', error);
    }
  };

  // 添加产品
  const addProduct = async () => {
    if (!currentProduct.name || !currentProduct.price || !db) return;

    try {
      await db.executeSql(
        'INSERT INTO products (name, price) VALUES (?, ?)',
        [currentProduct.name, parseFloat(currentProduct.price)]
      );
      
      setCurrentProduct({ name: '', price: '' });
      getProducts(db);
    } catch (error) {
      console.error('添加产品错误:', error);
    }
  };

  // 删除产品
  const deleteProduct = async (id) => {
    try {
      await db.executeSql('DELETE FROM products WHERE id = ?', [id]);
      getProducts(db);
    } catch (error) {
      console.error('删除产品错误:', error);
    }
  };

  // 初始化数据库和表
  useEffect(() => {
    async function initDatabase() {
      const database = await openDatabase();
      await createTable(database);
      await getProducts(database);
    }
    
    initDatabase();
    
    return () => {
      if (db) {
        db.close();
      }
    };
  }, []);

  // 渲染产品项
  const renderProductItem = ({ item }) => (
    <View style={styles.productItem}>
      <View>
        <Text style={styles.productName}>{item.name}</Text>
        <Text style={styles.productPrice}>¥{item.price.toFixed(2)}</Text>
      </View>
      <Button
        title="删除"
        color="red"
        onPress={() => deleteProduct(item.id)}
      />
    </View>
  );

  return (
    <View style={styles.container}>
      <Text style={styles.title}>SQLite示例</Text>
      
      <View style={styles.form}>
        <TextInput
          style={styles.input}
          placeholder="产品名称"
          value={currentProduct.name}
          onChangeText={(text) => setCurrentProduct({ ...currentProduct, name: text })}
        />
        
        <TextInput
          style={styles.input}
          placeholder="产品价格"
          value={currentProduct.price}
          onChangeText={(text) => setCurrentProduct({ ...currentProduct, price: text })}
          keyboardType="numeric"
        />
        
        <Button title="添加产品" onPress={addProduct} />
      </View>
      
      <FlatList
        data={products}
        keyExtractor={(item) => item.id.toString()}
        renderItem={renderProductItem}
        style={styles.list}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 20,
    textAlign: 'center',
  },
  form: {
    marginBottom: 20,
  },
  input: {
    height: 40,
    borderWidth: 1,
    borderColor: '#ccc',
    borderRadius: 5,
    paddingHorizontal: 10,
    marginBottom: 10,
  },
  list: {
    flex: 1,
  },
  productItem: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 15,
    borderBottomWidth: 1,
    borderBottomColor: '#eee',
  },
  productName: {
    fontSize: 18,
  },
  productPrice: {
    fontSize: 16,
    color: '#666',
  },
});
```

### MMKV

MMKV是一个高效的键值存储库，由微信团队开发，性能优于AsyncStorage。

#### 安装

```bash
npm install react-native-mmkv
```

#### 基本使用

```jsx
import React, { useState } from 'react';
import { View, Text, TextInput, Button, StyleSheet, Switch } from 'react-native';
import { MMKV } from 'react-native-mmkv';

// 创建存储实例
const storage = new MMKV();

export default function MMKVExample() {
  const [key, setKey] = useState('');
  const [value, setValue] = useState('');
  const [storedData, setStoredData] = useState({});
  const [isBoolean, setIsBoolean] = useState(false);
  const [isNumber, setIsNumber] = useState(false);

  // 存储数据
  const saveData = () => {
    if (!key) return;

    if (isBoolean) {
      // 存储布尔值
      const boolValue = value.toLowerCase() === 'true';
      storage.setBool(key, boolValue);
      retrieveAllData();
      return;
    }

    if (isNumber) {
      // 存储数字
      const numValue = Number(value);
      if (!isNaN(numValue)) {
        storage.setNumber(key, numValue);
        retrieveAllData();
      }
      return;
    }

    // 存储字符串
    storage.set(key, value);
    retrieveAllData();
  };

  // 获取所有存储数据
  const retrieveAllData = () => {
    const keys = storage.getAllKeys();
    const data = {};

    keys.forEach(k => {
      const type = storage.valueType(k);
      
      switch (type) {
        case 'boolean':
          data[k] = storage.getBool(k);
          break;
        case 'number':
          data[k] = storage.getNumber(k);
          break;
        case 'string':
          data[k] = storage.getString(k);
          break;
        default:
          data[k] = 'unknown type';
      }
    });

    setStoredData(data);
  };

  // 删除存储项
  const deleteItem = (itemKey) => {
    storage.delete(itemKey);
    retrieveAllData();
  };

  // 清空所有存储
  const clearStorage = () => {
    storage.clearAll();
    setStoredData({});
  };

  // 初始加载存储数据
  React.useEffect(() => {
    retrieveAllData();
  }, []);

  return (
    <View style={styles.container}>
      <Text style={styles.title}>MMKV存储示例</Text>
      
      <View style={styles.inputContainer}>
        <TextInput
          style={styles.input}
          placeholder="键名"
          value={key}
          onChangeText={setKey}
        />
        
        <TextInput
          style={styles.input}
          placeholder="值"
          value={value}
          onChangeText={setValue}
          keyboardType={isNumber ? 'numeric' : 'default'}
        />
        
        <View style={styles.switchContainer}>
          <Text>布尔值:</Text>
          <Switch
            value={isBoolean}
            onValueChange={(val) => {
              setIsBoolean(val);
              if (val) setIsNumber(false);
            }}
          />
          
          <Text style={{ marginLeft: 20 }}>数字:</Text>
          <Switch
            value={isNumber}
            onValueChange={(val) => {
              setIsNumber(val);
              if (val) setIsBoolean(false);
            }}
          />
        </View>
        
        <Button title="保存" onPress={saveData} />
      </View>
      
      <View style={styles.dataContainer}>
        <Text style={styles.subtitle}>存储的数据:</Text>
        
        {Object.keys(storedData).length === 0 ? (
          <Text style={styles.emptyText}>无存储数据</Text>
        ) : (
          Object.keys(storedData).map((k) => (
            <View key={k} style={styles.dataItem}>
              <Text>
                <Text style={styles.dataKey}>{k}:</Text> {' '}
                <Text style={styles.dataValue}>
                  {typeof storedData[k] === 'string' 
                    ? `"${storedData[k]}"` 
                    : String(storedData[k])}
      </Text>
                <Text style={styles.dataType}>
                  ({typeof storedData[k]})
                </Text>
              </Text>
              <Button title="删除" color="red" onPress={() => deleteItem(k)} />
            </View>
          ))
        )}
        
        {Object.keys(storedData).length > 0 && (
          <Button
            title="清空存储"
            color="#ff6b6b"
            onPress={clearStorage}
            style={styles.clearButton}
          />
        )}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 20,
    textAlign: 'center',
  },
  inputContainer: {
    marginBottom: 20,
  },
  input: {
    height: 40,
    borderWidth: 1,
    borderColor: '#ccc',
    borderRadius: 5,
    paddingHorizontal: 10,
    marginBottom: 10,
  },
  switchContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 10,
  },
  dataContainer: {
    flex: 1,
  },
  subtitle: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 10,
  },
  emptyText: {
    fontStyle: 'italic',
    color: '#666',
    textAlign: 'center',
    marginTop: 20,
  },
  dataItem: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 10,
    borderBottomWidth: 1,
    borderBottomColor: '#eee',
  },
  dataKey: {
    fontWeight: 'bold',
  },
  dataValue: {},
  dataType: {
    fontStyle: 'italic',
    color: '#666',
    fontSize: 12,
  },
  clearButton: {
    marginTop: 20,
  },
});
```

### 本地存储最佳实践

1. **选择合适的存储方案**
   - 简单键值对：AsyncStorage 或 MMKV（性能更优）
   - 结构化数据：Realm 或 SQLite
   - 复杂查询需求：SQLite

2. **数据加密**
   - 敏感数据应该使用加密存储
   - 考虑使用 react-native-encrypted-storage

3. **存储层抽象**
   - 创建统一的存储接口，隐藏具体实现
   - 方便未来切换存储机制

4. **处理存储错误**
   - 使用 try/catch 捕获所有存储操作错误
   - 实现适当的错误处理和恢复机制

5. **性能考虑**
   - 避免频繁读写，特别是大型数据
   - 考虑使用内存缓存减少读取操作

6. **数据同步**
   - 实现与服务器数据的同步策略
   - 处理冲突和断网情况 

## 原生模块集成

虽然React Native提供了丰富的API，但有时你需要访问平台特定的API或与现有原生代码交互。React Native允许你创建自定义原生模块和组件，以便在JavaScript中使用。

### 创建原生模块

#### Android原生模块

在Android上创建一个简单的原生模块，首先需要创建一个Java类：

1. **创建原生模块类**:

```java
// android/app/src/main/java/com/yourapp/CustomModule.java

package com.yourapp;

import androidx.annotation.NonNull;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.module.annotations.ReactModule;

@ReactModule(name = CustomModule.NAME)
public class CustomModule extends ReactContextBaseJavaModule {
    public static final String NAME = "CustomModule";

    public CustomModule(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    @NonNull
    public String getName() {
        return NAME;
    }

    // 暴露给JavaScript的方法，使用@ReactMethod注解
    @ReactMethod
    public void showToast(String message, int duration, Promise promise) {
        try {
            // 获取当前Activity的上下文
            android.content.Context context = getReactApplicationContext();
            
            // 显示Toast
            android.widget.Toast.makeText(
                context, 
                message, 
                duration == 0 ? android.widget.Toast.LENGTH_SHORT : android.widget.Toast.LENGTH_LONG
            ).show();
            
            // 成功回调
            promise.resolve("Toast显示成功");
        } catch (Exception e) {
            // 错误回调
            promise.reject("ERR", "显示Toast失败", e);
        }
    }
    
    // 同步方法示例
    @ReactMethod(isBlockingSynchronousMethod = true)
    public String getDeviceInfo() {
        return android.os.Build.MANUFACTURER + " " + android.os.Build.MODEL;
    }
}
```

2. **创建Package类注册模块**:

```java
// android/app/src/main/java/com/yourapp/CustomPackage.java

package com.yourapp;

import androidx.annotation.NonNull;
import com.facebook.react.ReactPackage;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.uimanager.ViewManager;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class CustomPackage implements ReactPackage {
    @NonNull
    @Override
    public List<NativeModule> createNativeModules(@NonNull ReactApplicationContext reactContext) {
        List<NativeModule> modules = new ArrayList<>();
        modules.add(new CustomModule(reactContext));
        return modules;
    }

    @NonNull
    @Override
    public List<ViewManager> createViewManagers(@NonNull ReactApplicationContext reactContext) {
        return Collections.emptyList();
    }
}
```

3. **在MainApplication中注册Package**:

```java
// android/app/src/main/java/com/yourapp/MainApplication.java

// 在getPackages()方法中添加:
@Override
protected List<ReactPackage> getPackages() {
    List<ReactPackage> packages = new PackageList(this).getPackages();
    // 添加自定义Package
    packages.add(new CustomPackage());
    return packages;
}
```

#### iOS原生模块

在iOS上创建一个简单的原生模块：

1. **创建模块头文件**:

```objc
// ios/YourApp/CustomModule.h

#import <React/RCTBridgeModule.h>

@interface CustomModule : NSObject <RCTBridgeModule>
@end
```

2. **实现模块**:

```objc
// ios/YourApp/CustomModule.m

#import "CustomModule.h"
#import <UIKit/UIKit.h>

@implementation CustomModule

// 必须添加此宏以导出模块到JavaScript
RCT_EXPORT_MODULE();

// 暴露方法给JavaScript
RCT_EXPORT_METHOD(showToast:(NSString *)message
                  duration:(NSInteger)duration
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
  dispatch_async(dispatch_get_main_queue(), ^{
    UIWindow *window = [[UIApplication sharedApplication] keyWindow];
    if (window) {
      UIViewController *rootViewController = window.rootViewController;
      
      UIAlertController *alert = [UIAlertController 
                                 alertControllerWithTitle:nil 
                                 message:message 
                                 preferredStyle:UIAlertControllerStyleAlert];
      
      [rootViewController presentViewController:alert animated:YES completion:nil];
      
      int durationInSeconds = (duration == 0) ? 2 : 3.5;
      dispatch_after(dispatch_time(DISPATCH_TIME_NOW, durationInSeconds * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        [alert dismissViewControllerAnimated:YES completion:nil];
        resolve(@"显示成功");
      });
    } else {
      reject(@"ERROR", @"无法获取根视图控制器", nil);
    }
  });
}

// 同步方法(iOS 10+)
RCT_EXPORT_SYNCHRONOUS_TYPED_METHOD(NSString *, getDeviceInfo)
{
  NSString *deviceInfo = [NSString stringWithFormat:@"%@ %@", 
                          [[UIDevice currentDevice] systemName], 
                          [[UIDevice currentDevice] systemVersion]];
  return deviceInfo;
}

// 指定JS线程方法
- (dispatch_queue_t)methodQueue
{
  return dispatch_get_main_queue();
}

// 导出常量
+ (NSDictionary *)constantsToExport
{
  return @{ 
    @"TOAST_SHORT": @0,
    @"TOAST_LONG": @1 
  };
}

@end
```

### 在JavaScript中使用原生模块

使用刚刚创建的原生模块：

```jsx
import React from 'react';
import { Button, View, StyleSheet, Text, NativeModules } from 'react-native';

// 获取原生模块
const { CustomModule } = NativeModules;

export default function NativeModuleExample() {
  // 使用异步方法
  const showToast = () => {
    CustomModule.showToast('这是来自原生模块的消息', 0)
      .then(result => console.log(result))
      .catch(error => console.error(error));
  };

  // 使用同步方法
  const getDeviceInfo = () => {
    try {
      const deviceInfo = CustomModule.getDeviceInfo();
      console.log('设备信息:', deviceInfo);
      return deviceInfo;
    } catch (error) {
      console.error(error);
      return 'Unknown';
    }
  };

  const deviceInfo = getDeviceInfo();

  return (
    <View style={styles.container}>
      <Text style={styles.title}>原生模块示例</Text>
      <Text style={styles.deviceInfo}>设备信息: {deviceInfo}</Text>
      <Button title="显示原生Toast" onPress={showToast} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 20,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 20,
  },
  deviceInfo: {
    fontSize: 16,
    marginBottom: 20,
  },
});
```

### 创建原生UI组件

除了模块，你还可以创建自定义原生UI组件：

#### Android原生UI组件

1. **创建原生视图管理器**:

```java
// android/app/src/main/java/com/yourapp/CustomButtonManager.java

package com.yourapp;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.uimanager.SimpleViewManager;
import com.facebook.react.uimanager.ThemedReactContext;
import com.facebook.react.uimanager.annotations.ReactProp;
import com.facebook.react.common.MapBuilder;

import android.widget.Button;
import android.view.View;
import java.util.Map;

public class CustomButtonManager extends SimpleViewManager<Button> {
    public static final String REACT_CLASS = "CustomButton";

    @Override
    @NonNull
    public String getName() {
        return REACT_CLASS;
    }

    @Override
    @NonNull
    protected Button createViewInstance(@NonNull ThemedReactContext reactContext) {
        Button button = new Button(reactContext);
        button.setAllCaps(false); // 默认不大写
        return button;
    }

    // 设置按钮文本
    @ReactProp(name = "text")
    public void setText(Button view, @Nullable String text) {
        view.setText(text);
    }

    // 设置按钮颜色
    @ReactProp(name = "color")
    public void setColor(Button view, @Nullable String color) {
        if (color != null) {
            try {
                view.setBackgroundColor(android.graphics.Color.parseColor(color));
            } catch (Exception e) {
                // 颜色格式错误，使用默认颜色
            }
        }
    }

    // 添加事件
    @Override
    public Map<String, Object> getExportedCustomDirectEventTypeConstants() {
        return MapBuilder.<String, Object>builder()
            .put("onPress", MapBuilder.of("registrationName", "onPress"))
            .build();
    }

    // 添加命令
    @Override
    public Map<String, Integer> getCommandsMap() {
        return MapBuilder.of(
            "setEnabled", 1,
            "setText", 2
        );
    }

    @Override
    public void receiveCommand(@NonNull Button view, String commandId, @Nullable ReadableArray args) {
        int command = Integer.parseInt(commandId);
        
        switch (command) {
            case 1: // setEnabled
                if (args != null) {
                    boolean isEnabled = args.getBoolean(0);
                    view.setEnabled(isEnabled);
                }
                break;
            case 2: // setText
                if (args != null) {
                    String text = args.getString(0);
                    view.setText(text);
                }
                break;
        }
    }
}
```

2. **在Package类中注册ViewManager**:

```java
// android/app/src/main/java/com/yourapp/CustomPackage.java

@NonNull
@Override
public List<ViewManager> createViewManagers(@NonNull ReactApplicationContext reactContext) {
    List<ViewManager> viewManagers = new ArrayList<>();
    viewManagers.add(new CustomButtonManager());
    return viewManagers;
}
```

#### iOS原生UI组件

1. **创建视图管理器头文件**:

```objc
// ios/YourApp/CustomButtonManager.h

#import <React/RCTViewManager.h>

@interface CustomButtonManager : RCTViewManager
@end
```

2. **实现视图管理器**:

```objc
// ios/YourApp/CustomButtonManager.m

#import "CustomButtonManager.h"
#import <React/RCTUIManager.h>

@implementation CustomButtonManager

RCT_EXPORT_MODULE()

- (UIView *)view
{
  UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
  [button addTarget:self
             action:@selector(buttonPressed:)
   forControlEvents:UIControlEventTouchUpInside];
  return button;
}

// 处理按钮点击
- (void)buttonPressed:(UIButton *)sender
{
  // 向JS发送事件
  if (sender.reactTag) {
    NSDictionary *event = @{};
    [self.bridge.eventDispatcher sendEvent:@{
      @"type": @"onPress",
      @"target": sender.reactTag,
      @"payload": event
    }];
  }
}

// 设置按钮文本
RCT_EXPORT_VIEW_PROPERTY(text, NSString)

// 设置按钮颜色
RCT_CUSTOM_VIEW_PROPERTY(color, NSString, UIButton)
{
  if (json) {
    NSString *colorString = [RCTConvert NSString:json];
    UIColor *color = nil;
    
    // 简单的颜色解析逻辑，实际应用中可能需要更复杂的解析
    if ([colorString isEqualToString:@"red"]) {
      color = [UIColor redColor];
    } else if ([colorString isEqualToString:@"green"]) {
      color = [UIColor greenColor];
    } else if ([colorString isEqualToString:@"blue"]) {
      color = [UIColor blueColor];
    } else {
      color = [UIColor systemBlueColor]; // 默认颜色
    }
    
    [view setBackgroundColor:color];
  }
}

// 命令: 设置按钮状态
RCT_EXPORT_METHOD(setEnabled:(nonnull NSNumber *)reactTag
                  isEnabled:(BOOL)isEnabled)
{
  [self.bridge.uiManager addUIBlock:^(RCTUIManager *uiManager, NSDictionary<NSNumber *,UIView *> *viewRegistry) {
    UIButton *button = (UIButton *)viewRegistry[reactTag];
    if ([button isKindOfClass:[UIButton class]]) {
      [button setEnabled:isEnabled];
    }
  }];
}

// 命令: 设置按钮文本
RCT_EXPORT_METHOD(setText:(nonnull NSNumber *)reactTag
                  text:(NSString *)text)
{
  [self.bridge.uiManager addUIBlock:^(RCTUIManager *uiManager, NSDictionary<NSNumber *,UIView *> *viewRegistry) {
    UIButton *button = (UIButton *)viewRegistry[reactTag];
    if ([button isKindOfClass:[UIButton class]]) {
      [button setTitle:text forState:UIControlStateNormal];
    }
  }];
}

@end
```

### 在JavaScript中使用原生UI组件

为原生组件创建包装组件：

```jsx
// CustomButton.js
import React, { useRef, useImperativeHandle, forwardRef } from 'react';
import { requireNativeComponent, UIManager, findNodeHandle } from 'react-native';

// 导入原生组件
const RCTCustomButton = requireNativeComponent('CustomButton');

// 创建命令助手
const CustomButtonCommands = {
  setEnabled: (viewRef, isEnabled) => {
    UIManager.dispatchViewManagerCommand(
      findNodeHandle(viewRef),
      UIManager.getViewManagerConfig('CustomButton').Commands.setEnabled,
      [isEnabled]
    );
  },
  setText: (viewRef, text) => {
    UIManager.dispatchViewManagerCommand(
      findNodeHandle(viewRef),
      UIManager.getViewManagerConfig('CustomButton').Commands.setText,
      [text]
    );
  }
};

// 创建React组件包装器
const CustomButton = forwardRef((props, ref) => {
  const nativeRef = useRef(null);

  // 暴露命令给父组件
  useImperativeHandle(ref, () => ({
    setEnabled: (isEnabled) => {
      CustomButtonCommands.setEnabled(nativeRef.current, isEnabled);
    },
    setText: (text) => {
      CustomButtonCommands.setText(nativeRef.current, text);
    }
  }));

  return (
    <RCTCustomButton
      {...props}
      ref={nativeRef}
    />
  );
});

export default CustomButton;
```

使用自定义UI组件：

```jsx
// NativeUIComponentExample.js
import React, { useRef } from 'react';
import { View, Button, StyleSheet, Text } from 'react-native';
import CustomButton from './CustomButton';

export default function NativeUIComponentExample() {
  const customButtonRef = useRef(null);

  const handleChangeText = () => {
    if (customButtonRef.current) {
      customButtonRef.current.setText('已更新文本');
    }
  };

  const handleToggleEnabled = () => {
    if (customButtonRef.current) {
      // 这里应该有一个状态变量来跟踪当前状态，简化示例
      const newEnabledState = true;
      customButtonRef.current.setEnabled(newEnabledState);
    }
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>原生UI组件示例</Text>
      
      <CustomButton
        ref={customButtonRef}
        style={styles.customButton}
        text="原生按钮"
        color="#4CAF50"
        onPress={() => console.log('原生按钮被点击')}
      />
      
      <View style={styles.controls}>
        <Button title="更改文本" onPress={handleChangeText} />
        <Button title="切换启用状态" onPress={handleToggleEnabled} />
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 20,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 20,
  },
  customButton: {
    width: 200,
    height: 50,
    marginVertical: 20,
  },
  controls: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    width: '100%',
    marginTop: 20,
  },
});
```

### TurboModules和Fabric

React Native新架构引入了两个关键概念：TurboModules和Fabric，它们提供了更好的性能和类型安全。

#### TurboModules

TurboModules改进了原生模块系统，按需加载原生模块，而不是在启动时全部加载。

主要特点：
- 延迟加载
- 类型安全
- 更好的错误处理
- 直接方法调用

#### Fabric

Fabric是React Native的新渲染系统，它带来了：
- 更流畅的动画
- 更好的手势处理
- 更少的主线程阻塞
- 增强的布局计算

### 原生模块集成最佳实践

1. **按需创建原生模块**
   - 仅当React Native不提供现有API时创建原生模块
   - 在创建自定义模块前，检查是否有现成的社区模块

2. **处理线程**
   - 了解React Native的线程模型
   - 确保耗时操作在正确的线程上执行

3. **异常处理**
   - 妥善处理原生代码中的异常
   - 使用Promise机制传递错误状态

4. **内存管理**
   - 特别是在iOS上，注意对象的生命周期
   - 避免循环引用导致的内存泄漏

5. **API设计**
   - 为原生模块提供清晰、一致的API
   - 提供适当的文档和类型定义

6. **版本兼容性**
   - 处理不同React Native版本的兼容性问题
   - 考虑新架构(TurboModules/Fabric)的迁移路径

## 部署与发布

将React Native应用部署到应用商店是开发过程的最后一步。本节介绍如何为iOS和Android平台准备、构建和发布应用。

### 版本管理

在发布应用前，需要正确设置版本信息：

#### Android版本配置

编辑`android/app/build.gradle`文件：

```gradle
android {
    defaultConfig {
        applicationId "com.yourapp"
        minSdkVersion rootProject.ext.minSdkVersion
        targetSdkVersion rootProject.ext.targetSdkVersion
        versionCode 1        // 每次发布时递增
        versionName "1.0.0"  // 语义化版本号
    }
}
```

#### iOS版本配置

编辑`ios/YourApp/Info.plist`文件，或在Xcode中修改：

```xml
<key>CFBundleShortVersionString</key>
<string>1.0.0</string>
<key>CFBundleVersion</key>
<string>1</string>
```

### 生成应用图标和启动屏幕

#### Android应用图标

1. 在`android/app/src/main/res`目录下，找到各种尺寸的mipmap文件夹
2. 替换ic_launcher.png文件为你的应用图标

可以使用在线工具如[Android Asset Studio](https://romannurik.github.io/AndroidAssetStudio/index.html)生成不同尺寸的图标。

#### iOS应用图标

1. 在Xcode中打开项目
2. 点击项目文件，选择Assets.xcassets
3. 选择AppIcon，添加不同尺寸的图标

可以使用[App Icon Generator](https://appicon.co/)这类在线工具生成所需尺寸的图标。

#### 启动屏幕

推荐使用[react-native-bootsplash](https://github.com/zoontek/react-native-bootsplash)或[react-native-splash-screen](https://github.com/crazycodeboy/react-native-splash-screen)库来实现启动屏幕。

### 准备发布版本

#### Android应用发布准备

1. **创建签名密钥**

```bash
keytool -genkeypair -v -keystore my-release-key.keystore -alias my-key-alias -keyalg RSA -keysize 2048 -validity 10000
```

2. **设置Gradle变量**

创建`android/gradle.properties`文件（如果不存在）：

```properties
MYAPP_UPLOAD_STORE_FILE=my-release-key.keystore
MYAPP_UPLOAD_KEY_ALIAS=my-key-alias
MYAPP_UPLOAD_STORE_PASSWORD=*****
MYAPP_UPLOAD_KEY_PASSWORD=*****
```

3. **配置签名**

编辑`android/app/build.gradle`：

```gradle
android {
    ...
    defaultConfig { ... }
    signingConfigs {
        release {
            storeFile file(MYAPP_UPLOAD_STORE_FILE)
            storePassword MYAPP_UPLOAD_STORE_PASSWORD
            keyAlias MYAPP_UPLOAD_KEY_ALIAS
            keyPassword MYAPP_UPLOAD_KEY_PASSWORD
        }
    }
    buildTypes {
        release {
            ...
            signingConfig signingConfigs.release
        }
    }
}
```

4. **启用Proguard（可选）**

编辑`android/app/build.gradle`：

```gradle
buildTypes {
    release {
        minifyEnabled true
        proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
    }
}
```

#### iOS应用发布准备

1. 在Xcode中打开项目
2. 选择"Generic iOS Device"或具体设备（而非模拟器）
3. 在Xcode菜单中选择Product > Archive
4. 确保已设置正确的Bundle Identifier和Developer Team

### 构建发布版本

#### Android构建发布版本

```bash
# 清理构建文件
cd android
./gradlew clean

# 构建AAB文件（推荐用于Google Play）
./gradlew bundleRelease

# 构建APK文件（适用于其他分发渠道）
./gradlew assembleRelease
```

构建完成后，AAB文件位于`android/app/build/outputs/bundle/release/app-release.aab`，APK文件位于`android/app/build/outputs/apk/release/app-release.apk`。

#### iOS构建发布版本

1. 在Xcode中完成Archive后，点击"Distribute App"
2. 选择分发方式:
   - App Store Connect: 发布到App Store
   - Ad Hoc: 分发到特定设备
   - Enterprise: 企业内部分发
   - Development: 开发测试分发
3. 按照向导完成剩余步骤

### 发布到应用商店

#### Google Play发布

1. 创建Google Play开发者账号（需支付25美元注册费）
2. 登录[Google Play Console](https://play.google.com/console)
3. 创建应用，填写详细信息、截图、宣传图片
4. 上传AAB或APK文件
5. 设置价格和分发国家/地区
6. 完成内容分级调查
7. 提交审核

#### App Store发布

1. 创建Apple开发者账号（年费99美元）
2. 登录[App Store Connect](https://appstoreconnect.apple.com/)
3. 创建新应用，填写元数据、截图、预览视频
4. 通过Xcode上传构建版本
5. 填写App Review信息
6. 提交审核

### 持续集成与部署(CI/CD)

自动化构建和部署可以显著提高开发效率。

#### 使用GitHub Actions

`.github/workflows/build.yml`示例：

```yaml
name: Build and Release

on:
  push:
    branches: [ main ]
    tags: [ 'v*' ]

jobs:
  build-android:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Node.js
        uses: actions/setup-node@v2
        with:
          node-version: '16'
          
      - name: Install dependencies
        run: npm install
        
      - name: Setup JDK
        uses: actions/setup-java@v2
        with:
          distribution: 'adopt'
          java-version: '11'
          
      - name: Setup Android SDK
        uses: android-actions/setup-android@v2
        
      - name: Build Android Release
        run: |
          cd android
          ./gradlew bundleRelease
          
      - name: Upload Artifact
        uses: actions/upload-artifact@v2
        with:
          name: app-release
          path: android/app/build/outputs/bundle/release/app-release.aab
```

#### 使用Fastlane

创建`fastlane/Fastfile`：

```ruby
platform :android do
  desc "Build and upload to Google Play"
  lane :beta do
    gradle(task: "clean bundleRelease")
    upload_to_play_store(track: 'beta')
  end
end

platform :ios do
  desc "Build and upload to TestFlight"
  lane :beta do
    build_app(scheme: "YourApp")
    upload_to_testflight
  end
end
```

### Over-The-Air更新

React Native支持通过Over-The-Air(OTA)更新JavaScript代码而无需重新提交应用商店。

#### 使用CodePush

[Microsoft App Center的CodePush](https://github.com/microsoft/react-native-code-push)是一个流行的OTA更新解决方案。

安装：
```bash
npm install react-native-code-push
```

集成到应用：

```jsx
import codePush from "react-native-code-push";

class App extends Component {
  // ...
}

const codePushOptions = {
  checkFrequency: codePush.CheckFrequency.ON_APP_START,
  installMode: codePush.InstallMode.IMMEDIATE
};

export default codePush(codePushOptions)(App);
```

发布更新：

```bash
appcenter codepush release-react -a <owner>/<app_name> -d Production
```

### 应用监控

部署后监控应用性能和错误对于保持应用质量至关重要。

#### 流行的监控工具

1. **Firebase Crashlytics**：跟踪崩溃和错误
2. **Sentry**：实时错误监控和性能跟踪
3. **New Relic**：应用性能监控
4. **Microsoft App Center**：分析、崩溃报告和推送通知

#### 集成Crashlytics示例

```bash
# 安装依赖
npm install @react-native-firebase/app @react-native-firebase/crashlytics
```

初始化Firebase并报告错误：

```jsx
import crashlytics from '@react-native-firebase/crashlytics';

// 记录用户信息(可选)
crashlytics().setUserId('user123');

// 捕获和报告JavaScript错误
try {
  // 可能抛出错误的代码
} catch (error) {
  crashlytics().recordError(error);
}
```

### 多环境配置

管理不同的环境（开发、测试、生产）是大型应用的关键需求。

#### 使用react-native-config

```bash
npm install react-native-config
```

创建环境文件：

`.env.development`:
```
API_URL=https://dev-api.example.com
```

`.env.production`:
```
API_URL=https://api.example.com
```

使用配置：

```jsx
import Config from 'react-native-config';

fetch(Config.API_URL + '/endpoint');
```

### 部署与发布核对清单

最终发布前的检查清单：

1. **功能测试**
   - 所有核心功能是否正常工作
   - 极端情况和边界条件处理

2. **兼容性测试**
   - 在不同设备和OS版本上测试
   - 横屏/竖屏适配检查

3. **性能验证**
   - 应用启动时间
   - 内存使用和泄漏检查
   - 屏幕流畅度

4. **安全审查**
   - API密钥和敏感数据保护
   - 网络安全（HTTPS等）
   - 数据存储安全

5. **发布资产**
   - 应用图标和启动屏幕
   - 屏幕截图和预览视频
   - 应用描述和关键词

6. **合规性**
   - 隐私政策
   - 使用条款
   - 所需权限的合理性

7. **应用商店特定要求**
   - Apple App Store审查指南
   - Google Play政策

按照这个清单执行发布前的最终检查，可以提高应用通过审核并顺利发布的几率。