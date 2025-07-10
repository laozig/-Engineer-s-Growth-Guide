# React Native 组件与生命周期

React Native 提供了一套完整的组件系统，允许开发者构建高性能的移动应用程序。本文档将深入解析 React Native 的核心组件和组件生命周期。

## 目录

- [核心组件概览](#核心组件概览)
- [视图组件](#视图组件)
- [文本与输入组件](#文本与输入组件)
- [列表组件](#列表组件)
- [导航组件](#导航组件)
- [组件生命周期](#组件生命周期)
- [函数组件与 Hooks](#函数组件与-hooks)
- [类组件生命周期](#类组件生命周期)
- [性能优化](#性能优化)
- [最佳实践](#最佳实践)

## 核心组件概览

React Native 核心组件是构建移动应用的基础。这些组件可直接映射到平台原生 UI 组件。

| React Native 组件 | Android 视图 | iOS 视图 | Web 类比 |
|-----------------|-------------|---------|---------|
| `<View>` | `<ViewGroup>` | `<UIView>` | `<div>` |
| `<Text>` | `<TextView>` | `<UITextView>` | `<span>` |
| `<Image>` | `<ImageView>` | `<UIImageView>` | `<img>` |
| `<ScrollView>` | `<ScrollView>` | `<UIScrollView>` | `<div>` |
| `<TextInput>` | `<EditText>` | `<UITextField>` | `<input>` |
| `<TouchableOpacity>` | `<Button>` | `<UIButton>` | `<button>` |

## 视图组件

### View

`View` 是 React Native 中最基础的组件，相当于 Web 开发中的 `div`。

```jsx
import { View, StyleSheet } from 'react-native';

const ViewExample = () => {
  return (
    <View style={styles.container}>
      <View style={styles.box} />
      <View style={styles.box} />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    flexDirection: 'row',
    justifyContent: 'center',
    alignItems: 'center',
  },
  box: {
    width: 100,
    height: 100,
    backgroundColor: '#3498db',
    margin: 10,
  }
});
```

### SafeAreaView

`SafeAreaView` 用于在 iOS 设备上确保内容不会被顶部状态栏或底部的 Home 指示器遮挡。

```jsx
import { SafeAreaView, StyleSheet, Text } from 'react-native';

const SafeAreaViewExample = () => {
  return (
    <SafeAreaView style={styles.container}>
      <Text>内容安全区域内显示</Text>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#ffffff',
  },
});
```

### Image

`Image` 组件用于显示各种类型的图像。

```jsx
import { View, Image, StyleSheet } from 'react-native';

const ImageExample = () => {
  return (
    <View style={styles.container}>
      {/* 本地图像 */}
      <Image 
        source={require('./assets/logo.png')} 
        style={styles.localImage} 
      />
      
      {/* 网络图像 */}
      <Image 
        source={{ uri: 'https://reactnative.dev/img/tiny_logo.png' }} 
        style={styles.remoteImage}
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  localImage: {
    width: 200,
    height: 200,
    marginBottom: 20,
  },
  remoteImage: {
    width: 100,
    height: 100,
  },
});
```

## 文本与输入组件

### Text

`Text` 组件用于显示文本内容。

```jsx
import { Text, StyleSheet } from 'react-native';

const TextExample = () => {
  return (
    <Text style={styles.text}>
      普通文本
      <Text style={styles.bold}>粗体文本</Text>
      <Text style={styles.italic}>斜体文本</Text>
    </Text>
  );
};

const styles = StyleSheet.create({
  text: {
    fontSize: 16,
    color: '#333333',
  },
  bold: {
    fontWeight: 'bold',
  },
  italic: {
    fontStyle: 'italic',
  },
});
```

### TextInput

`TextInput` 用于接收用户输入的文本。

```jsx
import { useState } from 'react';
import { View, TextInput, StyleSheet, Text } from 'react-native';

const TextInputExample = () => {
  const [text, setText] = useState('');
  
  return (
    <View style={styles.container}>
      <TextInput
        style={styles.input}
        placeholder="请输入内容"
        value={text}
        onChangeText={setText}
      />
      <Text style={styles.output}>您输入了: {text}</Text>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    padding: 20,
  },
  input: {
    height: 40,
    borderColor: '#cccccc',
    borderWidth: 1,
    borderRadius: 5,
    paddingHorizontal: 10,
  },
  output: {
    marginTop: 10,
  },
});
```

## 列表组件

### FlatList

`FlatList` 是高性能的列表组件，适用于长列表数据。

```jsx
import { FlatList, Text, StyleSheet, View } from 'react-native';

const data = Array.from({ length: 50 }, (_, index) => ({
  id: `item-${index}`,
  title: `列表项 ${index}`,
}));

const FlatListExample = () => {
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
};

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

### SectionList

`SectionList` 用于显示分组列表数据。

```jsx
import { SectionList, Text, StyleSheet, View } from 'react-native';

const DATA = [
  {
    title: '水果',
    data: ['苹果', '香蕉', '橙子'],
  },
  {
    title: '蔬菜',
    data: ['西红柿', '黄瓜', '胡萝卜'],
  },
  {
    title: '肉类',
    data: ['牛肉', '猪肉', '鸡肉'],
  },
];

const SectionListExample = () => {
  return (
    <SectionList
      sections={DATA}
      keyExtractor={(item, index) => item + index}
      renderItem={({ item }) => (
        <View style={styles.item}>
          <Text style={styles.itemText}>{item}</Text>
        </View>
      )}
      renderSectionHeader={({ section: { title } }) => (
        <Text style={styles.sectionHeader}>{title}</Text>
      )}
    />
  );
};

const styles = StyleSheet.create({
  item: {
    backgroundColor: '#ffffff',
    padding: 15,
    borderBottomWidth: 1,
    borderBottomColor: '#eeeeee',
  },
  itemText: {
    fontSize: 16,
  },
  sectionHeader: {
    backgroundColor: '#f2f2f2',
    padding: 10,
    fontSize: 18,
    fontWeight: 'bold',
  },
});
```

## 导航组件

React Navigation 是 React Native 应用中最常用的导航库。

```jsx
import { NavigationContainer } from '@react-navigation/native';
import { createStackNavigator } from '@react-navigation/stack';

const Stack = createStackNavigator();

function HomeScreen({ navigation }) {
  return (
    <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center' }}>
      <Text>Home Screen</Text>
      <Button
        title="Go to Details"
        onPress={() => navigation.navigate('Details')}
      />
    </View>
  );
}

function DetailsScreen() {
  return (
    <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center' }}>
      <Text>Details Screen</Text>
    </View>
  );
}

function NavigationExample() {
  return (
    <NavigationContainer>
      <Stack.Navigator initialRouteName="Home">
        <Stack.Screen 
          name="Home" 
          component={HomeScreen} 
          options={{ title: 'Overview' }}
        />
        <Stack.Screen name="Details" component={DetailsScreen} />
      </Stack.Navigator>
    </NavigationContainer>
  );
}
```

## 组件生命周期

React Native 组件的生命周期分为函数组件（使用 Hooks）和类组件两种形式。

## 函数组件与 Hooks

函数组件使用 Hooks API 管理状态和副作用，替代了类组件的生命周期方法。

### useState

用于在函数组件中添加状态。

```jsx
import { useState } from 'react';
import { View, Text, Button } from 'react-native';

function Counter() {
  const [count, setCount] = useState(0);
  
  return (
    <View>
      <Text>当前计数: {count}</Text>
      <Button title="增加" onPress={() => setCount(count + 1)} />
    </View>
  );
}
```

### useEffect

用于处理组件的副作用，相当于类组件中的多个生命周期方法的组合。

```jsx
import { useState, useEffect } from 'react';
import { View, Text } from 'react-native';

function DataFetcher() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    // 组件挂载时执行，相当于 componentDidMount
    fetch('https://api.example.com/data')
      .then(response => response.json())
      .then(json => {
        setData(json);
        setLoading(false);
      })
      .catch(error => {
        console.error(error);
        setLoading(false);
      });
      
    // 返回清理函数，相当于 componentWillUnmount
    return () => {
      // 执行清理操作，如取消网络请求
    };
  }, []); // 空依赖数组表示仅在组件挂载和卸载时执行
  
  if (loading) {
    return <Text>加载中...</Text>;
  }
  
  return (
    <View>
      <Text>{JSON.stringify(data)}</Text>
    </View>
  );
}
```

### useContext

用于消费 React 上下文。

```jsx
import { createContext, useContext } from 'react';
import { View, Text } from 'react-native';

// 创建上下文
const ThemeContext = createContext('light');

function ThemedText() {
  // 使用上下文
  const theme = useContext(ThemeContext);
  
  return (
    <Text style={{ 
      color: theme === 'dark' ? 'white' : 'black',
      backgroundColor: theme === 'dark' ? 'black' : 'white'
    }}>
      当前主题: {theme}
    </Text>
  );
}

function ContextExample() {
  return (
    <ThemeContext.Provider value="dark">
      <View style={{ padding: 20 }}>
        <ThemedText />
      </View>
    </ThemeContext.Provider>
  );
}
```

## 类组件生命周期

尽管 React 团队鼓励使用函数组件和 Hooks，但理解类组件的生命周期仍然很重要，尤其是在维护旧项目时。

### 挂载阶段

组件实例被创建并插入到 DOM 中时，这些方法会被调用：

1. `constructor()` - 初始化状态和绑定方法
2. `static getDerivedStateFromProps()` - 在渲染前更新状态
3. `render()` - 必需方法，返回要渲染的元素
4. `componentDidMount()` - 组件挂载后执行，适合进行网络请求

```jsx
import { Component } from 'react';
import { View, Text } from 'react-native';

class MountExample extends Component {
  constructor(props) {
    super(props);
    this.state = {
      data: null,
    };
    console.log('1. Constructor');
  }
  
  static getDerivedStateFromProps(props, state) {
    console.log('2. getDerivedStateFromProps');
    return null; // 返回一个对象来更新状态，或null表示不更新
  }
  
  componentDidMount() {
    console.log('4. componentDidMount');
    // 发起网络请求
    fetch('https://api.example.com/data')
      .then(response => response.json())
      .then(json => this.setState({ data: json }));
  }
  
  render() {
    console.log('3. render');
    return (
      <View>
        <Text>挂载阶段示例</Text>
      </View>
    );
  }
}
```

### 更新阶段

当组件的 props 或 state 发生变化时，这些方法会被调用：

1. `static getDerivedStateFromProps()` - 同挂载阶段
2. `shouldComponentUpdate()` - 决定组件是否应该更新
3. `render()` - 重新渲染
4. `getSnapshotBeforeUpdate()` - 在更新前获取一些信息
5. `componentDidUpdate()` - 更新后执行

```jsx
class UpdateExample extends Component {
  shouldComponentUpdate(nextProps, nextState) {
    console.log('2. shouldComponentUpdate');
    // 返回true允许更新，false阻止更新
    return true;
  }
  
  getSnapshotBeforeUpdate(prevProps, prevState) {
    console.log('4. getSnapshotBeforeUpdate');
    // 返回值将作为componentDidUpdate的第三个参数
    return { scrollPosition: 200 };
  }
  
  componentDidUpdate(prevProps, prevState, snapshot) {
    console.log('5. componentDidUpdate', snapshot);
    // 可以进行DOM操作或发起网络请求
  }
  
  render() {
    console.log('3. render');
    return (
      <View>
        <Text>更新阶段示例</Text>
      </View>
    );
  }
}
```

### 卸载阶段

当组件从 DOM 中移除时，会调用：

```jsx
class UnmountExample extends Component {
  componentWillUnmount() {
    console.log('componentWillUnmount');
    // 执行清理操作，如取消定时器、取消网络请求
  }
  
  render() {
    return (
      <View>
        <Text>卸载阶段示例</Text>
      </View>
    );
  }
}
```

## 性能优化

### 使用 React.memo 优化函数组件

```jsx
import { memo } from 'react';
import { Text } from 'react-native';

const ExpensiveComponent = memo(({ value }) => {
  console.log('渲染 ExpensiveComponent');
  return <Text>值: {value}</Text>;
});
```

### PureComponent 优化类组件

```jsx
import { PureComponent } from 'react';
import { Text } from 'react-native';

class OptimizedComponent extends PureComponent {
  render() {
    console.log('渲染 OptimizedComponent');
    return <Text>值: {this.props.value}</Text>;
  }
}
```

### 使用 useMemo 和 useCallback

```jsx
import { useState, useMemo, useCallback } from 'react';
import { View, Text, Button } from 'react-native';

function OptimizedExample() {
  const [count, setCount] = useState(0);
  
  // 计算密集型操作被缓存
  const expensiveResult = useMemo(() => {
    console.log('执行昂贵计算');
    let result = 0;
    for (let i = 0; i < 10000; i++) {
      result += count;
    }
    return result;
  }, [count]); // 仅当count变化时重新计算
  
  // 回调函数被缓存
  const handlePress = useCallback(() => {
    setCount(c => c + 1);
  }, []); // 空依赖数组表示回调不会重新创建
  
  return (
    <View>
      <Text>Count: {count}</Text>
      <Text>计算结果: {expensiveResult}</Text>
      <Button title="增加" onPress={handlePress} />
    </View>
  );
}
```

## 最佳实践

### 组件拆分

将大型组件拆分为小型、功能单一的组件，提高可维护性和复用性。

```jsx
// 不好的做法: 一个大型组件
function BigComponent() {
  return (
    <View>
      <Text>标题</Text>
      <TextInput placeholder="搜索" />
      <FlatList data={data} renderItem={renderItem} />
      {/* 其他大量UI元素 */}
    </View>
  );
}

// 好的做法: 拆分为小型组件
function Header() {
  return <Text>标题</Text>;
}

function SearchBar() {
  return <TextInput placeholder="搜索" />;
}

function ItemList({ data }) {
  return <FlatList data={data} renderItem={renderItem} />;
}

function BetterComponent() {
  return (
    <View>
      <Header />
      <SearchBar />
      <ItemList data={data} />
    </View>
  );
}
```

### 避免内联函数和对象

在渲染方法中创建内联函数或对象会导致每次渲染都创建新实例，影响性能。

```jsx
// 不好的做法
function BadPractice() {
  return (
    <Button 
      onPress={() => console.log('Pressed')} // 每次渲染都创建新函数
      style={{ padding: 10 }} // 每次渲染都创建新对象
    />
  );
}

// 好的做法
function GoodPractice() {
  const handlePress = useCallback(() => {
    console.log('Pressed');
  }, []);
  
  const buttonStyle = useMemo(() => ({ 
    padding: 10 
  }), []);
  
  return <Button onPress={handlePress} style={buttonStyle} />;
}
```

### 使用PropTypes进行类型检查

在不使用TypeScript的项目中，应使用PropTypes进行类型检查。

```jsx
import PropTypes from 'prop-types';
import { View, Text } from 'react-native';

function UserProfile({ name, age, isActive }) {
  return (
    <View>
      <Text>名称: {name}</Text>
      <Text>年龄: {age}</Text>
      <Text>状态: {isActive ? '活跃' : '非活跃'}</Text>
    </View>
  );
}

UserProfile.propTypes = {
  name: PropTypes.string.isRequired,
  age: PropTypes.number,
  isActive: PropTypes.bool,
};

UserProfile.defaultProps = {
  age: 0,
  isActive: false,
};
```

## 总结

React Native 组件系统结合了 React 的强大声明式编程模型与原生平台的性能。无论是使用现代的函数组件和 Hooks 还是传统的类组件，了解组件的生命周期和性能优化技术对于构建高质量的移动应用至关重要。

随着 React 和 React Native 的不断发展，推荐优先使用函数组件和 Hooks，它们提供了更简洁、更易于理解和测试的代码结构。不过，了解类组件的生命周期仍然对于维护现有代码库和理解 React 的工作原理很重要。 