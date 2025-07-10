# React Native 性能优化

性能是移动应用成功的关键因素。即使功能再强大，如果应用运行缓慢或消耗过多资源，用户体验也会大打折扣。本文档提供全面的 React Native 性能优化指南，帮助开发者构建流畅、高效的应用。

## 目录

- [性能问题的识别](#性能问题的识别)
- [JavaScript 优化](#javascript-优化)
- [渲染性能优化](#渲染性能优化)
- [列表优化](#列表优化)
- [图像优化](#图像优化)
- [网络请求优化](#网络请求优化)
- [导航优化](#导航优化)
- [动画优化](#动画优化)
- [内存管理](#内存管理)
- [启动性能优化](#启动性能优化)
- [原生模块优化](#原生模块优化)
- [新架构的性能提升](#新架构的性能提升)
- [性能测试和监控](#性能测试和监控)
- [最佳实践总结](#最佳实践总结)

## 性能问题的识别

在进行任何优化之前，首先要准确识别性能瓶颈。

### 使用开发者菜单

React Native 提供了内置的开发者菜单，可以帮助识别问题：

- **Performance Monitor**: 显示帧率和 JS 线程、UI 线程的性能
- **Debug JS Remotely**: 在 Chrome 开发者工具中分析性能
- **Show Perf Monitor**: 显示 FPS 监视器

### 使用 Flipper 进行分析

[Flipper](https://fbflipper.com/) 是一个用于调试 React Native 应用的平台，它提供以下功能：

- React DevTools 集成
- 网络请求监控
- Metro 捆绑器监控
- 布局检查

```bash
# 安装 Flipper (macOS)
brew cask install flipper
```

### 使用 Chrome 性能工具

```javascript
// 在关键代码周围添加性能标记
performance.mark('myFunctionStart');
doExpensiveTask();
performance.mark('myFunctionEnd');
performance.measure('myFunction', 'myFunctionStart', 'myFunctionEnd');
```

### 使用 React DevTools Profiler

React DevTools 提供了专业的 Profiler 工具，可以记录和分析组件渲染性能。

```bash
# 安装 React DevTools
npm install -g react-devtools
```

## JavaScript 优化

JavaScript 执行效率直接影响应用响应速度。

### 避免不必要的渲染

```jsx
// 不好的做法: 内联对象导致不必要的重新渲染
<MyComponent style={{ margin: 10 }} />

// 好的做法: 使用常量样式
const styles = StyleSheet.create({
  item: { margin: 10 }
});
<MyComponent style={styles.item} />
```

### 使用 React.memo() 和 useMemo()

```jsx
// 组件记忆化
const MyComponent = React.memo(function MyComponent(props) {
  return <Text>{props.text}</Text>;
});

// 值记忆化
function ParentComponent() {
  const [a, setA] = useState(0);
  const [b, setB] = useState(0);
  
  // 只有当 a 改变时才重新计算
  const result = useMemo(() => {
    return expensiveCalculation(a);
  }, [a]);
  
  return <ChildComponent result={result} />;
}
```

### 使用 useCallback 记忆化函数

```jsx
function ParentComponent() {
  const [count, setCount] = useState(0);
  
  // 只有当 count 改变时才创建新函数
  const handleClick = useCallback(() => {
    console.log(`Count: ${count}`);
  }, [count]);
  
  return <ChildComponent onClick={handleClick} />;
}
```

### 避免在渲染过程中进行大量计算

```jsx
// 不好的做法: 在渲染函数中进行大量计算
function BadComponent({ data }) {
  const processedData = heavyProcessing(data); // 每次渲染都会执行
  return <Text>{processedData}</Text>;
}

// 好的做法: 使用 useMemo
function GoodComponent({ data }) {
  const processedData = useMemo(() => {
    return heavyProcessing(data);
  }, [data]);
  return <Text>{processedData}</Text>;
}
```

### 避免使用大量闭包

闭包可能导致内存泄漏，特别是在事件处理程序中：

```jsx
// 不好的做法: 过度使用闭包
function BadComponent() {
  const [items, setItems] = useState([]);
  
  return (
    <View>
      {items.map((item) => (
        <TouchableOpacity
          key={item.id}
          onPress={() => {
            // 每个项都有自己的闭包函数实例
            console.log(item);
            doSomething(item);
          }}
        >
          <Text>{item.name}</Text>
        </TouchableOpacity>
      ))}
    </View>
  );
}

// 好的做法: 使用 useCallback 和函数参数
function GoodComponent() {
  const [items, setItems] = useState([]);
  
  const handlePress = useCallback((item) => {
    console.log(item);
    doSomething(item);
  }, []);
  
  return (
    <View>
      {items.map((item) => (
        <TouchableOpacity
          key={item.id}
          onPress={() => handlePress(item)}
        >
          <Text>{item.name}</Text>
        </TouchableOpacity>
      ))}
    </View>
  );
}
```

## 渲染性能优化

### 减少重新渲染

使用 `shouldComponentUpdate` 或 `React.memo` 减少不必要的重新渲染：

```jsx
class MyComponent extends React.Component {
  shouldComponentUpdate(nextProps, nextState) {
    // 只有当 id 改变时才更新
    return this.props.id !== nextProps.id;
  }
  
  render() {
    return <Text>{this.props.title}</Text>;
  }
}

// 使用 React.memo 的函数组件版本
const MyComponent = React.memo(
  function MyComponent({ title, id }) {
    return <Text>{title}</Text>;
  },
  (prevProps, nextProps) => {
    // 返回 true 表示不需要重新渲染
    return prevProps.id === nextProps.id;
  }
);
```

### 延迟加载组件

```jsx
import React, { Suspense, lazy } from 'react';

// 延迟加载大型组件
const HeavyComponent = lazy(() => import('./HeavyComponent'));

function MyComponent() {
  return (
    <Suspense fallback={<ActivityIndicator />}>
      <HeavyComponent />
    </Suspense>
  );
}
```

### 使用 PureComponent

```jsx
class MyPureComponent extends React.PureComponent {
  render() {
    return <Text>{this.props.title}</Text>;
  }
}
```

### 使用 React.Fragment 减少嵌套视图

```jsx
// 不好的做法: 不必要的 View 容器
function BadComponent() {
  return (
    <View>
      <Text>Item 1</Text>
      <Text>Item 2</Text>
    </View>
  );
}

// 好的做法: 使用 Fragment
function GoodComponent() {
  return (
    <>
      <Text>Item 1</Text>
      <Text>Item 2</Text>
    </>
  );
}
```

## 列表优化

列表是移动应用中常见的性能瓶颈。

### 使用 FlatList 和 SectionList

```jsx
import { FlatList } from 'react-native';

function OptimizedList({ data }) {
  const renderItem = ({ item }) => (
    <ListItem title={item.title} />
  );
  
  const keyExtractor = (item) => item.id.toString();
  
  return (
    <FlatList
      data={data}
      renderItem={renderItem}
      keyExtractor={keyExtractor}
      // 性能优化属性
      initialNumToRender={10} // 初始渲染数量
      maxToRenderPerBatch={10} // 每批次渲染的最大数量
      windowSize={5} // 视口的项目数
      removeClippedSubviews={true} // 移除屏幕外的组件
      updateCellsBatchingPeriod={50} // 批量更新的毫秒数
    />
  );
}
```

### 优化 renderItem 函数

```jsx
// 将 renderItem 提取到组件外部并用 React.memo 包装
const ListItem = React.memo(function ListItem({ title, onPress }) {
  return (
    <TouchableOpacity onPress={onPress}>
      <Text>{title}</Text>
    </TouchableOpacity>
  );
});

function MyList({ data }) {
  // 记忆化 renderItem 函数
  const renderItem = useCallback(({ item }) => {
    return <ListItem title={item.title} onPress={() => handlePress(item)} />;
  }, []);
  
  return (
    <FlatList
      data={data}
      renderItem={renderItem}
      keyExtractor={item => item.id.toString()}
    />
  );
}
```

### 使用 getItemLayout 优化滚动性能

如果项目高度固定，可以使用 `getItemLayout` 优化滚动性能：

```jsx
const ITEM_HEIGHT = 80; // 固定高度

function MyList({ data }) {
  const getItemLayout = (data, index) => ({
    length: ITEM_HEIGHT,
    offset: ITEM_HEIGHT * index,
    index,
  });
  
  return (
    <FlatList
      data={data}
      renderItem={renderItem}
      keyExtractor={keyExtractor}
      getItemLayout={getItemLayout}
    />
  );
}
```

## 图像优化

图像处理对性能影响很大，合理优化可显著提升应用体验。

### 使用适当的图像尺寸

```jsx
// 不好的做法: 使用过大的图像然后缩小
<Image 
  source={require('./large-image-4000x3000.png')} 
  style={{ width: 100, height: 100 }} 
/>

// 好的做法: 使用合适尺寸的图像
<Image 
  source={require('./thumbnail-200x200.png')} 
  style={{ width: 100, height: 100 }} 
/>
```

### 使用 resize 模式

```jsx
<Image
  source={{ uri: 'https://example.com/large-image.jpg' }}
  style={{ width: 100, height: 100 }}
  resizeMode="cover" // 'cover', 'contain', 'stretch', 'repeat', 'center'
/>
```

### 使用缓存

```jsx
import FastImage from 'react-native-fast-image';

// 使用 FastImage 代替 Image 组件
<FastImage
  style={{ width: 100, height: 100 }}
  source={{
    uri: 'https://example.com/image.jpg',
    // 缓存策略
    cache: FastImage.cacheControl.immutable,
    // 优先级
    priority: FastImage.priority.normal,
  }}
/>
```

### 使用渐进式加载

```jsx
function ProgressiveImage({ thumbnailSource, source, style }) {
  const [isLoaded, setIsLoaded] = useState(false);
  
  return (
    <View style={style}>
      <Image
        source={thumbnailSource}
        style={[style, { opacity: isLoaded ? 0 : 1 }]}
        blurRadius={1}
      />
      <Image
        source={source}
        style={[style, { opacity: isLoaded ? 1 : 0 }]}
        onLoad={() => setIsLoaded(true)}
      />
    </View>
  );
}

// 使用
<ProgressiveImage
  thumbnailSource={{ uri: 'https://example.com/thumbnail.jpg' }}
  source={{ uri: 'https://example.com/large-image.jpg' }}
  style={{ width: 300, height: 200 }}
/>
```

### 图像懒加载

```jsx
function LazyLoadImage({ uri, style }) {
  const [showImage, setShowImage] = useState(false);
  
  const onViewRef = useRef(({ viewableItems }) => {
    if (viewableItems.length > 0) {
      setShowImage(true);
    }
  });
  
  return (
    <View style={style}>
      {showImage ? (
        <Image source={{ uri }} style={style} />
      ) : (
        <View style={[style, { backgroundColor: '#f0f0f0' }]} />
      )}
    </View>
  );
}
```

## 网络请求优化

### 数据缓存

使用库如 `react-query` 或 `SWR` 进行数据缓存：

```jsx
import { useQuery } from 'react-query';

function UserProfile({ userId }) {
  const fetchUser = async () => {
    const response = await fetch(`https://api.example.com/users/${userId}`);
    return response.json();
  };
  
  const { data, isLoading, error } = useQuery(['user', userId], fetchUser, {
    cacheTime: 5 * 60 * 1000, // 缓存 5 分钟
    staleTime: 60 * 1000, // 1 分钟内不重新获取
  });
  
  if (isLoading) return <ActivityIndicator />;
  if (error) return <Text>Error: {error.message}</Text>;
  
  return <Text>Hello, {data.name}</Text>;
}
```

### 请求防抖和节流

```jsx
import { debounce } from 'lodash';
import { useState, useCallback } from 'react';

function SearchComponent() {
  const [searchTerm, setSearchTerm] = useState('');
  const [results, setResults] = useState([]);
  
  // 防抖搜索请求
  const debouncedSearch = useCallback(
    debounce(async (term) => {
      try {
        const response = await fetch(`https://api.example.com/search?q=${term}`);
        const data = await response.json();
        setResults(data);
      } catch (error) {
        console.error('Search failed:', error);
      }
    }, 500), // 500ms 防抖时间
    []
  );
  
  const handleSearch = (text) => {
    setSearchTerm(text);
    debouncedSearch(text);
  };
  
  return (
    <View>
      <TextInput
        value={searchTerm}
        onChangeText={handleSearch}
        placeholder="Search..."
      />
      <FlatList
        data={results}
        renderItem={({ item }) => <Text>{item.name}</Text>}
        keyExtractor={item => item.id.toString()}
      />
    </View>
  );
}
```

### 使用批量请求

```jsx
// 不好的做法: 多个单独请求
const fetchUserData = async (userId) => {
  const userInfo = await fetch(`/api/users/${userId}`).then(r => r.json());
  const userPosts = await fetch(`/api/users/${userId}/posts`).then(r => r.json());
  const userFollowers = await fetch(`/api/users/${userId}/followers`).then(r => r.json());
  
  return { userInfo, userPosts, userFollowers };
};

// 好的做法: 使用批量请求
const fetchUserData = async (userId) => {
  const response = await fetch(`/api/users/${userId}/batch`, {
    method: 'POST',
    body: JSON.stringify({
      include: ['info', 'posts', 'followers']
    })
  }).then(r => r.json());
  
  return response;
};
```

## 导航优化

导航转场是用户体验的重要部分，平滑的导航可以显著提升应用感知性能。

### 预加载屏幕

```jsx
import { createStackNavigator } from '@react-navigation/stack';

const Stack = createStackNavigator();

function AppNavigator() {
  return (
    <Stack.Navigator>
      <Stack.Screen name="Home" component={HomeScreen} />
      <Stack.Screen 
        name="Details" 
        component={DetailsScreen}
        options={{
          // 开启屏幕预加载
          animationEnabled: true,
          animationTypeForReplace: 'push',
        }}
      />
    </Stack.Navigator>
  );
}
```

### 减少导航堆栈深度

```jsx
// 不好的做法: 嵌套导航
function A() {
  return <Stack.Screen component={B} />;
}
function B() {
  return <Stack.Screen component={C} />;
}
function C() {
  // 嵌套太深

  // 返回到 A 需要多次 goBack()
  const goBackToA = () => {
    navigation.goBack();
    navigation.goBack();
  };
}

// 好的做法: 扁平化导航
function Navigator() {
  return (
    <Stack.Navigator>
      <Stack.Screen name="A" component={A} />
      <Stack.Screen name="B" component={B} />
      <Stack.Screen name="C" component={C} />
    </Stack.Navigator>
  );
}

function C() {
  // 直接返回到 A
  const goToA = () => {
    navigation.navigate('A');
  };
}
```

### 使用 React Navigation 的性能优化

```jsx
import { NavigationContainer } from '@react-navigation/native';
import { enableScreens } from 'react-native-screens';

// 启用原生屏幕容器
enableScreens();

function App() {
  return (
    <NavigationContainer>
      <Stack.Navigator />
    </NavigationContainer>
  );
}
```

## 动画优化

### 使用原生动画驱动

```jsx
import { Animated } from 'react-native';

function FadeInView({ children }) {
  const opacity = useRef(new Animated.Value(0)).current;
  
  useEffect(() => {
    Animated.timing(opacity, {
      toValue: 1,
      duration: 500,
      useNativeDriver: true, // 使用原生动画驱动
    }).start();
  }, []);
  
  return (
    <Animated.View style={{ opacity }}>
      {children}
    </Animated.View>
  );
}
```

### 使用 React Native Reanimated 2

```jsx
import Animated, {
  useSharedValue,
  useAnimatedStyle,
  withSpring,
} from 'react-native-reanimated';

function AnimatedBox() {
  const offset = useSharedValue(0);
  
  const animatedStyles = useAnimatedStyle(() => {
    return {
      transform: [{ translateX: offset.value }],
    };
  });
  
  const handlePress = () => {
    offset.value = withSpring(offset.value + 50);
  };
  
  return (
    <View>
      <Animated.View style={[styles.box, animatedStyles]} />
      <Button onPress={handlePress} title="Move" />
    </View>
  );
}
```

## 内存管理

### 避免内存泄漏

```jsx
function Component() {
  useEffect(() => {
    const subscription = someEventEmitter.addListener('event', handleEvent);
    
    // 清理函数
    return () => {
      subscription.remove();
    };
  }, []);
}
```

### 使用 InteractionManager

```jsx
import { InteractionManager } from 'react-native';

function MyComponent() {
  const [data, setData] = useState(null);
  
  useEffect(() => {
    // 等待交互和动画完成后执行
    const task = InteractionManager.runAfterInteractions(() => {
      fetchData().then(setData);
    });
    
    return () => task.cancel();
  }, []);
  
  return (
    // 渲染组件
  );
}
```

### 减少 Blob 的使用

```jsx
// 不好的做法: 在内存中保存大量二进制数据
async function handleFileUpload(fileUri) {
  const response = await fetch(fileUri);
  const blob = await response.blob();
  uploadFile(blob); // 可能导致内存问题
}

// 好的做法: 使用流式处理
import RNFS from 'react-native-fs';

async function handleFileUpload(fileUri) {
  const fileStream = RNFS.readFileStream(fileUri, { bufferSize: 1024 * 1024 });
  uploadFileStream(fileStream);
}
```

## 启动性能优化

### 使用 Hermes 引擎

在 `android/app/build.gradle` 中启用 Hermes：

```gradle
project.ext.react = [
  enableHermes: true  // 启用 Hermes
]
```

### 延迟加载非关键组件

```jsx
import { AppRegistry, Text } from 'react-native';

// 主应用入口
function App() {
  return (
    <View>
      <Text>App loaded</Text>
    </View>
  );
}

// 启动时只加载关键组件
AppRegistry.registerComponent('App', () => App);

// 延迟加载非关键组件
setTimeout(() => {
  // 加载分析、推送通知等非关键服务
  setupAnalytics();
  setupPushNotifications();
}, 3000);
```

### 优化字体加载

```jsx
import { Text } from 'react-native';
import AppLoading from 'expo-app-loading';
import * as Font from 'expo-font';
import { useState, useEffect } from 'react';

function App() {
  const [fontsLoaded, setFontsLoaded] = useState(false);
  
  useEffect(() => {
    async function loadFonts() {
      await Font.loadAsync({
        'custom-font': require('./assets/fonts/CustomFont.ttf'),
      });
      setFontsLoaded(true);
    }
    
    loadFonts();
  }, []);
  
  if (!fontsLoaded) {
    return <AppLoading />;
  }
  
  return (
    <Text style={{ fontFamily: 'custom-font' }}>
      Text with custom font
    </Text>
  );
}
```

## 原生模块优化

### 批处理原生调用

```javascript
// 不好的做法: 多次桥接调用
NativeModule.setItem('key1', 'value1');
NativeModule.setItem('key2', 'value2');
NativeModule.setItem('key3', 'value3');

// 好的做法: 批处理
NativeModule.multiSet([
  ['key1', 'value1'],
  ['key2', 'value2'],
  ['key3', 'value3']
]);
```

### 使用 Turbo Modules

```javascript
// 传统方式
import { NativeModules } from 'react-native';
const { CalendarModule } = NativeModules;

// 使用 Turbo Modules (React Native 0.68+)
import { getTurboModule } from 'react-native/Libraries/TurboModule/TurboModuleRegistry';

const CalendarModule = getTurboModule('CalendarModule');

// 使用模块
CalendarModule.createCalendarEvent('Meeting', 'Conference Room');
```

## 新架构的性能提升

React Native 新架构提供显著性能提升。

### Fabric (新 UI 层)

Fabric 通过同步渲染提供更流畅的 UI 交互：

- 优化触摸事件处理
- 改进高优先级更新
- 提高动画流畅度

### TurboModules

TurboModules 提高了 JavaScript 和原生代码之间的通信效率：

- 延迟加载模块
- 减少序列化/反序列化开销
- 类型安全的接口

### Codegen

自动生成类型安全的接口代码：

- 减少开发错误
- 提高运行时性能
- 简化原生模块开发

## 性能测试和监控

### 使用性能监控工具

```jsx
import { PerformanceObserver, performance } from 'react-native';

// 创建观察者
const observer = new PerformanceObserver((list) => {
  const entries = list.getEntries();
  entries.forEach((entry) => {
    console.log(`${entry.name}: ${entry.duration}ms`);
  });
});

// 开始观察
observer.observe({ entryTypes: ['measure'] });

// 标记和测量性能
function measureFunction() {
  performance.mark('functionStart');
  
  // 执行要测量的代码
  expensiveOperation();
  
  performance.mark('functionEnd');
  performance.measure('Function Execution', 'functionStart', 'functionEnd');
}
```

### 使用第三方监控服务

可以集成 Firebase Performance Monitoring, New Relic, Sentry 等服务。

```javascript
// Firebase Performance Monitoring 示例
import perf from '@react-native-firebase/perf';

async function loadData() {
  // 创建跟踪器
  const trace = await perf().startTrace('data_load');
  
  // 添加自定义属性
  trace.putAttribute('user_id', userId);
  
  // 添加指标
  trace.putMetric('data_size', 0);
  
  try {
    const data = await fetchData();
    
    // 更新指标
    trace.putMetric('data_size', JSON.stringify(data).length);
    
    return data;
  } finally {
    // 停止跟踪
    await trace.stop();
  }
}
```

## 最佳实践总结

### 1. 构建时优化

- 启用 Hermes 引擎
- 使用生产构建
- 移除不必要的依赖
- 代码分割和延迟加载

### 2. 运行时优化

- 避免不必要的渲染
- 优化列表性能
- 使用记忆化技术
- 高效图像处理
- 原生动画驱动

### 3. 架构优化

- 使用新架构 (Fabric & TurboModules)
- 保持组件简单和专注
- 采用单向数据流
- 合理拆分业务逻辑

### 4. 持续监控

- 集成性能监控工具
- 建立性能基准和阈值
- 定期性能审计

## 性能检查清单

在发布应用前，确保检查以下几点：

- [ ] 启用 Hermes 引擎
- [ ] 优化大型列表使用 FlatList
- [ ] 图像已被优化(尺寸和格式)
- [ ] 使用记忆化减少重渲染
- [ ] 检查并修复内存泄漏
- [ ] 网络请求已优化和缓存
- [ ] 原生动画使用 useNativeDriver: true
- [ ] 使用生产构建测试性能
- [ ] 应用大小已优化
- [ ] 启动时间在可接受范围内

React Native 性能优化是一个持续的过程。通过实施本文档中的技术和最佳实践，你可以显著提升应用的性能和用户体验。随着 React Native 的不断发展，特别是新架构的推出，应用性能将继续改进。保持关注社区的最新优化技术，并根据你的应用特性选择最合适的优化策略。 