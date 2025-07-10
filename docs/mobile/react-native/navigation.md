# React Native 导航与路由

导航是移动应用的核心功能，良好的导航结构可以极大提升用户体验。React Navigation 是 React Native 应用中最流行的导航库，提供了全面的导航解决方案。本文档将详细介绍如何使用 React Navigation 构建应用导航结构。

## 目录

- [React Navigation 简介](#react-navigation-简介)
- [安装与配置](#安装与配置)
- [导航器类型](#导航器类型)
- [基础导航](#基础导航)
- [参数传递](#参数传递)
- [嵌套导航](#嵌套导航)
- [选项卡导航](#选项卡导航)
- [抽屉导航](#抽屉导航)
- [自定义导航器](#自定义导航器)
- [导航生命周期](#导航生命周期)
- [深层链接](#深层链接)
- [身份验证流程](#身份验证流程)
- [TypeScript 支持](#typescript-支持)
- [最佳实践](#最佳实践)

## React Navigation 简介

React Navigation 是一个完全用 JavaScript 实现的导航库，不依赖于原生代码。它提供了多种导航器类型，如堆栈、选项卡、抽屉等，可以组合使用以创建复杂的导航结构。

### 为什么选择 React Navigation?

- **纯 JavaScript 实现**：无需链接原生代码
- **可定制性强**：高度可自定义的导航器和转场效果
- **广泛的社区支持**：活跃的生态系统和持续更新
- **跨平台一致性**：在 iOS 和 Android 上提供一致的体验
- **TypeScript 支持**：完整的类型定义

## 安装与配置

### 基础安装

```bash
npm install @react-navigation/native
```

### 安装依赖

```bash
npm install react-native-screens react-native-safe-area-context
```

对于 Expo 管理的项目，可以使用：

```bash
expo install react-native-screens react-native-safe-area-context
```

### 基础设置

在应用入口处，需要包装应用根组件：

```jsx
import React from 'react';
import { NavigationContainer } from '@react-navigation/native';

export default function App() {
  return (
    <NavigationContainer>
      {/* 应用的导航结构 */}
    </NavigationContainer>
  );
}
```

## 导航器类型

React Navigation 提供了多种导航器类型，以下是最常用的几种：

### 1. Stack Navigator（堆栈导航器）

适用于屏幕之间的前进后退导航。

```bash
npm install @react-navigation/stack
npm install react-native-gesture-handler
```

### 2. Tab Navigator（选项卡导航器）

用于底部或顶部的选项卡导航。

```bash
npm install @react-navigation/bottom-tabs
# 或者
npm install @react-navigation/material-top-tabs react-native-tab-view
```

### 3. Drawer Navigator（抽屉导航器）

侧边栏滑出菜单导航。

```bash
npm install @react-navigation/drawer react-native-gesture-handler react-native-reanimated
```

### 4. Material Bottom Tabs

Material Design 风格的底部选项卡导航。

```bash
npm install @react-navigation/material-bottom-tabs react-native-paper react-native-vector-icons
```

## 基础导航

### Stack Navigator 示例

```jsx
import React from 'react';
import { Button, View, Text } from 'react-native';
import { NavigationContainer } from '@react-navigation/native';
import { createStackNavigator } from '@react-navigation/stack';

// 定义主页屏幕
function HomeScreen({ navigation }) {
  return (
    <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center' }}>
      <Text>Home Screen</Text>
      <Button
        title="Go to Details"
        onPress={() => navigation.navigate('Details', {
          itemId: 86,
          otherParam: '详细信息',
        })}
      />
    </View>
  );
}

// 定义详情屏幕
function DetailsScreen({ route, navigation }) {
  // 获取参数
  const { itemId, otherParam } = route.params;
  
  return (
    <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center' }}>
      <Text>Details Screen</Text>
      <Text>Item ID: {itemId}</Text>
      <Text>Other Param: {otherParam}</Text>
      <Button
        title="Go to Details... again"
        onPress={() => navigation.push('Details', {
          itemId: Math.floor(Math.random() * 100),
        })}
      />
      <Button title="Go back" onPress={() => navigation.goBack()} />
      <Button
        title="Go back to first screen in stack"
        onPress={() => navigation.popToTop()}
      />
    </View>
  );
}

// 创建堆栈导航器
const Stack = createStackNavigator();

function App() {
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
          options={({ route }) => ({ title: route.params.otherParam })}
        />
      </Stack.Navigator>
    </NavigationContainer>
  );
}

export default App;
```

### 导航方法

React Navigation 提供了多种导航方法：

- **navigation.navigate('RouteName')**：导航到指定路由，如果该路由已存在于堆栈中，则返回到该路由
- **navigation.push('RouteName')**：向导航堆栈推入新路由，即使该路由已存在于堆栈中
- **navigation.goBack()**：返回上一个屏幕
- **navigation.popToTop()**：返回到堆栈的第一个屏幕
- **navigation.replace('RouteName')**：替换当前屏幕
- **navigation.setParams({ paramName: value })**：更新当前路由的参数
- **navigation.reset({})**：重置整个导航状态

## 参数传递

通过导航时传递参数：

```jsx
// 传递参数
navigation.navigate('Details', {
  itemId: 86,
  otherParam: '详细信息',
});

// 接收参数
function DetailsScreen({ route }) {
  const { itemId, otherParam } = route.params;
  // ...
}
```

### 更新参数

```jsx
// 更新当前路由的参数
navigation.setParams({
  itemId: 100,
});
```

### 初始参数

可以为屏幕设置初始参数：

```jsx
<Stack.Screen
  name="Details"
  component={DetailsScreen}
  initialParams={{ itemId: 42 }}
/>
```

## 嵌套导航

React Navigation 支持嵌套导航，这使得可以创建复杂的导航结构。

### 嵌套堆栈导航器

```jsx
import { createStackNavigator } from '@react-navigation/stack';

// 主堆栈导航器
const MainStack = createStackNavigator();
function MainStackScreen() {
  return (
    <MainStack.Navigator>
      <MainStack.Screen name="Home" component={HomeScreen} />
      <MainStack.Screen name="Details" component={DetailsScreen} />
    </MainStack.Navigator>
  );
}

// 根堆栈导航器
const RootStack = createStackNavigator();
function App() {
  return (
    <NavigationContainer>
      <RootStack.Navigator mode="modal">
        <RootStack.Screen
          name="Main"
          component={MainStackScreen}
          options={{ headerShown: false }}
        />
        <RootStack.Screen name="MyModal" component={ModalScreen} />
      </RootStack.Navigator>
    </NavigationContainer>
  );
}
```

### 导航到嵌套屏幕

```jsx
// 导航到嵌套屏幕
navigation.navigate('Main', {
  screen: 'Details',
  params: { itemId: 42 },
});
```

## 选项卡导航

### Bottom Tab Navigator（底部选项卡导航器）

```jsx
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import Ionicons from 'react-native-vector-icons/Ionicons';

const Tab = createBottomTabNavigator();

function MyTabs() {
  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        tabBarIcon: ({ focused, color, size }) => {
          let iconName;

          if (route.name === 'Home') {
            iconName = focused ? 'home' : 'home-outline';
          } else if (route.name === 'Settings') {
            iconName = focused ? 'settings' : 'settings-outline';
          }

          // 返回图标组件
          return <Ionicons name={iconName} size={size} color={color} />;
        },
      })}
      tabBarOptions={{
        activeTintColor: 'tomato',
        inactiveTintColor: 'gray',
      }}
    >
      <Tab.Screen name="Home" component={HomeScreen} />
      <Tab.Screen name="Settings" component={SettingsScreen} />
    </Tab.Navigator>
  );
}
```

### Material Top Tab Navigator（顶部选项卡导航器）

```jsx
import { createMaterialTopTabNavigator } from '@react-navigation/material-top-tabs';

const Tab = createMaterialTopTabNavigator();

function MyTabs() {
  return (
    <Tab.Navigator
      initialRouteName="Feed"
      tabBarOptions={{
        activeTintColor: '#e91e63',
        labelStyle: { fontSize: 12 },
        style: { backgroundColor: 'powderblue' },
      }}
    >
      <Tab.Screen
        name="Feed"
        component={FeedScreen}
        options={{ tabBarLabel: '动态' }}
      />
      <Tab.Screen
        name="Notifications"
        component={NotificationsScreen}
        options={{ tabBarLabel: '通知' }}
      />
      <Tab.Screen
        name="Profile"
        component={ProfileScreen}
        options={{ tabBarLabel: '个人' }}
      />
    </Tab.Navigator>
  );
}
```

## 抽屉导航

### Drawer Navigator（抽屉导航器）

```jsx
import { createDrawerNavigator } from '@react-navigation/drawer';

const Drawer = createDrawerNavigator();

function MyDrawer() {
  return (
    <Drawer.Navigator
      initialRouteName="Home"
      drawerContentOptions={{
        activeTintColor: '#e91e63',
        itemStyle: { marginVertical: 5 },
      }}
    >
      <Drawer.Screen
        name="Home"
        component={HomeScreen}
        options={{ drawerLabel: '首页' }}
      />
      <Drawer.Screen
        name="Notifications"
        component={NotificationsScreen}
        options={{ drawerLabel: '通知' }}
      />
    </Drawer.Navigator>
  );
}
```

### 自定义抽屉内容

```jsx
import {
  createDrawerNavigator,
  DrawerContentScrollView,
  DrawerItemList,
  DrawerItem,
} from '@react-navigation/drawer';

function CustomDrawerContent(props) {
  return (
    <DrawerContentScrollView {...props}>
      <DrawerItemList {...props} />
      <DrawerItem
        label="关闭抽屉"
        onPress={() => props.navigation.closeDrawer()}
      />
    </DrawerContentScrollView>
  );
}

const Drawer = createDrawerNavigator();

function MyDrawer() {
  return (
    <Drawer.Navigator
      drawerContent={props => <CustomDrawerContent {...props} />}
    >
      <Drawer.Screen name="Home" component={HomeScreen} />
      <Drawer.Screen name="Notifications" component={NotificationsScreen} />
    </Drawer.Navigator>
  );
}
```

## 自定义导航器

### 自定义导航器外观

```jsx
// 自定义 Stack Navigator 的标题
<Stack.Navigator
  screenOptions={{
    headerStyle: {
      backgroundColor: '#f4511e',
    },
    headerTintColor: '#fff',
    headerTitleStyle: {
      fontWeight: 'bold',
    },
  }}
>
  <Stack.Screen
    name="Home"
    component={HomeScreen}
    options={{ title: '我的首页' }}
  />
</Stack.Navigator>
```

### 自定义特定屏幕的选项

```jsx
<Stack.Screen
  name="Home"
  component={HomeScreen}
  options={{
    title: '首页',
    headerStyle: {
      backgroundColor: '#f4511e',
    },
    headerTintColor: '#fff',
    headerTitleStyle: {
      fontWeight: 'bold',
    },
    headerRight: () => (
      <Button
        onPress={() => alert('这是一个按钮！')}
        title="Info"
        color="#fff"
      />
    ),
  }}
/>
```

### 动态标题

```jsx
<Stack.Screen
  name="Details"
  component={DetailsScreen}
  options={({ route }) => ({ title: route.params.name })}
/>
```

## 导航生命周期

React Navigation 与 React 的生命周期方法集成。

### 使用 useFocusEffect

```jsx
import { useFocusEffect } from '@react-navigation/native';

function ProfileScreen() {
  useFocusEffect(
    React.useCallback(() => {
      // 当屏幕获得焦点时执行
      const fetchData = async () => {
        // 获取数据...
      };
      
      fetchData();
      
      // 可选的清理函数
      return () => {
        // 当屏幕失去焦点时执行
        // 清理资源...
      };
    }, [])
  );
  
  return <ProfileContent />;
}
```

### 监听导航事件

```jsx
import { useNavigation, useRoute, useFocusEffect } from '@react-navigation/native';

function MyScreen() {
  const navigation = useNavigation();
  
  React.useEffect(() => {
    const unsubscribe = navigation.addListener('focus', () => {
      // 屏幕获得焦点
      console.log('Screen focused');
    });
    
    // 清理订阅
    return unsubscribe;
  }, [navigation]);
  
  return <View>...</View>;
}
```

可用的导航事件：

- `focus`：屏幕获得焦点时触发
- `blur`：屏幕失去焦点时触发
- `beforeRemove`：屏幕被移除前触发
- `state`：导航状态改变时触发

## 深层链接

深层链接允许通过 URL 直接打开应用的特定屏幕。

### 配置深层链接

```jsx
import { NavigationContainer } from '@react-navigation/native';
import { linking } from './linking'; // 自定义链接配置

function App() {
  return (
    <NavigationContainer
      linking={linking}
      fallback={<Text>Loading...</Text>}
    >
      {/* ... */}
    </NavigationContainer>
  );
}
```

### 链接配置示例

```jsx
// linking.js
export const linking = {
  prefixes: ['myapp://', 'https://myapp.com'],
  config: {
    screens: {
      Home: 'home',
      Profile: {
        path: 'user/:id',
        parse: {
          id: (id) => `${id}`,
        },
      },
      Settings: 'settings',
    },
  },
};
```

## 身份验证流程

实现一个基本的身份验证流程：

```jsx
import React, { useState, useEffect, useContext } from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createStackNavigator } from '@react-navigation/stack';
import AsyncStorage from '@react-native-async-storage/async-storage';

// 创建认证上下文
const AuthContext = React.createContext();

function App() {
  const [state, dispatch] = React.useReducer(
    (prevState, action) => {
      switch (action.type) {
        case 'RESTORE_TOKEN':
          return {
            ...prevState,
            userToken: action.token,
            isLoading: false,
          };
        case 'SIGN_IN':
          return {
            ...prevState,
            isSignout: false,
            userToken: action.token,
          };
        case 'SIGN_OUT':
          return {
            ...prevState,
            isSignout: true,
            userToken: null,
          };
      }
    },
    {
      isLoading: true,
      isSignout: false,
      userToken: null,
    }
  );

  useEffect(() => {
    // 检查令牌
    const bootstrapAsync = async () => {
      let userToken;

      try {
        userToken = await AsyncStorage.getItem('userToken');
      } catch (e) {
        // 读取令牌失败
        console.error(e);
      }

      // 验证令牌
      dispatch({ type: 'RESTORE_TOKEN', token: userToken });
    };

    bootstrapAsync();
  }, []);

  const authContext = React.useMemo(
    () => ({
      signIn: async (data) => {
        // 在此发送实际的身份验证请求
        const { username, password } = data;
        // 假设API调用成功，获取令牌
        const userToken = 'dummy-auth-token';
        
        try {
          await AsyncStorage.setItem('userToken', userToken);
        } catch (e) {
          console.error(e);
        }
        
        dispatch({ type: 'SIGN_IN', token: userToken });
      },
      signOut: async () => {
        try {
          await AsyncStorage.removeItem('userToken');
        } catch (e) {
          console.error(e);
        }
        
        dispatch({ type: 'SIGN_OUT' });
      },
      signUp: async (data) => {
        // 在此发送注册请求
        // ...
        
        // 注册后自动登录
        const userToken = 'dummy-auth-token';
        
        try {
          await AsyncStorage.setItem('userToken', userToken);
        } catch (e) {
          console.error(e);
        }
        
        dispatch({ type: 'SIGN_IN', token: userToken });
      },
    }),
    []
  );

  // 创建导航堆栈
  const Stack = createStackNavigator();

  return (
    <AuthContext.Provider value={authContext}>
      <NavigationContainer>
        <Stack.Navigator>
          {state.isLoading ? (
            // 加载屏幕
            <Stack.Screen name="Splash" component={SplashScreen} />
          ) : state.userToken == null ? (
            // 未认证屏幕
            <>
              <Stack.Screen
                name="SignIn"
                component={SignInScreen}
                options={{
                  title: '登录',
                  animationTypeForReplace: state.isSignout ? 'pop' : 'push',
                }}
              />
              <Stack.Screen name="SignUp" component={SignUpScreen} options={{ title: '注册' }} />
            </>
          ) : (
            // 已认证屏幕
            <>
              <Stack.Screen name="Home" component={HomeScreen} />
              <Stack.Screen name="Profile" component={ProfileScreen} />
            </>
          )}
        </Stack.Navigator>
      </NavigationContainer>
    </AuthContext.Provider>
  );
}

// 登录屏幕
function SignInScreen() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  
  const { signIn } = useContext(AuthContext);
  
  return (
    <View>
      <TextInput
        placeholder="用户名"
        value={username}
        onChangeText={setUsername}
      />
      <TextInput
        placeholder="密码"
        value={password}
        onChangeText={setPassword}
        secureTextEntry
      />
      <Button title="登录" onPress={() => signIn({ username, password })} />
    </View>
  );
}
```

## TypeScript 支持

React Navigation 提供了完整的 TypeScript 支持。

### 类型化参数

```tsx
import { RouteProp } from '@react-navigation/native';
import { StackNavigationProp } from '@react-navigation/stack';

// 定义参数类型
type RootStackParamList = {
  Home: undefined;
  Profile: { userId: string };
  Feed: { sort: 'latest' | 'top' } | undefined;
};

// 定义屏幕 props 类型
type ProfileScreenRouteProp = RouteProp<RootStackParamList, 'Profile'>;
type ProfileScreenNavigationProp = StackNavigationProp<RootStackParamList, 'Profile'>;

type ProfileScreenProps = {
  route: ProfileScreenRouteProp;
  navigation: ProfileScreenNavigationProp;
};

// 使用类型
function ProfileScreen({ route, navigation }: ProfileScreenProps) {
  // 安全地访问参数
  const { userId } = route.params;
  
  return (
    <View>
      <Text>User ID: {userId}</Text>
      <Button
        title="Go to Home"
        onPress={() => navigation.navigate('Home')}
      />
    </View>
  );
}
```

### 使用 useNavigation 和 useRoute Hooks

```tsx
import { useNavigation, useRoute, RouteProp } from '@react-navigation/native';
import { StackNavigationProp } from '@react-navigation/stack';

type RootStackParamList = {
  Home: undefined;
  Profile: { userId: string };
};

function ProfileScreen() {
  // 类型化的导航 hook
  const navigation = useNavigation<StackNavigationProp<RootStackParamList, 'Profile'>>();
  // 类型化的路由 hook
  const route = useRoute<RouteProp<RootStackParamList, 'Profile'>>();
  
  const { userId } = route.params;
  
  return (
    <View>
      <Text>User ID: {userId}</Text>
      <Button
        title="Go to Home"
        onPress={() => navigation.navigate('Home')}
      />
    </View>
  );
}
```

## 最佳实践

### 1. 组织导航结构

为大型应用创建良好的导航结构：

```jsx
// navigation/index.js
import React from 'react';
import { NavigationContainer } from '@react-navigation/native';
import RootNavigator from './RootNavigator';
import { linking } from './linking';

export default function Navigation() {
  return (
    <NavigationContainer linking={linking}>
      <RootNavigator />
    </NavigationContainer>
  );
}

// navigation/RootNavigator.js
import React from 'react';
import { createStackNavigator } from '@react-navigation/stack';
import BottomTabNavigator from './BottomTabNavigator';
import NotFoundScreen from '../screens/NotFoundScreen';

const Stack = createStackNavigator();

export default function RootNavigator() {
  return (
    <Stack.Navigator screenOptions={{ headerShown: false }}>
      <Stack.Screen name="Root" component={BottomTabNavigator} />
      <Stack.Screen name="NotFound" component={NotFoundScreen} options={{ title: 'Oops!' }} />
    </Stack.Navigator>
  );
}

// navigation/BottomTabNavigator.js
import React from 'react';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import HomeNavigator from './HomeNavigator';
import ProfileNavigator from './ProfileNavigator';

const BottomTab = createBottomTabNavigator();

export default function BottomTabNavigator() {
  return (
    <BottomTab.Navigator>
      <BottomTab.Screen name="Home" component={HomeNavigator} />
      <BottomTab.Screen name="Profile" component={ProfileNavigator} />
    </BottomTab.Navigator>
  );
}
```

### 2. 使用常量管理路由名称

```jsx
// navigation/routes.js
export const ROUTES = {
  HOME: 'Home',
  PROFILE: 'Profile',
  SETTINGS: 'Settings',
  DETAILS: 'Details',
};

// 使用
import { ROUTES } from '../navigation/routes';

navigation.navigate(ROUTES.PROFILE, { userId: '123' });
```

### 3. 避免不必要的重渲染

```jsx
// 不推荐 - 内联函数会导致组件重新渲染
<Button
  onPress={() => navigation.navigate('Details')}
  title="Go to Details"
/>

// 推荐 - 使用 useCallback
const goToDetails = useCallback(() => {
  navigation.navigate('Details');
}, [navigation]);

<Button
  onPress={goToDetails}
  title="Go to Details"
/>
```

### 4. 使用 React Navigation 的状态持久化

```jsx
import AsyncStorage from '@react-native-async-storage/async-storage';

const PERSISTENCE_KEY = 'NAVIGATION_STATE_V1';

export default function App() {
  const [isReady, setIsReady] = React.useState(false);
  const [initialState, setInitialState] = React.useState();

  React.useEffect(() => {
    const restoreState = async () => {
      try {
        const savedStateString = await AsyncStorage.getItem(PERSISTENCE_KEY);
        const state = savedStateString
          ? JSON.parse(savedStateString)
          : undefined;

        if (state !== undefined) {
          setInitialState(state);
        }
      } finally {
        setIsReady(true);
      }
    };

    restoreState();
  }, []);

  if (!isReady) {
    return <ActivityIndicator />;
  }

  return (
    <NavigationContainer
      initialState={initialState}
      onStateChange={(state) =>
        AsyncStorage.setItem(PERSISTENCE_KEY, JSON.stringify(state))
      }
    >
      {/* ... */}
    </NavigationContainer>
  );
}
```

### 5. 优化性能

使用 `React.memo` 避免不必要的屏幕重渲染：

```jsx
const HomeScreen = React.memo(function HomeScreen({ navigation }) {
  return (
    <View>
      <Text>Home Screen</Text>
      <Button
        title="Go to Details"
        onPress={() => navigation.navigate('Details')}
      />
    </View>
  );
});
```

## 总结

React Navigation 是一个功能强大且灵活的导航库，可以帮助您构建从简单到复杂的各种导航结构。通过组合不同类型的导航器，您可以创建符合现代移动应用标准的用户体验。

本文档介绍了 React Navigation 的基础概念和高级功能，包括堆栈导航、选项卡导航、参数传递、嵌套导航等。掌握这些知识点，可以帮助您设计和实现出用户友好的导航系统。

随着应用的发展，可能需要进一步探索 React Navigation 的高级特性，如状态持久化、深层链接和导航生命周期，以满足更复杂的需求。 