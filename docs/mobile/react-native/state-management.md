# React Native 状态管理

状态管理是 React Native 应用开发中至关重要的一环。随着应用规模的增长，有效管理应用状态变得愈发重要。本文档将从最基本的内置状态管理开始，逐步探索更复杂的状态管理解决方案。

## 目录

- [内置状态管理](#内置状态管理)
- [Context API](#context-api)
- [Redux](#redux)
- [MobX](#mobx)
- [Recoil](#recoil)
- [Zustand](#zustand)
- [Jotai](#jotai)
- [异步状态管理](#异步状态管理)
- [持久化状态](#持久化状态)
- [状态管理最佳实践](#状态管理最佳实践)
- [选择合适的状态管理方案](#选择合适的状态管理方案)

## 内置状态管理

React Native 基于 React，因此继承了 React 的状态管理能力。

### useState Hook

最基本的状态管理是使用 `useState` Hook：

```jsx
import React, { useState } from 'react';
import { View, Text, Button } from 'react-native';

function Counter() {
  const [count, setCount] = useState(0);
  
  return (
    <View>
      <Text>计数: {count}</Text>
      <Button title="增加" onPress={() => setCount(count + 1)} />
      <Button title="减少" onPress={() => setCount(count - 1)} />
    </View>
  );
}
```

### useReducer Hook

当状态逻辑较复杂时，可以使用 `useReducer` Hook：

```jsx
import React, { useReducer } from 'react';
import { View, Text, Button } from 'react-native';

// 定义reducer
function counterReducer(state, action) {
  switch (action.type) {
    case 'INCREMENT':
      return { count: state.count + 1 };
    case 'DECREMENT':
      return { count: state.count - 1 };
    case 'RESET':
      return { count: 0 };
    default:
      return state;
  }
}

function CounterWithReducer() {
  const [state, dispatch] = useReducer(counterReducer, { count: 0 });
  
  return (
    <View>
      <Text>计数: {state.count}</Text>
      <Button title="增加" onPress={() => dispatch({ type: 'INCREMENT' })} />
      <Button title="减少" onPress={() => dispatch({ type: 'DECREMENT' })} />
      <Button title="重置" onPress={() => dispatch({ type: 'RESET' })} />
    </View>
  );
}
```

### 组件本地状态

类组件可以使用 `this.state` 和 `this.setState()`：

```jsx
import React, { Component } from 'react';
import { View, Text, Button } from 'react-native';

class ClassCounter extends Component {
  constructor(props) {
    super(props);
    this.state = {
      count: 0
    };
  }
  
  increment = () => {
    this.setState(prevState => ({ count: prevState.count + 1 }));
  };
  
  decrement = () => {
    this.setState(prevState => ({ count: prevState.count - 1 }));
  };
  
  render() {
    return (
      <View>
        <Text>计数: {this.state.count}</Text>
        <Button title="增加" onPress={this.increment} />
        <Button title="减少" onPress={this.decrement} />
      </View>
    );
  }
}
```

## Context API

对于中小型应用，React 的 Context API 是避免 "prop drilling" 的好方法。

```jsx
import React, { createContext, useState, useContext } from 'react';
import { View, Text, Button } from 'react-native';

// 创建上下文
const CounterContext = createContext();

// 提供者组件
function CounterProvider({ children }) {
  const [count, setCount] = useState(0);
  
  const increment = () => setCount(count + 1);
  const decrement = () => setCount(count - 1);
  
  return (
    <CounterContext.Provider value={{ count, increment, decrement }}>
      {children}
    </CounterContext.Provider>
  );
}

// 消费组件
function CountDisplay() {
  const { count } = useContext(CounterContext);
  return <Text>计数: {count}</Text>;
}

function CountButtons() {
  const { increment, decrement } = useContext(CounterContext);
  return (
    <View>
      <Button title="增加" onPress={increment} />
      <Button title="减少" onPress={decrement} />
    </View>
  );
}

// 使用
function App() {
  return (
    <CounterProvider>
      <View style={{ padding: 20 }}>
        <CountDisplay />
        <CountButtons />
      </View>
    </CounterProvider>
  );
}
```

### 组合多个 Context

```jsx
import React, { createContext, useContext, useState } from 'react';

// 创建多个上下文
const ThemeContext = createContext();
const UserContext = createContext();

function App() {
  const [theme, setTheme] = useState('light');
  const [user, setUser] = useState(null);
  
  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      <UserContext.Provider value={{ user, setUser }}>
        <MainContent />
      </UserContext.Provider>
    </ThemeContext.Provider>
  );
}
```

## Redux

Redux 是最流行的 React/React Native 状态管理库之一，特别适合大型应用和复杂状态。

### 安装

```bash
npm install redux react-redux @reduxjs/toolkit
```

### 使用 Redux Toolkit 创建 Store

```jsx
// store.js
import { configureStore, createSlice } from '@reduxjs/toolkit';

// 创建计数器切片
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
    incrementByAmount: (state, action) => {
      state.value += action.payload;
    },
  },
});

// 导出 actions
export const { increment, decrement, incrementByAmount } = counterSlice.actions;

// 创建 store
export const store = configureStore({
  reducer: {
    counter: counterSlice.reducer,
  },
});
```

### 在应用中使用 Redux

```jsx
// App.js
import React from 'react';
import { Provider } from 'react-redux';
import { store } from './store';
import Counter from './Counter';

export default function App() {
  return (
    <Provider store={store}>
      <Counter />
    </Provider>
  );
}

// Counter.js
import React from 'react';
import { View, Text, Button } from 'react-native';
import { useSelector, useDispatch } from 'react-redux';
import { increment, decrement } from './store';

function Counter() {
  const count = useSelector(state => state.counter.value);
  const dispatch = useDispatch();
  
  return (
    <View>
      <Text>计数: {count}</Text>
      <Button title="增加" onPress={() => dispatch(increment())} />
      <Button title="减少" onPress={() => dispatch(decrement())} />
    </View>
  );
}
```

### Redux 中间件

中间件用于处理异步操作，如网络请求：

```jsx
// 用于异步操作的 thunk
import { createAsyncThunk } from '@reduxjs/toolkit';

export const fetchUserById = createAsyncThunk(
  'users/fetchById',
  async (userId, thunkAPI) => {
    const response = await fetch(`https://api.example.com/users/${userId}`);
    return await response.json();
  }
);

const userSlice = createSlice({
  name: 'users',
  initialState: {
    entities: [],
    loading: 'idle',
    error: null,
  },
  reducers: {},
  extraReducers: (builder) => {
    builder
      .addCase(fetchUserById.pending, (state) => {
        state.loading = 'loading';
      })
      .addCase(fetchUserById.fulfilled, (state, action) => {
        state.loading = 'idle';
        state.entities.push(action.payload);
      })
      .addCase(fetchUserById.rejected, (state, action) => {
        state.loading = 'idle';
        state.error = action.error;
      });
  },
});
```

## MobX

MobX 是另一种流行的状态管理库，它使用可观察（observable）对象，更接近于面向对象编程。

### 安装

```bash
npm install mobx mobx-react-lite
```

### 创建 MobX Store

```jsx
// counterStore.js
import { makeAutoObservable } from "mobx";

class CounterStore {
  count = 0;

  constructor() {
    makeAutoObservable(this);
  }

  increment() {
    this.count++;
  }

  decrement() {
    this.count--;
  }
}

export const counterStore = new CounterStore();
```

### 在组件中使用 MobX

```jsx
// Counter.js
import React from 'react';
import { View, Text, Button } from 'react-native';
import { observer } from 'mobx-react-lite';
import { counterStore } from './counterStore';

const Counter = observer(() => {
  return (
    <View>
      <Text>计数: {counterStore.count}</Text>
      <Button title="增加" onPress={() => counterStore.increment()} />
      <Button title="减少" onPress={() => counterStore.decrement()} />
    </View>
  );
});

export default Counter;
```

### MobX 异步操作

```jsx
import { makeAutoObservable, runInAction } from "mobx";

class UserStore {
  user = null;
  loading = false;
  error = null;

  constructor() {
    makeAutoObservable(this);
  }

  async fetchUser(id) {
    this.loading = true;
    this.error = null;
    
    try {
      const response = await fetch(`https://api.example.com/users/${id}`);
      const data = await response.json();
      
      // 使用 runInAction 包装状态更新
      runInAction(() => {
        this.user = data;
        this.loading = false;
      });
    } catch (e) {
      runInAction(() => {
        this.error = e.message;
        this.loading = false;
      });
    }
  }
}

export const userStore = new UserStore();
```

## Recoil

Recoil 是 Facebook 的实验性状态管理库，它提供了一种原子化的状态管理方法。

### 安装

```bash
npm install recoil
```

### 基本用法

```jsx
import React from 'react';
import { RecoilRoot, atom, useRecoilState } from 'recoil';
import { View, Text, Button } from 'react-native';

// 定义一个原子状态
const countState = atom({
  key: 'countState',
  default: 0,
});

function Counter() {
  const [count, setCount] = useRecoilState(countState);
  
  return (
    <View>
      <Text>计数: {count}</Text>
      <Button title="增加" onPress={() => setCount(count + 1)} />
      <Button title="减少" onPress={() => setCount(count - 1)} />
    </View>
  );
}

function App() {
  return (
    <RecoilRoot>
      <Counter />
    </RecoilRoot>
  );
}
```

### 选择器（Selector）

选择器可以派生状态：

```jsx
import { selector, useRecoilValue } from 'recoil';

const doubleCountState = selector({
  key: 'doubleCountState',
  get: ({get}) => {
    const count = get(countState);
    return count * 2;
  },
});

function DoubleCounter() {
  const doubleCount = useRecoilValue(doubleCountState);
  
  return (
    <View>
      <Text>双倍计数: {doubleCount}</Text>
    </View>
  );
}
```

## Zustand

Zustand 是一个轻量级的状态管理库，语法简洁，性能优秀。

### 安装

```bash
npm install zustand
```

### 基本用法

```jsx
import create from 'zustand';
import { View, Text, Button } from 'react-native';

// 创建 store
const useStore = create((set) => ({
  count: 0,
  increment: () => set((state) => ({ count: state.count + 1 })),
  decrement: () => set((state) => ({ count: state.count - 1 })),
}));

// 在组件中使用
function Counter() {
  const { count, increment, decrement } = useStore();
  
  return (
    <View>
      <Text>计数: {count}</Text>
      <Button title="增加" onPress={increment} />
      <Button title="减少" onPress={decrement} />
    </View>
  );
}
```

### 异步操作

```jsx
const useUserStore = create((set) => ({
  user: null,
  loading: false,
  error: null,
  
  fetchUser: async (id) => {
    set({ loading: true, error: null });
    
    try {
      const response = await fetch(`https://api.example.com/users/${id}`);
      const user = await response.json();
      set({ user, loading: false });
    } catch (error) {
      set({ error: error.message, loading: false });
    }
  }
}));
```

## Jotai

Jotai 提供了一种原子化的状态管理方法，类似于 Recoil，但更轻量。

### 安装

```bash
npm install jotai
```

### 基本用法

```jsx
import React from 'react';
import { atom, useAtom } from 'jotai';
import { View, Text, Button } from 'react-native';

// 创建原子
const countAtom = atom(0);

function Counter() {
  const [count, setCount] = useAtom(countAtom);
  
  return (
    <View>
      <Text>计数: {count}</Text>
      <Button title="增加" onPress={() => setCount(count + 1)} />
      <Button title="减少" onPress={() => setCount(count - 1)} />
    </View>
  );
}
```

### 派生原子

```jsx
import { atom, useAtom } from 'jotai';

const countAtom = atom(0);
const doubleCountAtom = atom((get) => get(countAtom) * 2);

function DoubleCounter() {
  const [count] = useAtom(countAtom);
  const [doubleCount] = useAtom(doubleCountAtom);
  
  return (
    <View>
      <Text>计数: {count}</Text>
      <Text>双倍计数: {doubleCount}</Text>
    </View>
  );
}
```

## 异步状态管理

### SWR (Stale-While-Revalidate)

SWR 是一个用于数据获取的 React Hooks 库。

```bash
npm install swr
```

```jsx
import useSWR from 'swr';
import { View, Text } from 'react-native';

const fetcher = url => fetch(url).then(r => r.json());

function Profile({ userId }) {
  const { data, error, isLoading } = useSWR(
    `https://api.example.com/users/${userId}`,
    fetcher
  );

  if (error) return <Text>加载失败</Text>;
  if (isLoading) return <Text>加载中...</Text>;

  return (
    <View>
      <Text>你好，{data.name}！</Text>
    </View>
  );
}
```

### React Query

React Query 是一个强大的异步状态管理库。

```bash
npm install @tanstack/react-query
```

```jsx
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query';
import { View, Text } from 'react-native';

const queryClient = new QueryClient();

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <UserProfile userId="1" />
    </QueryClientProvider>
  );
}

function UserProfile({ userId }) {
  const { isLoading, error, data } = useQuery({
    queryKey: ['user', userId],
    queryFn: () =>
      fetch(`https://api.example.com/users/${userId}`).then(res =>
        res.json()
      )
  });

  if (isLoading) return <Text>加载中...</Text>;
  if (error) return <Text>错误: {error.message}</Text>;

  return (
    <View>
      <Text>用户名: {data.name}</Text>
    </View>
  );
}
```

## 持久化状态

### AsyncStorage

使用 AsyncStorage 持久化存储状态：

```jsx
import AsyncStorage from '@react-native-async-storage/async-storage';
import { useState, useEffect } from 'react';

function PersistentCounter() {
  const [count, setCount] = useState(0);
  
  // 加载保存的计数
  useEffect(() => {
    const loadCount = async () => {
      try {
        const savedCount = await AsyncStorage.getItem('count');
        if (savedCount !== null) {
          setCount(parseInt(savedCount, 10));
        }
      } catch (e) {
        console.error('加载计数失败', e);
      }
    };
    
    loadCount();
  }, []);
  
  // 保存计数
  const updateCount = async (newCount) => {
    try {
      await AsyncStorage.setItem('count', newCount.toString());
      setCount(newCount);
    } catch (e) {
      console.error('保存计数失败', e);
    }
  };
  
  return (
    <View>
      <Text>计数: {count}</Text>
      <Button title="增加" onPress={() => updateCount(count + 1)} />
      <Button title="减少" onPress={() => updateCount(count - 1)} />
    </View>
  );
}
```

### Redux Persist

为 Redux 状态添加持久化功能：

```bash
npm install redux-persist
```

```jsx
// store.js
import { configureStore } from '@reduxjs/toolkit';
import { persistStore, persistReducer } from 'redux-persist';
import AsyncStorage from '@react-native-async-storage/async-storage';
import counterReducer from './counterSlice';

const persistConfig = {
  key: 'root',
  storage: AsyncStorage,
};

const persistedReducer = persistReducer(persistConfig, counterReducer);

export const store = configureStore({
  reducer: persistedReducer,
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        ignoredActions: ['persist/PERSIST'],
      },
    }),
});

export const persistor = persistStore(store);
```

```jsx
// App.js
import { Provider } from 'react-redux';
import { PersistGate } from 'redux-persist/integration/react';
import { store, persistor } from './store';

function App() {
  return (
    <Provider store={store}>
      <PersistGate loading={null} persistor={persistor}>
        <Counter />
      </PersistGate>
    </Provider>
  );
}
```

## 状态管理最佳实践

### 1. 确定状态的位置

- **本地状态**: 仅在单个组件中使用的状态，使用 `useState` 或 `useReducer`
- **共享状态**: 在多个组件中使用的状态，使用 Context API 或状态管理库

### 2. 状态分类

- **UI 状态**: 控制界面显示，如模态框是否打开、加载中状态等
- **服务器状态**: 来自服务器的数据，考虑使用 SWR 或 React Query
- **表单状态**: 表单输入和验证，可使用 Formik 或 React Hook Form
- **URL 状态**: 存在 URL 中的状态，与导航相关

### 3. 避免过度使用全局状态

不是所有状态都需要放入全局 store。应该根据状态的用途和共享范围来决定存放位置。

### 4. 使用不可变更新模式

```jsx
// 不好的方式 - 直接修改对象
const updateUser = (user) => {
  user.name = 'New Name'; // 直接修改
  setUser(user);
};

// 好的方式 - 创建新对象
const updateUser = (user) => {
  setUser({ ...user, name: 'New Name' }); // 创建新对象
};
```

### 5. 规范化复杂状态

对于复杂的数据结构，采用规范化模式：

```jsx
// 规范化前
const state = {
  users: [
    { id: 1, name: 'Alice', posts: [101, 102] },
    { id: 2, name: 'Bob', posts: [103] }
  ],
  posts: [
    { id: 101, title: 'Hello', content: '...' },
    { id: 102, title: 'World', content: '...' },
    { id: 103, title: 'React', content: '...' }
  ]
};

// 规范化后
const state = {
  users: {
    byId: {
      1: { id: 1, name: 'Alice', posts: [101, 102] },
      2: { id: 2, name: 'Bob', posts: [103] }
    },
    allIds: [1, 2]
  },
  posts: {
    byId: {
      101: { id: 101, title: 'Hello', content: '...' },
      102: { id: 102, title: 'World', content: '...' },
      103: { id: 103, title: 'React', content: '...' }
    },
    allIds: [101, 102, 103]
  }
};
```

### 6. 代码分割状态逻辑

将大型状态分割成更小的模块：

```jsx
// Redux Toolkit 例子
// userSlice.js
const userSlice = createSlice({
  name: 'users',
  initialState,
  reducers: {/* ... */}
});

// postsSlice.js
const postsSlice = createSlice({
  name: 'posts',
  initialState,
  reducers: {/* ... */}
});

// store.js
const store = configureStore({
  reducer: {
    users: userSlice.reducer,
    posts: postsSlice.reducer,
  }
});
```

## 选择合适的状态管理方案

### 小型应用

- **React 内置状态管理**: useState, useReducer
- **Context API**: 适用于简单的全局状态

### 中型应用

- **Zustand**: 简单直观，适合中等复杂度
- **Jotai/Recoil**: 原子化状态，灵活组合

### 大型应用

- **Redux Toolkit**: 结构化强，适合复杂状态逻辑
- **MobX**: 面向对象风格，适合复杂领域模型

### 特定需求

- **服务端状态**: SWR, React Query
- **表单状态**: Formik, React Hook Form

## 总结

选择合适的状态管理方案应该基于项目需求和团队偏好。没有放之四海而皆准的解决方案，关键是理解不同方案的优缺点，在适当的场景选择合适的工具。

随着 React 和 React Native 生态系统的发展，状态管理解决方案也在不断进化。保持对新工具和最佳实践的学习，是确保应用架构健壮性的关键。 