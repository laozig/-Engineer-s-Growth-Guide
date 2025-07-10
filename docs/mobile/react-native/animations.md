# React Native 动画系统

动画是移动应用用户体验的重要组成部分，良好的动画效果能够让应用感觉更流畅、更专业。React Native 提供了强大的 Animated API，使开发者能够创建各种流畅的动画效果。本文档将深入探讨 React Native 动画系统的各个方面。

## 目录

- [动画系统概述](#动画系统概述)
- [Animated API 基础](#animated-api-基础)
- [动画类型](#动画类型)
- [插值（Interpolation）](#插值interpolation)
- [组合动画](#组合动画)
- [事件动画](#事件动画)
- [布局动画](#布局动画)
- [手势动画](#手势动画)
- [Reanimated 2](#reanimated-2)
- [性能优化](#性能优化)
- [常见动画模式](#常见动画模式)
- [最佳实践](#最佳实践)

## 动画系统概述

React Native 提供了两个主要的动画系统：

1. **Animated API**：核心动画库，提供细粒度的控制和高性能
2. **LayoutAnimation**：声明式 API，用于全局布局过渡

除了内置的动画系统外，社区还有一些流行的动画库：

- **React Native Reanimated**：提供更底层的动画能力，性能更优
- **React Native Gesture Handler**：手势系统，常与动画库配合使用
- **Lottie**：支持 After Effects 动画

## Animated API 基础

### 创建动画值

```jsx
import React, { useRef, useEffect } from 'react';
import { Animated, View, StyleSheet } from 'react-native';

function FadeInView({ children }) {
  // 创建一个动画值，初始为0
  const fadeAnim = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    // 启动动画
    Animated.timing(fadeAnim, {
      toValue: 1, // 目标值
      duration: 1000, // 持续时间（毫秒）
      useNativeDriver: true, // 使用原生驱动，提高性能
    }).start(); // 开始动画
  }, []);

  return (
    <Animated.View
      style={{
        ...styles.container,
        opacity: fadeAnim, // 绑定动画值到样式
      }}
    >
      {children}
    </Animated.View>
  );
}

const styles = StyleSheet.create({
  container: {
    padding: 20,
    backgroundColor: '#f8f8f8',
    borderRadius: 5,
  },
});
```

### 可动画的组件

Animated 模块提供了一些内置的可动画组件：

- `Animated.View`
- `Animated.Text`
- `Animated.Image`
- `Animated.ScrollView`
- `Animated.FlatList`

你也可以创建自定义的可动画组件：

```jsx
const AnimatedButton = Animated.createAnimatedComponent(TouchableOpacity);
```

### 配置动画

每个动画方法都接受一个配置对象，常见的属性包括：

```jsx
Animated.timing(animValue, {
  toValue: 1, // 目标值
  duration: 500, // 持续时间
  delay: 100, // 延迟启动
  easing: Easing.ease, // 缓动函数
  useNativeDriver: true, // 使用原生驱动
}).start();
```

### useNativeDriver 参数

`useNativeDriver: true` 告诉 React Native 在 JavaScript 线程之外的 UI 线程上运行动画。这能显著提高性能，但有一些限制：

- 只能用于非布局属性：如 `opacity` 和 `transform`
- 不能动态更新动画配置
- 不能用于 `backgroundColor` 等颜色属性

## 动画类型

### timing - 随时间变化的动画

```jsx
import { Easing } from 'react-native';

// 基本使用
Animated.timing(opacity, {
  toValue: 1,
  duration: 1000,
  useNativeDriver: true,
}).start();

// 使用缓动函数
Animated.timing(scale, {
  toValue: 2,
  duration: 300,
  easing: Easing.bounce, // 弹跳效果
  useNativeDriver: true,
}).start();
```

常见缓动函数：

- `Easing.linear` - 线性变化
- `Easing.ease` - 标准曲线（默认）
- `Easing.bounce` - 弹跳效果
- `Easing.elastic(4)` - 弹性效果
- `Easing.bezier(.42,0,.58,1)` - 自定义贝塞尔曲线

### spring - 弹簧物理动画

```jsx
// 基本弹簧动画
Animated.spring(scale, {
  toValue: 1.5,
  friction: 3, // 摩擦力，值越小弹性越大
  tension: 40, // 张力，值越大速度越快
  useNativeDriver: true,
}).start();

// 更精确的弹簧配置
Animated.spring(scale, {
  toValue: 1,
  stiffness: 100, // 刚度
  damping: 10, // 阻尼
  mass: 1, // 质量
  velocity: 0, // 初始速度
  useNativeDriver: true,
}).start();
```

### decay - 衰减动画

```jsx
// 带有初始速度的衰减动画
Animated.decay(position, {
  velocity: { x: gesture.vx, y: gesture.vy }, // 初始速度
  deceleration: 0.997, // 衰减系数
  useNativeDriver: true,
}).start();
```

## 插值（Interpolation）

插值允许你将一个输入范围映射到输出范围，实现更复杂的转换。

```jsx
import React, { useRef, useEffect } from 'react';
import { Animated, View, Text } from 'react-native';

function ColorChange() {
  const animValue = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    Animated.timing(animValue, {
      toValue: 1,
      duration: 2000,
      useNativeDriver: false, // 由于修改backgroundColor，不能使用原生驱动
    }).start();
  }, []);

  // 创建基于animValue的插值
  const backgroundColor = animValue.interpolate({
    inputRange: [0, 0.5, 1], // 输入值范围
    outputRange: ['red', 'green', 'blue'], // 对应的输出范围
  });

  const textSize = animValue.interpolate({
    inputRange: [0, 1],
    outputRange: [14, 28],
  });

  const rotateZ = animValue.interpolate({
    inputRange: [0, 1],
    outputRange: ['0deg', '360deg'],
  });

  return (
    <Animated.View
      style={{
        padding: 20,
        backgroundColor, // 背景色插值
        transform: [{ rotateZ }], // 旋转插值
      }}
    >
      <Animated.Text style={{ fontSize: textSize }}>
        Hello Animation
      </Animated.Text>
    </Animated.View>
  );
}
```

### 插值配置选项

```jsx
const animatedValue = new Animated.Value(0);

const interpolatedValue = animatedValue.interpolate({
  inputRange: [0, 1], // 输入范围
  outputRange: [0, 100], // 输出范围
  extrapolate: 'clamp', // 超出范围的处理方式
  // 选项: 'extend' (默认) | 'clamp' | 'identity'
});
```

## 组合动画

### 顺序动画 (sequence)

```jsx
// 按顺序执行动画
Animated.sequence([
  Animated.timing(opacity, {
    toValue: 1,
    duration: 500,
    useNativeDriver: true,
  }),
  Animated.delay(300), // 延迟300毫秒
  Animated.spring(scale, {
    toValue: 1.2,
    friction: 4,
    useNativeDriver: true,
  })
]).start();
```

### 并行动画 (parallel)

```jsx
// 同时执行多个动画
Animated.parallel([
  Animated.timing(opacity, {
    toValue: 1,
    duration: 500,
    useNativeDriver: true,
  }),
  Animated.spring(scale, {
    toValue: 1.2,
    friction: 4,
    useNativeDriver: true,
  })
]).start();
```

### 交错动画 (stagger)

```jsx
// 延迟一定时间开始每个动画
Animated.stagger(100, [
  Animated.timing(anim1, { ... }),
  Animated.timing(anim2, { ... }),
  Animated.timing(anim3, { ... })
]).start();
```

### 循环动画 (loop)

```jsx
// 创建无限循环动画
const pulse = Animated.loop(
  Animated.sequence([
    Animated.timing(scale, {
      toValue: 1.2,
      duration: 500,
      useNativeDriver: true,
    }),
    Animated.timing(scale, {
      toValue: 1,
      duration: 500,
      useNativeDriver: true,
    })
  ]),
  { iterations: -1 } // -1表示无限循环，或设置具体次数
);

// 启动循环动画
pulse.start();

// 停止循环动画
pulse.stop();
```

## 事件动画

Animated API 可以直接绑定到手势事件上，创建响应式动画。

### 基于 PanResponder 的拖拽动画

```jsx
import React, { useRef } from 'react';
import { Animated, PanResponder, StyleSheet, View } from 'react-native';

function DraggableBox() {
  const pan = useRef(new Animated.ValueXY()).current;

  const panResponder = useRef(
    PanResponder.create({
      onStartShouldSetPanResponder: () => true,
      onPanResponderMove: Animated.event(
        [null, { dx: pan.x, dy: pan.y }],
        { useNativeDriver: false }
      ),
      onPanResponderRelease: () => {
        // 松手后回到原位置的动画
        Animated.spring(pan, {
          toValue: { x: 0, y: 0 },
          useNativeDriver: false,
        }).start();
      }
    })
  ).current;

  return (
    <View style={styles.container}>
      <Animated.View
        style={{
          ...styles.box,
          transform: [
            { translateX: pan.x },
            { translateY: pan.y }
          ]
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
    justifyContent: 'center',
  },
  box: {
    width: 100,
    height: 100,
    backgroundColor: 'blue',
    borderRadius: 5,
  },
});
```

### 基于手势事件的动画

```jsx
import { Animated, ScrollView } from 'react-native';

function AnimatedHeader() {
  const scrollY = useRef(new Animated.Value(0)).current;
  
  const headerHeight = scrollY.interpolate({
    inputRange: [0, 200],
    outputRange: [120, 60],
    extrapolate: 'clamp',
  });
  
  return (
    <View>
      <Animated.View style={{ height: headerHeight }}>
        {/* 头部内容 */}
      </Animated.View>
      <ScrollView
        onScroll={Animated.event(
          [{ nativeEvent: { contentOffset: { y: scrollY } } }],
          { useNativeDriver: false }
        )}
        scrollEventThrottle={16} // 约60fps
      >
        {/* 滚动内容 */}
      </ScrollView>
    </View>
  );
}
```

## 布局动画

LayoutAnimation 提供了一种简单的方式来创建下一次布局变更时的动画。

```jsx
import React, { useState } from 'react';
import { View, Button, LayoutAnimation, Platform, UIManager } from 'react-native';

// 在Android上启用LayoutAnimation
if (Platform.OS === 'android') {
  if (UIManager.setLayoutAnimationEnabledExperimental) {
    UIManager.setLayoutAnimationEnabledExperimental(true);
  }
}

function LayoutAnimationExample() {
  const [expanded, setExpanded] = useState(false);

  const toggleExpand = () => {
    // 配置下一次布局变更的动画
    LayoutAnimation.configureNext(LayoutAnimation.Presets.spring);
    setExpanded(!expanded);
  };

  return (
    <View style={{ flex: 1, padding: 20 }}>
      <Button title="Toggle" onPress={toggleExpand} />
      <View style={{
        height: expanded ? 200 : 100,
        backgroundColor: 'orange',
        marginTop: 20,
      }} />
    </View>
  );
}
```

### LayoutAnimation 预设

```jsx
// 弹簧动画
LayoutAnimation.configureNext(LayoutAnimation.Presets.spring);

// 线性动画
LayoutAnimation.configureNext(LayoutAnimation.Presets.linear);

// 缓动动画
LayoutAnimation.configureNext(LayoutAnimation.Presets.easeInEaseOut);
```

### 自定义 LayoutAnimation

```jsx
LayoutAnimation.configureNext({
  duration: 700, // 持续时间
  create: { // 新元素出现时的动画
    type: LayoutAnimation.Types.spring,
    property: LayoutAnimation.Properties.opacity,
    springDamping: 0.7,
  },
  update: { // 更新时的动画
    type: LayoutAnimation.Types.spring,
    springDamping: 0.7,
  },
  delete: { // 元素消失时的动画
    type: LayoutAnimation.Types.spring,
    property: LayoutAnimation.Properties.opacity,
    springDamping: 0.7,
  },
});
```

## 手势动画

### 结合 React Native Gesture Handler

React Native Gesture Handler 提供了更底层的手势控制能力，与动画系统结合使用效果极佳。

```jsx
import { Animated } from 'react-native';
import {
  PanGestureHandler,
  State,
} from 'react-native-gesture-handler';

function GestureAnimation() {
  const translateX = useRef(new Animated.Value(0)).current;
  const translateY = useRef(new Animated.Value(0)).current;
  const lastOffset = useRef({ x: 0, y: 0 }).current;

  const onGestureEvent = Animated.event(
    [{
      nativeEvent: {
        translationX: translateX,
        translationY: translateY,
      },
    }],
    { useNativeDriver: true }
  );

  const onHandlerStateChange = event => {
    if (event.nativeEvent.oldState === State.ACTIVE) {
      // 保存最后的偏移值
      lastOffset.x += event.nativeEvent.translationX;
      lastOffset.y += event.nativeEvent.translationY;
      translateX.setOffset(lastOffset.x);
      translateX.setValue(0);
      translateY.setOffset(lastOffset.y);
      translateY.setValue(0);
    }
  };

  return (
    <PanGestureHandler
      onGestureEvent={onGestureEvent}
      onHandlerStateChange={onHandlerStateChange}
    >
      <Animated.View
        style={{
          transform: [
            { translateX },
            { translateY },
          ],
        }}
      />
    </PanGestureHandler>
  );
}
```

## Reanimated 2

React Native Reanimated 是一个更强大的动画库，它提供了在 UI 线程上运行的声明式动画。

### 安装

```bash
npm install react-native-reanimated@next
```

### 基本用法

```jsx
import React from 'react';
import { StyleSheet, Button, View } from 'react-native';
import Animated, {
  useSharedValue,
  withTiming,
  useAnimatedStyle,
  Easing,
} from 'react-native-reanimated';

export default function AnimatedStyleUpdateExample() {
  const offset = useSharedValue(0);

  const animatedStyles = useAnimatedStyle(() => {
    return {
      transform: [
        {
          translateX: withTiming(offset.value, {
            duration: 500,
            easing: Easing.bezier(0.25, 0.1, 0.25, 1),
          }),
        },
      ],
    };
  });

  return (
    <View style={styles.container}>
      <Animated.View style={[styles.box, animatedStyles]} />
      <Button
        onPress={() => {
          offset.value = Math.random() * 255;
        }}
        title="Move"
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
  box: {
    height: 120,
    width: 120,
    backgroundColor: '#b58df1',
    borderRadius: 20,
    marginBottom: 30,
  },
});
```

### Reanimated 2 的工作原理

Reanimated 2 使用工作线程（Worklet）在 UI 线程上运行 JavaScript 代码，这带来了几个主要优势：

1. 动画在 UI 线程上运行，消除了 JS-Native 桥接开销
2. 可以在不阻塞 JS 线程的情况下实现复杂的动画
3. 支持手势和动画的紧密集成

## 性能优化

### 使用原生驱动

```jsx
Animated.timing(opacity, {
  toValue: 1,
  duration: 1000,
  useNativeDriver: true, // 启用原生驱动
}).start();
```

### 避免过多的动画组件

尽量减少同时运行的动画数量，特别是在滚动列表中。

### 使用 shouldComponentUpdate 或 React.memo

```jsx
const AnimatedItem = React.memo(({ item, animValue }) => {
  // 组件实现
});
```

### 监控性能

使用 React Native 的性能监测工具来检测动画是否导致卡顿：

```jsx
// 开发模式下启用性能监测
if (__DEV__) {
  require('react-native').Systrace.setEnabled(true);
}
```

## 常见动画模式

### 淡入淡出

```jsx
import React, { useRef, useEffect } from 'react';
import { Animated } from 'react-native';

function FadeInOut({ visible, children }) {
  const opacity = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    Animated.timing(opacity, {
      toValue: visible ? 1 : 0,
      duration: 300,
      useNativeDriver: true,
    }).start();
  }, [visible]);

  return (
    <Animated.View style={{ opacity }}>
      {children}
    </Animated.View>
  );
}
```

### 弹出效果

```jsx
function PopIn({ children }) {
  const scale = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    Animated.spring(scale, {
      toValue: 1,
      friction: 5,
      tension: 40,
      useNativeDriver: true,
    }).start();
  }, []);

  return (
    <Animated.View style={{ transform: [{ scale }] }}>
      {children}
    </Animated.View>
  );
}
```

### 滑动进入

```jsx
function SlideIn({ children, direction = 'left' }) {
  const translateX = useRef(new Animated.Value(direction === 'left' ? -100 : 100)).current;

  useEffect(() => {
    Animated.spring(translateX, {
      toValue: 0,
      friction: 8,
      tension: 40,
      useNativeDriver: true,
    }).start();
  }, []);

  return (
    <Animated.View style={{ transform: [{ translateX }] }}>
      {children}
    </Animated.View>
  );
}
```

### 加载指示器

```jsx
function LoadingIndicator() {
  const rotation = useRef(new Animated.Value(0)).current;
  
  useEffect(() => {
    Animated.loop(
      Animated.timing(rotation, {
        toValue: 1,
        duration: 1500,
        useNativeDriver: true,
        easing: Easing.linear,
      })
    ).start();
  }, []);
  
  const spin = rotation.interpolate({
    inputRange: [0, 1],
    outputRange: ['0deg', '360deg'],
  });
  
  return (
    <Animated.View
      style={{
        width: 30,
        height: 30,
        borderWidth: 2,
        borderRadius: 15,
        borderColor: '#f0f0f0',
        borderTopColor: '#3498db',
        transform: [{ rotate: spin }],
      }}
    />
  );
}
```

## 最佳实践

### 1. 优先使用原生驱动

```jsx
// 好的做法
Animated.timing(opacity, {
  toValue: 1,
  useNativeDriver: true,
}).start();
```

### 2. 创建可重用的动画组件

```jsx
// 创建可重用的动画Hook
function useAnimation(config) {
  const { initialValue, toValue, duration } = config;
  const animValue = useRef(new Animated.Value(initialValue)).current;
  
  const animate = useCallback(() => {
    Animated.timing(animValue, {
      toValue,
      duration,
      useNativeDriver: true,
    }).start();
  }, [toValue, duration]);
  
  return [animValue, animate];
}

// 使用
function MyComponent() {
  const [opacity, fadeIn] = useAnimation({ initialValue: 0, toValue: 1, duration: 500 });
  
  useEffect(() => {
    fadeIn();
  }, []);
  
  return <Animated.View style={{ opacity }}>{/* content */}</Animated.View>;
}
```

### 3. 使用 useNativeDriver 的限制

原生驱动只能用于以下属性：
- transform
- opacity
- borderRadius (在较新版本的 React Native 中)

不能用于：
- backgroundColor
- width/height
- margin/padding
- position (left, top, etc.)

### 4. 动画完成回调

```jsx
Animated.timing(opacity, {
  toValue: 0,
  duration: 500,
  useNativeDriver: true,
}).start(({ finished }) => {
  // finished 为 true 表示动画正常完成
  // 为 false 表示动画被中断
  if (finished) {
    // 动画完成后的逻辑
    console.log('Animation completed');
  }
});
```

### 5. 多平台差异处理

某些动画在 iOS 和 Android 上表现不一致，需要针对平台做调整：

```jsx
import { Platform } from 'react-native';

const animConfig = {
  duration: 500,
  // Android上动画可能需要更多的弹性
  ...(Platform.OS === 'android' ? { friction: 8 } : { friction: 5 }),
  useNativeDriver: true,
};

Animated.spring(scale, animConfig).start();
```

## 总结

React Native 的动画系统提供了多种创建流畅用户体验的方式。从简单的透明度变化到复杂的交互式动画，都可以通过 Animated API 或 React Native Reanimated 实现。

理解动画的核心概念如动画值、插值和组合动画，以及使用原生驱动器来优化性能，是创建高质量 React Native 动画的关键。随着对这些工具的熟练掌握，你将能够创建既美观又高效的动画效果，大大提升应用的用户体验。

在大型应用中，建议逐步过渡到 Reanimated 2，它提供了更好的性能和更灵活的动画能力，特别是对于复杂的手势交互。无论选择哪种方案，合理使用动画始终是提升用户体验的有效方式。 