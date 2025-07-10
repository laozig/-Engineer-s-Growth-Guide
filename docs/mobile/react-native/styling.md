# React Native 样式与布局

React Native 提供了一个强大而灵活的样式系统，结合了 CSS 的熟悉语法与 JavaScript 的动态性。本文档深入探讨 React Native 的样式系统、Flexbox 布局和响应式设计技术。

## 目录

- [样式基础](#样式基础)
- [Flexbox 布局](#flexbox-布局)
- [尺寸与定位](#尺寸与定位)
- [颜色与背景](#颜色与背景)
- [文本样式](#文本样式)
- [边框与阴影](#边框与阴影)
- [样式组织与复用](#样式组织与复用)
- [响应式设计](#响应式设计)
- [动态样式](#动态样式)
- [平台特定样式](#平台特定样式)
- [常见布局模式](#常见布局模式)
- [最佳实践](#最佳实践)

## 样式基础

React Native 中的样式基于 CSS，但使用 JavaScript 对象语法。样式属性通常采用驼峰命名法（如 `backgroundColor` 而非 `background-color`）。

### 内联样式

```jsx
import { View, Text } from 'react-native';

function InlineStyleExample() {
  return (
    <View style={{ padding: 20, backgroundColor: '#f0f0f0' }}>
      <Text style={{ fontSize: 18, color: '#333' }}>
        这是使用内联样式的文本
      </Text>
    </View>
  );
}
```

### StyleSheet API

推荐使用 `StyleSheet.create` 创建样式，它提供了性能优化和自动完成功能。

```jsx
import { View, Text, StyleSheet } from 'react-native';

function StyleSheetExample() {
  return (
    <View style={styles.container}>
      <Text style={styles.text}>这是使用 StyleSheet 的文本</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    padding: 20,
    backgroundColor: '#f0f0f0',
  },
  text: {
    fontSize: 18,
    color: '#333',
  },
});
```

### 多样式组合

可以通过数组语法组合多个样式：

```jsx
<View style={[styles.container, styles.bordered]}>
  <Text style={[styles.text, styles.bold, { color: 'red' }]}>
    组合样式示例
  </Text>
</View>
```

## Flexbox 布局

React Native 使用 Flexbox 布局算法，但有一些与 Web 的差异：默认的 `flexDirection` 是 `column` 而非 `row`。

### Flex 属性

#### flex

`flex` 属性决定了子元素如何分配空间。

```jsx
import { View, StyleSheet } from 'react-native';

function FlexExample() {
  return (
    <View style={styles.container}>
      <View style={[styles.box, { flex: 1, backgroundColor: '#ff7979' }]} />
      <View style={[styles.box, { flex: 2, backgroundColor: '#badc58' }]} />
      <View style={[styles.box, { flex: 3, backgroundColor: '#7ed6df' }]} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    flexDirection: 'column',
  },
  box: {
    height: 50,
  },
});
```

在上面的例子中，总共有 6 个 flex 单位（1+2+3），第一个框占 1/6，第二个占 2/6，第三个占 3/6。

#### flexDirection

决定子元素排列的主轴方向：

```jsx
<View style={{ flexDirection: 'row' }}>
  {/* 子元素水平排列 */}
</View>

<View style={{ flexDirection: 'column' }}>
  {/* 子元素垂直排列（默认值） */}
</View>

<View style={{ flexDirection: 'row-reverse' }}>
  {/* 子元素水平排列但方向相反 */}
</View>

<View style={{ flexDirection: 'column-reverse' }}>
  {/* 子元素垂直排列但方向相反 */}
</View>
```

#### justifyContent

控制子元素沿主轴的对齐方式：

```jsx
<View style={{ justifyContent: 'flex-start' }}>
  {/* 子元素靠近主轴起点对齐（默认值） */}
</View>

<View style={{ justifyContent: 'flex-end' }}>
  {/* 子元素靠近主轴终点对齐 */}
</View>

<View style={{ justifyContent: 'center' }}>
  {/* 子元素在主轴上居中对齐 */}
</View>

<View style={{ justifyContent: 'space-between' }}>
  {/* 子元素均匀分布，第一个在起点，最后一个在终点 */}
</View>

<View style={{ justifyContent: 'space-around' }}>
  {/* 子元素均匀分布，两端有一半大小的间距 */}
</View>

<View style={{ justifyContent: 'space-evenly' }}>
  {/* 子元素均匀分布，间距完全相等 */}
</View>
```

#### alignItems

控制子元素沿交叉轴的对齐方式：

```jsx
<View style={{ alignItems: 'flex-start' }}>
  {/* 子元素靠近交叉轴起点对齐 */}
</View>

<View style={{ alignItems: 'flex-end' }}>
  {/* 子元素靠近交叉轴终点对齐 */}
</View>

<View style={{ alignItems: 'center' }}>
  {/* 子元素在交叉轴上居中对齐 */}
</View>

<View style={{ alignItems: 'stretch' }}>
  {/* 子元素拉伸以填充交叉轴（默认值） */}
</View>

<View style={{ alignItems: 'baseline' }}>
  {/* 子元素基于其基准线对齐 */}
</View>
```

#### alignSelf

可以覆盖父容器设置的 `alignItems` 值：

```jsx
<View style={{ alignItems: 'center' }}>
  <Text style={{ alignSelf: 'flex-start' }}>
    该文本将靠左对齐，忽略父元素的居中对齐设置
  </Text>
</View>
```

#### flexWrap

控制子元素是否换行：

```jsx
<View style={{ flexDirection: 'row', flexWrap: 'wrap' }}>
  {/* 子元素在需要时换行 */}
</View>

<View style={{ flexDirection: 'row', flexWrap: 'nowrap' }}>
  {/* 子元素不换行（默认值） */}
</View>
```

### 完整的 Flexbox 布局示例

```jsx
import { View, Text, StyleSheet } from 'react-native';

function FlexLayoutExample() {
  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerText}>头部</Text>
      </View>
      <View style={styles.content}>
        <View style={styles.sidebar}>
          <Text style={styles.sidebarText}>侧边栏</Text>
        </View>
        <View style={styles.mainContent}>
          <Text style={styles.mainText}>主要内容区域</Text>
        </View>
      </View>
      <View style={styles.footer}>
        <Text style={styles.footerText}>底部</Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    flexDirection: 'column',
  },
  header: {
    height: 60,
    backgroundColor: '#3498db',
    justifyContent: 'center',
    alignItems: 'center',
  },
  headerText: {
    color: '#fff',
    fontSize: 18,
  },
  content: {
    flex: 1,
    flexDirection: 'row',
  },
  sidebar: {
    flex: 1,
    backgroundColor: '#e67e22',
    justifyContent: 'center',
    alignItems: 'center',
  },
  sidebarText: {
    color: '#fff',
  },
  mainContent: {
    flex: 3,
    backgroundColor: '#f1c40f',
    justifyContent: 'center',
    alignItems: 'center',
  },
  mainText: {
    fontSize: 16,
  },
  footer: {
    height: 60,
    backgroundColor: '#2ecc71',
    justifyContent: 'center',
    alignItems: 'center',
  },
  footerText: {
    color: '#fff',
  },
});
```

## 尺寸与定位

### 尺寸单位

React Native 不使用像素单位，而是使用无单位的数字（对应设备的逻辑像素）：

```jsx
<View style={{ width: 100, height: 100 }} />
```

### 百分比尺寸

对于特定属性（如 `width`, `height`, `top`, `left` 等），可以使用百分比值：

```jsx
<View style={{ width: '50%', height: '25%' }} />
```

### 绝对与相对定位

```jsx
// 相对定位 (默认)
<View style={{ position: 'relative', left: 10, top: 10 }} />

// 绝对定位
<View style={{ position: 'absolute', left: 10, top: 10 }} />
```

### zIndex

控制重叠元素的堆叠顺序：

```jsx
<View style={{ position: 'absolute', zIndex: 1 }} />
```

## 颜色与背景

### 背景颜色

```jsx
<View style={{ backgroundColor: '#3498db' }} />
<View style={{ backgroundColor: 'rgba(52, 152, 219, 0.5)' }} />
```

### 不透明度

```jsx
<View style={{ opacity: 0.5 }} />
```

## 文本样式

```jsx
<Text style={{
  color: '#333',
  fontSize: 16,
  fontWeight: 'bold', // 'normal', 'bold', '100'~'900'
  fontStyle: 'italic', // 'normal', 'italic'
  textAlign: 'center', // 'auto', 'left', 'right', 'center', 'justify'
  textDecorationLine: 'underline', // 'none', 'underline', 'line-through', 'underline line-through'
  letterSpacing: 1.5, // 字符间距
  lineHeight: 24, // 行高
  textShadowColor: '#000',
  textShadowOffset: { width: 1, height: 1 },
  textShadowRadius: 3,
}}>
  文本样式示例
</Text>
```

### 自定义字体

```jsx
// 首先需要在项目中链接字体文件
import { Text } from 'react-native';

<Text style={{ fontFamily: 'YourCustomFont' }}>
  自定义字体文本
</Text>
```

## 边框与阴影

### 边框

```jsx
<View style={{
  borderWidth: 1,
  borderColor: '#ccc',
  borderRadius: 5, // 圆角
  borderStyle: 'solid', // 'solid', 'dotted', 'dashed'
}} />
```

也可以单独设置各边的边框：

```jsx
<View style={{
  borderLeftWidth: 2,
  borderLeftColor: 'red',
  borderRightWidth: 2,
  borderRightColor: 'blue',
  borderTopWidth: 2,
  borderTopColor: 'green',
  borderBottomWidth: 2,
  borderBottomColor: 'yellow',
}} />
```

### 阴影（iOS）

```jsx
<View style={{
  shadowColor: '#000',
  shadowOffset: { width: 0, height: 2 },
  shadowOpacity: 0.3,
  shadowRadius: 3,
}} />
```

### 阴影（Android）

Android 使用 `elevation` 属性：

```jsx
<View style={{ elevation: 5 }} />
```

## 样式组织与复用

### 组合样式

```jsx
import { StyleSheet } from 'react-native';

const baseStyles = StyleSheet.create({
  text: {
    fontSize: 16,
    color: '#333',
  },
});

const variants = StyleSheet.create({
  header: {
    fontSize: 24,
    fontWeight: 'bold',
  },
  warning: {
    color: 'red',
  },
});

// 使用组合
<Text style={[baseStyles.text, variants.header]}>标题文本</Text>
<Text style={[baseStyles.text, variants.warning]}>警告文本</Text>
```

### 样式函数

创建动态样式的函数：

```jsx
function getButtonStyle(type) {
  return {
    padding: 10,
    borderRadius: 5,
    backgroundColor: type === 'primary' ? '#3498db' : '#e74c3c',
  };
}

<TouchableOpacity style={getButtonStyle('primary')}>
  <Text>主按钮</Text>
</TouchableOpacity>
```

### 主题系统

```jsx
import { createContext, useContext } from 'react';

// 创建主题上下文
const ThemeContext = createContext({
  colors: {
    primary: '#3498db',
    secondary: '#2ecc71',
    text: '#333',
    background: '#fff',
  },
  spacing: {
    small: 8,
    medium: 16,
    large: 24,
  },
});

// 使用主题
function ThemedComponent() {
  const theme = useContext(ThemeContext);
  
  return (
    <View style={{ 
      backgroundColor: theme.colors.background,
      padding: theme.spacing.medium,
    }}>
      <Text style={{ color: theme.colors.text }}>
        主题化组件
      </Text>
      <TouchableOpacity style={{ 
        backgroundColor: theme.colors.primary,
        padding: theme.spacing.small,
        borderRadius: 5,
      }}>
        <Text style={{ color: '#fff' }}>按钮</Text>
      </TouchableOpacity>
    </View>
  );
}
```

## 响应式设计

### 获取屏幕尺寸

```jsx
import { View, Text, Dimensions } from 'react-native';

function ResponsiveComponent() {
  const windowWidth = Dimensions.get('window').width;
  const windowHeight = Dimensions.get('window').height;
  
  return (
    <View>
      <Text>屏幕宽度: {windowWidth}</Text>
      <Text>屏幕高度: {windowHeight}</Text>
    </View>
  );
}
```

### 动态适应屏幕尺寸

```jsx
import { StyleSheet, View, Dimensions } from 'react-native';

const windowWidth = Dimensions.get('window').width;

function ResponsiveLayout() {
  return (
    <View style={styles.container}>
      <View style={[styles.box, { width: windowWidth < 500 ? '100%' : '50%' }]} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
  },
  box: {
    height: 100,
    backgroundColor: '#3498db',
  },
});
```

### 使用 useWindowDimensions Hook

`useWindowDimensions` 会在窗口尺寸变化时自动更新，比 `Dimensions.get` 更适合响应式布局：

```jsx
import { View, useWindowDimensions } from 'react-native';

function DynamicComponent() {
  const { width, height } = useWindowDimensions();
  
  return (
    <View style={{
      width: width > 500 ? '50%' : '90%',
      height: height > 700 ? 200 : 100,
    }}>
      {/* 内容 */}
    </View>
  );
}
```

### 横竖屏适配

```jsx
import { useState, useEffect } from 'react';
import { View, Dimensions } from 'react-native';

function OrientationAwareComponent() {
  const [orientation, setOrientation] = useState(
    Dimensions.get('window').width > Dimensions.get('window').height ? 'landscape' : 'portrait'
  );
  
  useEffect(() => {
    const updateOrientation = () => {
      const { width, height } = Dimensions.get('window');
      setOrientation(width > height ? 'landscape' : 'portrait');
    };
    
    Dimensions.addEventListener('change', updateOrientation);
    
    return () => {
      // 清理监听器
    };
  }, []);
  
  return (
    <View style={{
      flexDirection: orientation === 'landscape' ? 'row' : 'column',
    }}>
      {/* 根据方向调整的内容 */}
    </View>
  );
}
```

## 动态样式

### 条件样式

```jsx
function ConditionalStyleComponent({ isActive, isError }) {
  return (
    <View
      style={{
        backgroundColor: isError ? 'red' : isActive ? 'green' : 'gray',
        padding: isActive ? 20 : 10,
      }}
    >
      {/* 内容 */}
    </View>
  );
}
```

### 基于状态的样式

```jsx
import { useState } from 'react';
import { View, TouchableOpacity, Text, StyleSheet } from 'react-native';

function StatefulButton() {
  const [isPressed, setIsPressed] = useState(false);
  
  return (
    <TouchableOpacity
      style={[
        styles.button,
        isPressed ? styles.buttonPressed : styles.buttonNormal,
      ]}
      onPressIn={() => setIsPressed(true)}
      onPressOut={() => setIsPressed(false)}
    >
      <Text style={styles.text}>按钮</Text>
    </TouchableOpacity>
  );
}

const styles = StyleSheet.create({
  button: {
    padding: 15,
    borderRadius: 5,
  },
  buttonNormal: {
    backgroundColor: '#3498db',
  },
  buttonPressed: {
    backgroundColor: '#2980b9',
  },
  text: {
    color: '#fff',
    textAlign: 'center',
  },
});
```

## 平台特定样式

### 使用 Platform 模块

```jsx
import { Platform, StyleSheet } from 'react-native';

const styles = StyleSheet.create({
  container: {
    ...Platform.select({
      ios: {
        shadowColor: '#000',
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.3,
        shadowRadius: 3,
      },
      android: {
        elevation: 5,
      },
    }),
  },
});
```

### 平台特定文件

创建具有平台后缀的文件：
- `MyComponent.ios.js`
- `MyComponent.android.js`

然后只需引入：

```jsx
import MyComponent from './MyComponent'; // 自动选择正确的平台版本
```

## 常见布局模式

### 卡片布局

```jsx
import { View, Text, StyleSheet } from 'react-native';

function Card({ title, content }) {
  return (
    <View style={styles.card}>
      <Text style={styles.cardTitle}>{title}</Text>
      <Text style={styles.cardContent}>{content}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: '#fff',
    borderRadius: 8,
    padding: 16,
    marginVertical: 8,
    marginHorizontal: 16,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 6,
    elevation: 2,
  },
  cardTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 8,
  },
  cardContent: {
    fontSize: 14,
    color: '#666',
  },
});
```

### 网格布局

```jsx
import { View, Text, StyleSheet, FlatList } from 'react-native';

function GridLayout({ data, numColumns = 2 }) {
  const renderItem = ({ item }) => (
    <View style={styles.gridItem}>
      <Text>{item.title}</Text>
    </View>
  );
  
  return (
    <FlatList
      data={data}
      renderItem={renderItem}
      numColumns={numColumns}
      keyExtractor={item => item.id}
      contentContainerStyle={styles.grid}
    />
  );
}

const styles = StyleSheet.create({
  grid: {
    padding: 8,
  },
  gridItem: {
    flex: 1,
    margin: 8,
    height: 150,
    backgroundColor: '#f9f9f9',
    borderRadius: 8,
    justifyContent: 'center',
    alignItems: 'center',
  },
});
```

### 堆叠布局

```jsx
import { View, Text, StyleSheet } from 'react-native';

function StackedLayout() {
  return (
    <View style={styles.container}>
      <View style={styles.background} />
      <View style={styles.card}>
        <Text style={styles.cardText}>堆叠在背景上的卡片</Text>
      </View>
      <View style={styles.floatingButton}>
        <Text style={styles.buttonText}>+</Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  background: {
    ...StyleSheet.absoluteFillObject, // 填满整个父容器
    backgroundColor: '#3498db',
  },
  card: {
    position: 'absolute',
    top: 100,
    left: 20,
    right: 20,
    height: 200,
    backgroundColor: '#fff',
    borderRadius: 10,
    padding: 20,
    justifyContent: 'center',
    alignItems: 'center',
    elevation: 5,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.3,
    shadowRadius: 4,
  },
  cardText: {
    fontSize: 18,
  },
  floatingButton: {
    position: 'absolute',
    right: 20,
    bottom: 20,
    width: 60,
    height: 60,
    borderRadius: 30,
    backgroundColor: '#e74c3c',
    justifyContent: 'center',
    alignItems: 'center',
    elevation: 8,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 4,
  },
  buttonText: {
    fontSize: 30,
    color: '#fff',
  },
});
```

## 最佳实践

### 样式结构化

```jsx
// 按功能组织样式
const styles = StyleSheet.create({
  // 布局相关
  container: {
    flex: 1,
    padding: 20,
  },
  row: {
    flexDirection: 'row',
  },
  
  // 组件特定样式
  button: {
    padding: 10,
    borderRadius: 5,
  },
  buttonPrimary: {
    backgroundColor: '#3498db',
  },
  
  // 文本样式
  text: {
    fontSize: 16,
  },
  textHeader: {
    fontSize: 24,
    fontWeight: 'bold',
  },
});
```

### 避免过度使用绝对定位

绝对定位会使布局变得脆弱，难以适应不同屏幕尺寸。尽量使用 Flex 布局：

```jsx
// 不推荐
const styles = StyleSheet.create({
  container: {
    position: 'relative',
    height: 300,
  },
  header: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    height: 60,
  },
  content: {
    position: 'absolute',
    top: 60,
    bottom: 60,
    left: 0,
    right: 0,
  },
  footer: {
    position: 'absolute',
    bottom: 0,
    left: 0,
    right: 0,
    height: 60,
  },
});

// 推荐
const styles = StyleSheet.create({
  container: {
    flex: 1,
    flexDirection: 'column',
  },
  header: {
    height: 60,
  },
  content: {
    flex: 1,
  },
  footer: {
    height: 60,
  },
});
```

### 使用常量定义样式值

```jsx
// 样式常量文件 (styleConstants.js)
export const COLORS = {
  primary: '#3498db',
  secondary: '#2ecc71',
  accent: '#e74c3c',
  background: '#f9f9f9',
  text: '#333',
  lightText: '#999',
};

export const SPACING = {
  small: 8,
  medium: 16,
  large: 24,
};

export const FONT_SIZES = {
  small: 12,
  regular: 16,
  large: 20,
  extraLarge: 24,
};

// 在组件中使用
import { COLORS, SPACING, FONT_SIZES } from './styleConstants';

const styles = StyleSheet.create({
  container: {
    backgroundColor: COLORS.background,
    padding: SPACING.medium,
  },
  title: {
    fontSize: FONT_SIZES.large,
    color: COLORS.text,
  },
});
```

### 避免深层次的样式对象

```jsx
// 不推荐
const styles = StyleSheet.create({
  container: {
    backgroundColor: '#fff',
    borderWidth: 1,
    borderColor: '#ccc',
    borderRadius: 5,
    padding: 10,
    margin: 10,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 2,
    elevation: 2,
  },
});

// 推荐 - 分解为可复用部分
const styles = StyleSheet.create({
  container: {
    backgroundColor: '#fff',
    padding: 10,
    margin: 10,
  },
  bordered: {
    borderWidth: 1,
    borderColor: '#ccc',
    borderRadius: 5,
  },
  shadowed: {
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 2,
    elevation: 2,
  },
});

// 使用
<View style={[styles.container, styles.bordered, styles.shadowed]} />
```

## 总结

React Native 的样式系统结合了 CSS 的熟悉语法和 JavaScript 的灵活性，使开发者能够创建既美观又高性能的移动应用界面。掌握 Flexbox 布局是构建响应式界面的关键，而合理组织样式代码则可以提高可维护性和复用性。

通过本文档中展示的各种技术和最佳实践，你可以在 React Native 中创建出适应各种设备尺寸和平台的优秀用户界面。记住，好的 UI 设计不仅仅是外观，还包括性能和用户体验，所以始终关注样式对应用性能的影响。 