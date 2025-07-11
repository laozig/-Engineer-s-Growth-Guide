# React Native 测试与调试

React Native 应用的测试与调试是确保应用质量和开发效率的关键环节。本文将介绍 React Native 中的测试策略、常用测试工具以及调试技巧，帮助开发者构建高质量的移动应用。

## 目录

- [单元测试](#单元测试)
  - [Jest 基础](#jest-基础)
  - [组件测试](#组件测试)
  - [Hook 测试](#hook-测试)
  - [模拟 (Mocking)](#模拟-mocking)
- [集成测试](#集成测试)
  - [React Native Testing Library](#react-native-testing-library)
  - [端到端测试工具](#端到端测试工具)
  - [Detox](#detox)
  - [Appium](#appium)
- [调试技巧](#调试技巧)
  - [React Developer Tools](#react-developer-tools)
  - [Flipper](#flipper)
  - [Chrome 开发者工具](#chrome-开发者工具)
  - [日志调试](#日志调试)
  - [性能调试](#性能调试)
- [常见问题与解决方案](#常见问题与解决方案)
- [最佳实践](#最佳实践)

## 单元测试

单元测试是验证代码最小单元（如函数、组件）正确性的测试。在 React Native 中，Jest 是最常用的单元测试框架。

### Jest 基础

Jest 是一个零配置的测试框架，已集成在 React Native 项目中。以下是基本用法：

```javascript
// 创建一个简单的测试文件 sum.test.js
function sum(a, b) {
  return a + b;
}

test('adds 1 + 2 to equal 3', () => {
  expect(sum(1, 2)).toBe(3);
});
```

运行测试：

```bash
npx jest
```

Jest 配置：在 `package.json` 中可以添加 Jest 配置，或创建 `jest.config.js` 文件：

```javascript
// jest.config.js
module.exports = {
  preset: 'react-native',
  setupFiles: ['./jest.setup.js'],
  transformIgnorePatterns: [
    'node_modules/(?!(react-native|@react-native|react-navigation|@react-navigation)/)',
  ],
};
```

### 组件测试

测试 React Native 组件需要使用 React Test Renderer 或 React Native Testing Library：

```javascript
// Button.test.js
import React from 'react';
import renderer from 'react-test-renderer';
import Button from './Button';

test('Button renders correctly', () => {
  const tree = renderer.create(<Button title="测试按钮" />).toJSON();
  expect(tree).toMatchSnapshot();
});

test('Button onPress works', () => {
  const onPressMock = jest.fn();
  const component = renderer.create(<Button title="测试按钮" onPress={onPressMock} />);
  const button = component.root.findByType('TouchableOpacity');
  
  button.props.onPress();
  expect(onPressMock).toHaveBeenCalledTimes(1);
});
```

快照测试是组件测试的常用方法，它可以捕获组件渲染输出并与之前的快照比较：

```javascript
test('组件快照测试', () => {
  const tree = renderer.create(<MyComponent />).toJSON();
  expect(tree).toMatchSnapshot();
});
```

### Hook 测试

测试自定义 Hook 需要使用 `@testing-library/react-hooks`：

```javascript
// useCounter.js
import { useState } from 'react';

function useCounter(initialValue = 0) {
  const [count, setCount] = useState(initialValue);
  const increment = () => setCount(c => c + 1);
  const decrement = () => setCount(c => c - 1);
  return { count, increment, decrement };
}

// useCounter.test.js
import { renderHook, act } from '@testing-library/react-hooks';
import useCounter from './useCounter';

test('应该使用初始值初始化', () => {
  const { result } = renderHook(() => useCounter(5));
  expect(result.current.count).toBe(5);
});

test('应该递增计数', () => {
  const { result } = renderHook(() => useCounter());
  act(() => {
    result.current.increment();
  });
  expect(result.current.count).toBe(1);
});
```

### 模拟 (Mocking)

模拟是测试中的重要技术，用于隔离被测代码并控制其依赖：

1. **函数模拟**：

```javascript
test('测试函数调用', () => {
  const mockCallback = jest.fn();
  forEach([1, 2], mockCallback);
  
  expect(mockCallback.mock.calls.length).toBe(2);
  expect(mockCallback.mock.calls[0][0]).toBe(1);
});
```

2. **模块模拟**：

```javascript
// 模拟 axios
jest.mock('axios');

test('应该获取用户数据', async () => {
  const users = [{ name: 'Bob' }];
  axios.get.mockResolvedValue({ data: users });
  
  await expect(fetchUsers()).resolves.toEqual(users);
});
```

3. **模拟原生模块**：

```javascript
// 模拟 Alert
jest.mock('react-native/Libraries/Alert/Alert', () => ({
  alert: jest.fn(),
}));
```

4. **定时器模拟**：

```javascript
jest.useFakeTimers();

test('测试定时器', () => {
  const callback = jest.fn();
  setTimeout(callback, 1000);
  
  // 快进所有定时器
  jest.runAllTimers();
  expect(callback).toHaveBeenCalled();
});
```

## 集成测试

集成测试验证多个组件或功能一起工作的正确性。

### React Native Testing Library

React Native Testing Library (RNTL) 提供了比 Test Renderer 更友好的 API，专注于从用户角度测试组件：

```bash
npm install --save-dev @testing-library/react-native
```

基本用法：

```javascript
// LoginForm.test.js
import React from 'react';
import { render, fireEvent, waitFor } from '@testing-library/react-native';
import LoginForm from './LoginForm';

test('应该提交登录表单', async () => {
  const onSubmit = jest.fn();
  const { getByPlaceholderText, getByText } = render(
    <LoginForm onSubmit={onSubmit} />
  );
  
  fireEvent.changeText(getByPlaceholderText('用户名'), 'testuser');
  fireEvent.changeText(getByPlaceholderText('密码'), 'password');
  fireEvent.press(getByText('登录'));
  
  await waitFor(() => {
    expect(onSubmit).toHaveBeenCalledWith({
      username: 'testuser',
      password: 'password',
    });
  });
});
```

RNTL 提供的关键功能：

- 多种查询方法（getByText, getByTestId 等）
- 事件触发（fireEvent）
- 异步测试助手（waitFor, waitForElementToBeRemoved）

### 端到端测试工具

端到端测试验证应用从头到尾的功能，更接近真实用户体验。

### Detox

Detox 是一个端到端测试框架，专为 React Native 和原生应用设计：

```bash
npm install --save-dev detox
```

配置 Detox（在 `package.json` 中添加）：

```json
{
  "detox": {
    "configurations": {
      "ios.sim.debug": {
        "binaryPath": "ios/build/Build/Products/Debug-iphonesimulator/MyApp.app",
        "build": "xcodebuild -workspace ios/MyApp.xcworkspace -scheme MyApp -configuration Debug -sdk iphonesimulator -derivedDataPath ios/build",
        "type": "ios.simulator",
        "device": {
          "type": "iPhone 12"
        }
      }
    },
    "test-runner": "jest"
  }
}
```

Detox 测试示例：

```javascript
// e2e/login.test.js
describe('登录流程', () => {
  beforeAll(async () => {
    await device.launchApp();
  });

  beforeEach(async () => {
    await device.reloadReactNative();
  });

  it('应该成功登录', async () => {
    await element(by.id('username')).typeText('user@example.com');
    await element(by.id('password')).typeText('password123');
    await element(by.text('登录')).tap();
    
    await expect(element(by.text('欢迎回来'))).toBeVisible();
  });
});
```

运行 Detox 测试：

```bash
npx detox build --configuration ios.sim.debug
npx detox test --configuration ios.sim.debug
```

### Appium

Appium 是一个开源的跨平台自动化测试工具，支持 iOS 和 Android：

```bash
npm install --save-dev webdriverio
```

Appium 测试示例：

```javascript
// test/specs/app.test.js
const { remote } = require('webdriverio');

describe('我的 React Native 应用', () => {
  let client;

  before(async () => {
    client = await remote({
      logLevel: 'error',
      path: '/wd/hub',
      capabilities: {
        platformName: 'iOS',
        'appium:deviceName': 'iPhone Simulator',
        'appium:app': '/path/to/my-app.app',
        'appium:automationName': 'XCUITest'
      }
    });
  });

  after(async () => {
    await client.deleteSession();
  });

  it('应该显示欢迎文本', async () => {
    const welcomeText = await client.$('~Welcome');
    await expect(welcomeText).toBeDisplayed();
  });
});
```

## 调试技巧

有效的调试对于解决问题和提高开发效率至关重要。

### React Developer Tools

React Developer Tools 是调试 React 组件最强大的工具之一：

```bash
npm install -g react-devtools
```

使用方法：

1. 运行独立应用：`react-devtools`
2. 连接到你的 React Native 应用
3. 检查组件树、props、state 等

### Flipper

Flipper 是 Facebook 的开源调试平台，提供丰富的插件生态系统：

```bash
npm install --save-dev flipper-plugin-react-native-performance
```

Flipper 主要功能：

- 日志查看器
- 网络请求监控
- 布局检查器
- Redux 调试
- AsyncStorage 查看器
- React Native 性能监控

### Chrome 开发者工具

使用 Chrome 开发者工具调试 React Native 应用：

1. 在开发菜单中选择 "Debug JS Remotely"
2. Chrome 调试器将打开，可以使用 Sources 标签页设置断点
3. 使用 Console 标签页查看日志和执行代码

快捷键调试技巧：

- 在模拟器中按 `Cmd+D` (iOS) 或 `Cmd+M` (Android) 打开开发菜单
- 使用 Chrome 的 `Cmd+Option+I` 打开开发者工具

### 日志调试

使用日志进行调试是最基本也是最常用的方法：

```javascript
console.log('变量值:', myVariable);
console.warn('警告信息');
console.error('错误信息');
console.info('信息消息');

// 分组日志
console.group('API 请求');
console.log('请求 URL:', url);
console.log('请求参数:', params);
console.groupEnd();

// 表格形式展示数据
console.table([
  { name: 'John', age: 30 },
  { name: 'Jane', age: 25 }
]);

// 性能计时
console.time('操作耗时');
// 执行一些操作
console.timeEnd('操作耗时');
```

### 性能调试

使用内置的性能工具监测应用性能：

```javascript
import { PerformanceObserver, performance } from 'react-native';

// 标记开始
performance.mark('functionStart');

// 执行一些代码
doSomething();

// 标记结束
performance.mark('functionEnd');

// 测量两个标记之间的时间
performance.measure('functionDuration', 'functionStart', 'functionEnd');

// 创建观察者获取性能度量结果
const observer = new PerformanceObserver((list) => {
  const entries = list.getEntries();
  entries.forEach((entry) => {
    console.log(`${entry.name}: ${entry.duration}ms`);
  });
});

observer.observe({ entryTypes: ['measure'] });
```

使用 Systrace 进行性能分析：

```bash
npx react-native profile
```

## 常见问题与解决方案

### 1. 测试时的 "ReferenceError: fetch is not defined"

**问题**: Jest 测试环境中没有 `fetch` API。

**解决方案**: 在 `jest.setup.js` 中添加 fetch polyfill：

```javascript
// jest.setup.js
global.fetch = require('jest-fetch-mock');
```

并更新 Jest 配置：

```javascript
// jest.config.js
module.exports = {
  setupFiles: ['./jest.setup.js'],
};
```

### 2. 模拟原生模块失败

**问题**: 无法正确模拟 React Native 原生模块。

**解决方案**: 确保正确设置了 `transformIgnorePatterns`：

```javascript
// jest.config.js
module.exports = {
  transformIgnorePatterns: [
    'node_modules/(?!(react-native|@react-native|react-navigation|@react-navigation)/)',
  ],
};
```

### 3. 组件渲染不匹配快照

**问题**: 组件快照测试失败，显示不匹配。

**解决方案**: 检查是否有动态内容，如日期或随机值。对于这些内容，可以使用自定义序列化器或模拟：

```javascript
// 模拟 Date
Date.now = jest.fn(() => 1600000000000);

// 或者使用自定义序列化器
expect.addSnapshotSerializer({
  test: (val) => val && val.type === 'DateDisplay',
  print: () => 'DateDisplay(mocked-date)',
});
```

### 4. Detox 测试找不到元素

**问题**: Detox 测试无法找到指定的 UI 元素。

**解决方案**: 确保为组件添加了适当的测试 ID：

```jsx
<TextInput
  testID="username"  // iOS 和 Android
  accessibilityLabel="username"  // 提高可访问性
  placeholder="用户名"
/>
```

## 最佳实践

1. **测试金字塔**：遵循测试金字塔原则，多写单元测试，适量写集成测试，少量写端到端测试。

2. **测试文件组织**：将测试文件与源文件放在一起，或创建平行的 `__tests__` 目录：
   ```
   src/
   ├── components/
   │   ├── Button.js
   │   └── __tests__/
   │       └── Button.test.js
   ```

3. **命名约定**：使用一致的命名约定，如 `*.test.js` 或 `*.spec.js`。

4. **测试覆盖率**：定期检查测试覆盖率，并设定最低覆盖率要求：
   ```bash
   npx jest --coverage
   ```

5. **持续集成**：将测试集成到 CI/CD 流程中，确保每次提交都运行测试。

6. **独立测试**：每个测试应该是独立的，不依赖其他测试的状态。

7. **模拟外部依赖**：测试时模拟外部依赖（API、数据库等），使测试更可靠。

8. **快照测试使用指南**：
   - 谨慎使用快照测试，避免过大的快照
   - 检查快照差异，确保变化是预期的
   - 定期更新快照 (`npx jest -u`)

9. **测试行为而非实现**：测试组件的行为和输出，而非内部实现细节。

10. **调试日志管理**：
    - 生产环境中移除或禁用详细调试日志
    - 考虑使用日志库管理不同环境的日志级别
    ```javascript
    import { LogBox } from 'react-native';
    
    // 忽略特定警告
    LogBox.ignoreLogs(['特定警告文本']);
    
    // 禁用所有黄色框警告（仅在开发时使用）
    if (__DEV__) {
      LogBox.ignoreAllLogs();
    }
    ```

测试和调试是开发高质量 React Native 应用的关键部分。通过采用本文介绍的工具和技术，开发者可以更有效地发现和解决问题，提高应用的稳定性和用户体验。 