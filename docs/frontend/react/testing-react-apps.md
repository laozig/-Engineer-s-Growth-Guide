# 17. 测试: Jest & React Testing Library

在软件开发中，测试是保证代码质量、减少 Bug、提升应用稳定性和可维护性的关键环节。在 React 生态中，测试通常分为几种类型，但最常见的是**单元测试 (Unit Testing)** 和**集成测试 (Integration Testing)**。

现代 React 测试的主流工具栈是 **Jest** + **React Testing Library**。Create React App 已经内置了对它们的支持。

## 核心工具

### Jest
Jest 是一个由 Facebook 开发的、功能全面的 JavaScript 测试框架。它提供了运行测试所需的一切：
- **测试运行器 (Test Runner)**: 负责找到测试文件、执行测试、并报告结果。
- **断言库 (Assertion Library)**: 提供了像 `expect(value).toBe(true)` 这样的函数，用于验证你的代码是否产生了预期的结果。
- **Mocking / Spying**: 允许你创建"模拟"函数或模块，以便在测试中隔离被测试的单元。
- **快照测试 (Snapshot Testing)**: 一种特殊的测试，用于跟踪 UI 的变化。

### React Testing Library (RTL)
React Testing Library 是一个专注于测试 React 组件的库。它的核心哲学是：
> **你的测试代码应该尽可能地模拟用户与应用交互的方式。**

与早期的一些测试库（如 Enzyme）不同，RTL **不鼓励**你测试组件的内部实现细节（如 state, props, 或实例方法）。相反，它鼓励你通过用户能看到和交互的方式来测试组件。你应该去查找表单、按钮、文本等，然后与它们交互（点击、输入），最后断言 UI 是否如预期那样发生了变化。

这种方法使得你的测试更加健壮和易于维护。当你的组件实现发生重构时（例如，从 Class 组件改为函数组件），只要其最终的行为对用户来说没有改变，你的测试就**不需要**修改。

## 编写你的第一个测试

假设我们有一个简单的计数器组件 `Counter.js`：
```jsx
// src/components/Counter.js
import React, { useState } from 'react';

export default function Counter() {
  const [count, setCount] = useState(0);

  return (
    <div>
      <h1>Counter</h1>
      <p>Current count: {count}</p>
      <button onClick={() => setCount(count + 1)}>Increment</button>
    </div>
  );
}
```

现在，我们为它编写一个测试文件 `Counter.test.js`：
```jsx
// src/components/Counter.test.js
import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom'; // 提供了额外的 DOM 断言，如 .toBeInTheDocument()
import Counter from './Counter';

describe('Counter component', () => {

  // 测试用例 1: 检查组件是否能正确渲染初始状态
  test('renders initial state correctly', () => {
    // 1. Arrange: 渲染组件
    render(<Counter />);
    
    // 2. Act: (无，因为我们只测试初始渲染)

    // 3. Assert: 断言 UI 是否符合预期
    // 检查标题是否存在
    expect(screen.getByRole('heading', { name: /counter/i })).toBeInTheDocument();
    
    // 检查初始计数值是否为 0
    expect(screen.getByText(/current count: 0/i)).toBeInTheDocument();

    // 检查按钮是否存在
    expect(screen.getByRole('button', { name: /increment/i })).toBeInTheDocument();
  });

  // 测试用例 2: 检查点击按钮后，计数值是否会增加
  test('increments count when increment button is clicked', () => {
    // 1. Arrange: 渲染组件
    render(<Counter />);
    
    // 2. Act: 模拟用户行为
    // 找到 "Increment" 按钮
    const incrementButton = screen.getByRole('button', { name: /increment/i });
    // 模拟点击事件
    fireEvent.click(incrementButton);

    // 3. Assert: 断言 UI 是否更新
    // 检查计数值是否变成了 1
    expect(screen.getByText(/current count: 1/i)).toBeInTheDocument();
    
    // 检查旧的计数值是否已不存在 (可选，但更严谨)
    expect(screen.queryByText(/current count: 0/i)).not.toBeInTheDocument();
  });

});
```

### 测试流程解析

- **`describe`**: 将相关的测试用例组织在一起。
- **`test` (或 `it`)**: 定义一个单独的测试用例。
- **`render`**: 由 RTL 提供，用于将你的 React 组件渲染到一个虚拟的 DOM 中（使用 JSDOM）。
- **`screen`**: 由 RTL 提供，它是一个包含所有查询方法的对象，用于查找 DOM 中的元素。
- **查询方法 (Queries)**:
    - `getBy...`: 查找一个元素，如果找不到或找到多个，会抛出错误。
    - `queryBy...`: 查找一个元素，如果找不到，返回 `null`，不会抛错。用于断言某个元素**不**存在。
    - `findBy...`: 查找一个元素，返回一个 Promise。用于处理异步出现的元素。
- **`fireEvent`**: 由 RTL 提供，用于触发 DOM 事件，模拟用户交互。

## 模拟 (Mocking)

当你的组件依赖于外部模块（如 API 请求、第三方库）时，你不希望在测试中真实地调用它们。这时就需要使用 Jest 的模拟功能。

假设一个组件在挂载时会请求用户数据：
```jsx
// src/components/UserProfile.js
import React, { useState, useEffect } from 'react';
import axios from 'axios';

export default function UserProfile({ userId }) {
  const [user, setUser] = useState(null);

  useEffect(() => {
    axios.get(`/api/users/${userId}`)
      .then(response => setUser(response.data));
  }, [userId]);

  if (!user) {
    return <div>Loading...</div>;
  }

  return <h1>{user.name}</h1>;
}
```

在测试中，我们可以模拟 `axios`：
```jsx
// src/components/UserProfile.test.js
import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import axios from 'axios';
import UserProfile from './UserProfile';

// 告诉 Jest 我们要模拟 axios 模块
jest.mock('axios');

test('displays user name after fetching data', async () => {
  const mockUser = { name: 'John Doe' };
  
  // 模拟 get 请求的返回值
  axios.get.mockResolvedValue({ data: mockUser });

  render(<UserProfile userId="1" />);

  // 初始状态下，显示 "Loading..."
  expect(screen.getByText(/loading/i)).toBeInTheDocument();

  // 等待异步操作完成，并断言最终的 UI 状态
  // findBy... 方法会等待元素出现
  const userNameElement = await screen.findByText('John Doe');
  expect(userNameElement).toBeInTheDocument();
  
  // 确认 loading 文本已消失
  expect(screen.queryByText(/loading/i)).not.toBeInTheDocument();
});
```

- **`jest.mock('axios')`**: 自动将 `axios` 模块替换为一个模拟版本。
- **`axios.get.mockResolvedValue(...)`**: 指定当 `axios.get` 被调用时，应该返回一个解析后的 Promise，其值为我们提供的模拟数据。
- **`await screen.findByText(...)`**: `findBy` 查询方法是异步的，它会等待直到找到元素或者超时。这对于测试异步更新的UI至关重要。

编写测试可能在一开始会感觉有些繁琐，但它带来的好处是巨大的。它迫使你编写更松耦合、更可测试的代码，并为你提供了一个强大的安全网，让你在重构或添加新功能时充满信心。 