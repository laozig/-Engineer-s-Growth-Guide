# 测试: Vitest & Vue Testing Library

单元测试和组件测试是确保 Vue 应用质量、可维护性和稳定性的关键环节。在现代 Vue 生态中，Vitest 和 Vue Testing Library 是进行测试的黄金搭档。

-   **Vitest**: 一个由 Vite 驱动的极速单元测试框架。它与 Vite 无缝集成，提供了与 Jest 兼容的 API，并拥有闪电般的速度。
-   **Vue Testing Library**: 一个轻量级的 Vue 组件测试库，鼓励开发者编写关注用户行为而非实现细节的测试。

## Vitest

Vitest 利用了 Vite 的按需编译能力，使得测试启动和执行都非常快。它的配置和使用方式与 Jest 非常相似，使得迁移和学习成本都很低。

### 核心特性

-   **Vite 驱动**: 与你的 Vite 配置共享，开箱即用。
-   **智能文件监听**: 极速的 HMR 和测试重跑。
-   **与 Jest 兼容**: 支持 `describe`, `it`, `expect` 等 API。
-   **内置功能**: 开箱即用的 TypeScript/JSX、断言、Mocking、覆盖率报告等。

### 示例：测试一个简单的函数

```javascript
// utils/math.js
export function add(a, b) {
  return a + b;
}

// tests/math.spec.js
import { describe, it, expect } from 'vitest';
import { add } from '../utils/math';

describe('add', () => {
  it('should add two numbers', () => {
    expect(add(1, 2)).toBe(3);
  });
});
```

## Vue Testing Library

Vue Testing Library (VTL) 建立在 DOM Testing Library 之上，提供了一系列查询 DOM 的方法，使得测试更贴近用户的实际使用方式。它的核心理念是：**测试越是模拟真实用户的使用方式，就越能提供信心。**

### 安装

```bash
npm install --save-dev @testing-library/vue
```

### 示例：测试一个计数器组件

假设我们有以下组件：

```vue
<!-- components/Counter.vue -->
<template>
  <div>
    <span>Count: {{ count }}</span>
    <button @click="increment">Increment</button>
  </div>
</template>

<script setup>
import { ref } from 'vue';

const count = ref(0);
const increment = () => {
  count.value++;
};
</script>
```

我们可以这样测试它：

```javascript
// tests/Counter.spec.js
import { render, screen, fireEvent } from '@testing-library/vue';
import Counter from '../components/Counter.vue';

describe('Counter', () => {
  it('increments count when button is clicked', async () => {
    // 1. 渲染组件
    render(Counter);

    // 2. 查找元素
    // screen 对象提供了多种查询方法
    const button = screen.getByRole('button', { name: /increment/i });
    const countSpan = screen.getByText(/count: 0/i);

    // 3. 断言初始状态
    expect(countSpan).toBeInTheDocument();

    // 4. 触发事件
    await fireEvent.click(button);

    // 5. 断言结果
    // 注意：在 VTL 中，我们不关心组件的内部状态 (count.value)
    // 我们只关心 DOM 是否如预期更新
    expect(screen.getByText(/count: 1/i)).toBeInTheDocument();
  });
});
```

通过结合 Vitest 的快速执行和 Vue Testing Library 的用户中心测试哲学，你可以为你的 Vue 应用构建一个高效、可靠的测试套件。 