# JavaScript 测试之道

在软件开发生命周期中，测试是保障代码质量、功能稳定性和应用可靠性的核心环节。一个经过良好测试的应用，能让开发者在迭代和重构时充满信心。

## 1. 为什么需要测试？

-   **确保正确性**: 验证代码的行为是否符合预期。
-   **防止回归 (Regression)**: 确保新的改动没有破坏现有功能。
-   **提供文档**: 测试用例是描述代码功能的"活文档"。
-   **促进重构**: 有了全面的测试覆盖，你才能安心地改进代码设计。

### 测试金字塔

测试金字塔是一个经典的隐喻，它描述了不同测试类型在数量和执行速度上的理想比例。

-   **单元测试 (Unit Tests)**: 位于金字塔底部，数量最多，运行速度最快。它们测试最小的代码单元（如一个函数或一个 React 组件），且不涉及外部依赖（如网络、数据库）。
-   **集成测试 (Integration Tests)**: 位于中部。它们测试多个单元如何协同工作（如一个 API 路由和其控制器的交互）。
-   **端到端测试 (End-to-End, E2E Tests)**: 位于塔尖，数量最少，运行最慢、成本最高。它们从用户的角度模拟完整的应用流程（如登录、购物、支付）。

![测试金字塔](https://martinfowler.com/bliki/images/testPyramid/test-pyramid.png)
*(图片来源: Martin Fowler)*

---

## 2. 单元与集成测试

对于 Node.js 后端和前端组件逻辑，单元测试和集成测试是我们的主要关注点。

### (1) Jest: 功能全面的测试框架

[Jest](https://jestjs.io/) 是由 Facebook 开发的、最流行的 JavaScript 测试框架之一。它以"零配置"开箱即用的体验、内置的断言库、Mock 功能和覆盖率报告而闻名。

#### 安装与配置

```bash
npm install --save-dev jest
```
在 `package.json` 中添加脚本:
```json
{
  "scripts": {
    "test": "jest",
    "test:watch": "jest --watchAll",
    "test:coverage": "jest --coverage"
  },
  "jest": {
    "testEnvironment": "node" 
  }
}
```
*对于前端项目，`testEnvironment` 通常设置为 `jsdom`。*

#### 基础示例

```javascript
// src/math.js
export const sum = (a, b) => a + b;

// src/math.test.js
import { sum } from './math.js';

describe('math functions', () => {
  it('should return the sum of two numbers', () => {
    // 断言 (Assertion)
    expect(sum(1, 2)).toBe(3);
    expect(sum(-1, 1)).toBe(0);
  });
});
```

#### 异步代码测试

```javascript
// src/user.service.js
export const fetchUser = async (userId) => {
  if (userId <= 0) throw new Error('Invalid user ID');
  return { id: userId, name: 'John Doe' };
};

// src/user.service.test.js
import { fetchUser } from './user.service.js';

describe('userService', () => {
  it('should fetch a user object for a valid ID', async () => {
    const user = await fetchUser(1);
    expect(user).toEqual({ id: 1, name: 'John Doe' });
  });

  it('should throw an error for an invalid ID', async () => {
    // 必须用 expect.assertions 确保异步的 throw 被捕获
    expect.assertions(1);
    try {
      await fetchUser(0);
    } catch (error) {
      expect(error.message).toBe('Invalid user ID');
    }
  });

  // 更简洁的写法
  it('should throw an error for an invalid ID (alternative)', () => {
    return expect(fetchUser(0)).rejects.toThrow('Invalid user ID');
  });
});
```

### (2) Vitest: 下一代测试框架

[Vitest](https://vitest.dev/) 是一个由 Vite 驱动的新一代测试框架。它拥有与 Jest 兼容的 API，但提供了更快的速度和更好的开发体验。

**为什么选择 Vitest?**
-   **极速**: 利用 Vite 的按需转换能力，启动和重载速度极快。
-   **原生 ESM**: 天然支持 ES Modules，无需复杂配置。
-   **与 Vite 集成**: 如果你的项目已经在使用 Vite，Vitest 是无缝集成的最佳选择。

#### Vitest 示例
```javascript
// vitest.config.js (或 vite.config.js)
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Vitest 配置
  },
});

// 测试代码与 Jest 几乎完全相同！
// src/math.test.js
import { describe, it, expect } from 'vitest'; // 从 vitest 导入
import { sum } from './math.js';

describe('math functions', () => {
  it('should return the sum of two numbers', () => {
    expect(sum(1, 2)).toBe(3);
  });
});
```

---

## 3. 端到端 (E2E) 测试

E2E 测试通过真实的浏览器来自动化用户操作流程，以确保整个应用的集成是正确的。

### Playwright: 现代化的 E2E 测试工具

[Playwright](https://playwright.dev/) 是由微软开发的 E2E 测试框架。它支持所有现代浏览器（Chromium, Firefox, WebKit），并以其强大的功能、速度和可靠性而受到赞誉。

#### E2E 测试示例

假设我们想测试一个简单的页面，其中包含一个按钮，点击后会显示一条消息。

**`index.html`**
```html
<!DOCTYPE html>
<html>
<body>
  <button id="my-button">Click Me</button>
  <p id="message" style="display:none;">Hello World</p>
  <script>
    document.getElementById('my-button').addEventListener('click', () => {
      document.getElementById('message').style.display = 'block';
    });
  </script>
</body>
</html>
```

**`e2e.spec.js`**
```javascript
import { test, expect } from '@playwright/test';

test('should display message on button click', async ({ page }) => {
  // 1. 导航到页面 (Arrange)
  await page.goto('file:///path/to/your/index.html');

  // 2. 点击按钮 (Act)
  await page.click('#my-button');

  // 3. 断言消息可见 (Assert)
  const message = page.locator('#message');
  await expect(message).toBeVisible();
  await expect(message).toHaveText('Hello World');
});
```

**运行测试**
```bash
# 安装 Playwright
npm init playwright@latest

# 运行测试
npx playwright test
```

---

## 4. 测试最佳实践

-   **清晰的描述**: 测试的描述（`describe` 和 `it`）应该清晰地说明它在测试什么。
-   **AAA 模式**: 遵循 **准备 (Arrange)**、**行动 (Act)**、**断言 (Assert)** 的结构来组织你的测试代码。
-   **独立性**: 每个测试都应该是独立的，不依赖于其他测试的执行顺序或状态。使用 `beforeEach` 和 `afterEach` 钩子来清理和设置环境。
-   **只测试一件事**: 每个 `it` 块应该只关注一个具体的行为或输出。
-   **模拟外部依赖**: 在单元测试中，使用 Mock（如 `jest.fn()`）来模拟数据库、网络请求等外部依赖，以保证测试的快速和稳定。
-   **代码覆盖率不是唯一目标**: 覆盖率是衡量测试完整性的有用指标，但 100% 的覆盖率不等于没有 bug。应专注于测试关键和复杂的业务逻辑。