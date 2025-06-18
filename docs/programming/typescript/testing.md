# 自动化测试

编写测试是确保软件质量、预防回归错误和促进重构的关键环节。在 TypeScript 项目中，我们可以利用其类型系统编写出更可靠、更易于维护的测试代码。本章将以流行的测试框架 **Jest** 为例，介绍如何为 TypeScript 项目配置和编写自动化测试。

## 1. 为什么选择 Jest?

- **一体化**：Jest 是一个"全家桶"式的测试框架，内置了测试运行器、断言库和 mock 功能，无需组合多个库。
- **配置简单**：对于大多数项目，Jest 的配置非常少。
- **快照测试**：能够轻松地对大型对象或 UI 组件进行快照测试。
- **优秀的 TypeScript 支持**：通过 `ts-jest` 包可以与 TypeScript 无缝集成。

## 2. 环境配置

首先，在你的项目中安装 Jest 和相关的类型定义及 `ts-jest`：

```bash
npm install --save-dev jest @types/jest ts-jest
```
- `jest`: Jest 核心库。
- `@types/jest`: Jest 的类型定义。
- `ts-jest`: 一个 TypeScript 预处理器，让 Jest 能够理解 `.ts` 文件。

接下来，生成 Jest 的配置文件 (`jest.config.js`)：
```bash
npx ts-jest config:init
```
这会创建一个 `jest.config.js` 文件，内容如下：
```javascript
// jest.config.js
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
};
```

最后，在 `package.json` 中添加一个 `test` 脚本：
```json
{
  "scripts": {
    "test": "jest"
  }
}
```

## 3. 编写第一个测试

让我们来测试一个简单的工具函数。

**创建 `src/utils.ts`:**
```typescript
// src/utils.ts
export function add(a: number, b: number): number {
  return a + b;
}
```

**创建测试文件 `src/utils.test.ts`:**
Jest 会自动发现并运行项目里所有以 `.test.ts` 或 `.spec.ts` 结尾的文件。

```typescript
// src/utils.test.ts
import { add } from './utils';

// 使用 describe 来组织一组相关的测试
describe('add function', () => {
  
  // 使用 it 或 test 来定义一个具体的测试用例
  it('should correctly add two positive numbers', () => {
    // 断言 (Assertion)
    expect(add(1, 2)).toBe(3);
  });

  it('should correctly add a positive and a negative number', () => {
    expect(add(5, -3)).toBe(2);
  });

  it('should correctly add two negative numbers', () => {
    expect(add(-1, -2)).toBe(-3);
  });

  it('should return zero when adding zero to a number', () => {
    expect(add(5, 0)).toBe(5);
  });
});
```

现在，在终端运行 `npm test`，Jest 将会执行这些测试并给出报告。

```
PASS  src/utils.test.ts
 add function
   ✓ should correctly add two positive numbers (2ms)
   ✓ should correctly add a positive and a negative number
   ✓ should correctly add two negative numbers
   ✓ should return zero when adding zero to a number (1ms)

Test Suites: 1 passed, 1 total
Tests:       4 passed, 4 total
Snapshots:   0 total
Time:        1.55s
```

## 4. 模拟 (Mocking)

在测试中，我们常常需要模拟某些模块或函数的行为，以便隔离被测试的单元。Jest 提供了强大的 mock 功能。

假设我们有一个函数，它依赖于一个获取数据的服务：

**`src/data-service.ts`**
```typescript
// src/data-service.ts
export function fetchData(): Promise<string> {
  // 假设这是一个真实的网络请求
  return new Promise(resolve => setTimeout(() => resolve('real data'), 1000));
}
```

**`src/user.ts`**
```typescript
// src/user.ts
import { fetchData } from './data-service';

export async function getUserData(): Promise<string> {
  const data = await fetchData();
  return `User data: ${data}`;
}
```

在测试 `getUserData` 时，我们不希望真的去调用 `fetchData`（因为它可能很慢或不稳定）。我们可以 mock 它：

**`src/user.test.ts`**
```typescript
// src/user.test.ts
import { getUserData } from './user';
import { fetchData } from './data-service';

// 告诉 Jest 我们要 mock 这个模块
jest.mock('./data-service');

// 类型断言，将导入的 fetchData 转为可 mock 的类型
const mockedFetchData = fetchData as jest.Mock;

describe('getUserData', () => {
  it('should return user data with mocked value', async () => {
    // 为 mock 函数设置一个一次性的返回值
    mockedFetchData.mockResolvedValue('mocked data');

    const userData = await getUserData();

    expect(userData).toBe('User data: mocked data');
    expect(mockedFetchData).toHaveBeenCalledTimes(1); // 确保 mock 函数被调用了一次
  });
});
```
通过 `jest.mock('./data-service')`，Jest 会自动用一个 mock 函数替换掉 `data-service` 模块的所有导出。然后我们就可以完全控制 `fetchData` 的行为了。

---

恭喜你！你已经完成了 TypeScript 学习指南的所有核心内容。通过结合静态类型和自动化测试，你现在已经具备了构建高质量、可维护的现代应用程序的强大能力。 