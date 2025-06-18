# 与现代框架集成

TypeScript 已经成为现代 Web 开发的一等公民。几乎所有主流的前端框架都对 TypeScript 提供了优秀的支持，使得开发者可以构建类型安全、可维护的大型应用。本章将介绍如何在 React、Vue 和 Angular 这三大框架中使用 TypeScript。

## 1. React 与 TypeScript

React 与 TypeScript 是一个非常流行的组合。Facebook 和社区共同维护着 `@types/react` 和 `@types/react-dom` 这两个类型定义包，为 React API 提供了全面的类型支持。

### 创建项目

创建新的 React + TypeScript 项目最简单的方式是使用官方推荐的构建工具，如 Vite 或 Create React App。

**使用 Vite (推荐):**
```bash
npm create vite@latest my-react-app -- --template react-ts
```

### 为组件添加类型

使用 `React.FC` (Function Component) 类型可以为函数组件提供类型校验，包括对 `children` 的支持。

```tsx
// components/Greeting.tsx
import React from 'react';

type GreetingProps = {
  name: string;
  messageCount?: number;
};

const Greeting: React.FC<GreetingProps> = ({ name, messageCount = 0 }) => {
  return (
    <div>
      <h2>Hello, {name}!</h2>
      {messageCount > 0 && <p>You have {messageCount} unread messages.</p>}
    </div>
  );
};

export default Greeting;
```

### Hooks 的类型

TypeScript 对 React Hooks 的类型推断非常出色。

**`useState`**: 编译器会根据初始值自动推断 state 的类型。
```tsx
const [count, setCount] = React.useState(0); // count 的类型被推断为 number
const [user, setUser] = React.useState<User | null>(null); // 明确指定 state 可以是 User 或 null
```

**`useEffect`** 和 **`useRef`**:
```tsx
const inputRef = React.useRef<HTMLInputElement>(null); // 为 ref 指定元素类型

React.useEffect(() => {
  // 在这里可以安全地访问 inputRef.current
  inputRef.current?.focus();
}, []);
```

## 2. Vue 与 TypeScript

Vue 3 在设计之初就将 TypeScript 放在了核心位置，提供了世界级的 TypeScript 支持，尤其是在使用组合式 API (Composition API) 和 `<script setup>` 语法时。

### 创建项目

同样，使用 Vite 是创建 Vue + TypeScript 项目的最佳方式。

```bash
npm create vite@latest my-vue-app -- --template vue-ts
```

### `<script setup>` 中的类型

在 `<script setup>` 块中，TypeScript 的能力得到了最大程度的发挥。

**定义 Props**: 使用 `defineProps` 宏，它可以根据传入的泛型参数推断类型。
```vue
<!-- components/UserCard.vue -->
<script setup lang="ts">
interface User {
  id: number;
  name: string;
}

const props = defineProps<{
  user: User;
}>();
</script>

<template>
  <div>
    <h3>{{ props.user.name }}</h3>
    <p>ID: {{ props.user.id }}</p>
  </div>
</template>
```

**定义 Emits**: 使用 `defineEmits`。
```vue
<script setup lang="ts">
const emit = defineEmits<{
  (e: 'change', id: number): void;
  (e: 'update', value: string): void;
}>();

emit('change', 123);
</script>
```

**`ref` 和 `reactive`**: 类型推断同样非常智能。
```vue
import { ref } from 'vue';
const count = ref(0); // count.value 的类型是 number

const user = reactive<User>({ id: 1, name: 'Vue' }); // 明确指定类型
```

## 3. Angular 与 TypeScript

Angular 是一个完全用 TypeScript 编写的框架，因此 TypeScript 是其核心组成部分，无需任何额外配置即可获得完美的集成体验。

### 创建项目

使用 Angular CLI 创建新项目。
```bash
ng new my-angular-app
```
CLI 会自动为你配置好所有 TypeScript 相关的设置。

### 类型化的组件和服务

Angular 的所有核心构建块，如组件、服务、指令等，都以类的形式存在，这与 TypeScript 的面向对象特性完美契合。

**组件 (Component)**:
```typescript
// user-profile.component.ts
import { Component, Input } from '@angular/core';

@Component({
  selector: 'app-user-profile',
  templateUrl: './user-profile.component.html',
})
export class UserProfileComponent {
  @Input() name: string = ''; // Input 属性是类型安全的
  @Input() age: number = 0;
}
```

**服务 (Service) 与依赖注入 (DI)**:
```typescript
// user.service.ts
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface User {
  id: number;
  name: string;
}

@Injectable({
  providedIn: 'root',
})
export class UserService {
  constructor(private http: HttpClient) {} // DI 也是类型安全的

  getUsers(): Observable<User[]> {
    return this.http.get<User[]>('/api/users'); // HttpClient 支持泛型
  }
}
```
Angular 的强类型特性贯穿于整个框架，从模板中的类型检查到 RxJS 的可观察对象，为构建大型、健壮的企业级应用提供了坚实的基础。

---

掌握了如何在前端框架中使用 TypeScript 后，让我们把目光投向服务器端：[后端开发 (Node.js)](nodejs-development.md)。 