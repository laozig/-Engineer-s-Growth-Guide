# 2. 模板语法与指令

Vue 使用一种基于 HTML 的模板语法，允许开发者声明式地将 DOM 绑定到组件实例的数据。所有 Vue 的模板都是合法的 HTML，所以能被遵循规范的浏览器和 HTML 解析器解析。

在底层，Vue 会将模板编译成高度优化的 JavaScript 代码。结合响应式系统，当应用状态变更时，Vue 能够智能地计算出最小的组件重渲染数量，并应用最少的 DOM 操作。

## 文本插值

数据绑定最常见的形式就是使用"Mustache"语法 (双大括号) 的文本插值：

```vue
<script setup>
import { ref } from 'vue'
const msg = ref('Hello Vue!')
</script>

<template>
  <span>Message: {{ msg }}</span>
</template>
```

双大括号标签会被替换为 `msg` property 的值。无论何时，只要 `msg` property 改变，插值处的内容都会更新。

## 原始 HTML

双大括号会将数据解释为普通文本，而非 HTML 代码。为了输出真正的 HTML，你需要使用 `v-html` 指令：

```vue
<script setup>
import { ref } from 'vue'
const rawHtml = ref('<span style="color: red">This should be red.</span>')
</script>

<template>
  <p>Using text interpolation: {{ rawHtml }}</p>
  <p>Using v-html directive: <span v-html="rawHtml"></span></p>
</template>
```

> **安全警告**: 在网站上动态渲染任意 HTML 是非常危险的，因为它很容易导致 [XSS 攻击](https://en.wikipedia.org/wiki/Cross-site_scripting)。请只对可信内容使用 `v-html`，**绝不要**将其用于用户提交的内容。

## Attribute 绑定

双大括号语法不能作用在 HTML attribute 上。遇到这种情况，请使用 `v-bind` 指令：

```vue
<script setup>
import { ref } from 'vue'
const elementId = ref('my-element')
const isButtonDisabled = ref(true)
</script>

<template>
  <div v-bind:id="elementId">...</div>
  <button v-bind:disabled="isButtonDisabled">Button</button>
</template>
```

`v-bind` 指令指示 Vue 将元素的 `id` attribute 与组件的 `elementId` property 保持一致。

### 缩写

因为 `v-bind` 是一个非常常用的指令，所以它有一个专属的缩写语法 `:`：

```vue
<template>
  <div :id="elementId">...</div>
  <button :disabled="isButtonDisabled">Button</button>
</template>
```

## 使用 JavaScript 表达式

Vue 在所有数据绑定中都支持完整的 JavaScript 表达式：

```vue
<script setup>
import { ref } from 'vue'
const number = ref(10)
const ok = ref(true)
const message = ref('Hello World')
</script>

<template>
  {{ number + 1 }}
  {{ ok ? 'YES' : 'NO' }}
  {{ message.split('').reverse().join('') }}
</template>
```

这些表达式会在当前组件实例的数据作用域下作为 JavaScript 被解析。

## 指令 (Directives)

指令是带有 `v-` 前缀的特殊 attribute。指令 attribute 的值预期是**单个 JavaScript 表达式**。指令的职责是，当表达式的值改变时，将其产生的连带影响，响应式地作用于 DOM。

一些常见的指令：
-   `v-if` / `v-else` / `v-else-if`: 条件性地渲染一块内容。
-   `v-for`: 基于源数据多次渲染元素或模板块。
-   `v-on`: 监听 DOM 事件。缩写为 `@`。
-   `v-model`: 在表单输入和应用状态之间创建双向绑定。

```vue
<script setup>
import { ref } from 'vue'
const seen = ref(true)
const items = ref([{ message: 'Foo' }, { message: 'Bar' }])
function doSomething() {
  alert('Button clicked!')
}
</script>

<template>
  <p v-if="seen">Now you see me</p>
  <ul>
    <li v-for="item in items">
      {{ item.message }}
    </li>
  </ul>
  <button v-on:click="doSomething">Click Me</button>
</template>
``` 