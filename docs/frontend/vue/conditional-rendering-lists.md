# 6. 条件渲染与列表渲染

在 Vue 中，我们可以使用指令来动态地渲染内容，包括根据条件显示/隐藏元素，以及根据数组或对象来渲染列表。

## 条件渲染

### `v-if`, `v-else`, `v-else-if`

`v-if` 指令用于条件性地渲染一块内容。这块内容只会在指令的表达式返回真值时才被渲染。

```vue
<script setup>
import { ref } from 'vue'
const awesome = ref(true)
</script>

<template>
  <button @click="awesome = !awesome">Toggle</button>

  <h1 v-if="awesome">Vue is awesome!</h1>
  <h1 v-else>Oh no 😢</h1>
</template>
```

`v-else` 元素必须紧跟在带 `v-if` 或者 `v-else-if` 的元素的后面，否则它将不会被识别。

`v-else-if` 提供了一个"else if 块"的能力：

```vue
<div v-if="type === 'A'">
  A
</div>
<div v-else-if="type === 'B'">
  B
</div>
<div v-else-if="type === 'C'">
  C
</div>
<div v-else>
  Not A/B/C
</div>
```

### `v-show`

另一个用于按条件显示元素的指令是 `v-show`。用法和 `v-if` 大致一样：

```vue
<h1 v-show="ok">Hello!</h1>
```

不同的是带有 `v-show` 的元素会始终被渲染并保留在 DOM 中。`v-show` 只是简单地切换元素的 CSS `display` property。

### `v-if` vs `v-show`

-   `v-if` 是"真正"的条件渲染，因为它会确保在切换过程中条件块内的事件监听器和子组件适当地被销毁和重建。
-   `v-if` 也是**惰性的**：如果在初始渲染时条件为假，则什么也不做——直到条件第一次变为真时，才会开始渲染条件块。
-   `v-show` 就简单得多——不管初始条件是什么，元素总是会被渲染，并且只是简单地基于 CSS 进行切换。

总的来说，`v-if` 有更高的切换开销，而 `v-show` 有更高的初始渲染开销。因此，如果需要非常频繁地切换，则使用 `v-show` 较好；如果在运行时条件很少改变，则使用 `v-if` 较好。

## 列表渲染

### `v-for`

我们可以用 `v-for` 指令基于一个数组来渲染一个列表。

```vue
<script setup>
import { ref } from 'vue'

const items = ref([{ message: 'Foo' }, { message: 'Bar' }])
</script>

<template>
  <li v-for="(item, index) in items">
    {{ index }} - {{ item.message }}
  </li>
</template>
```

`v-for` 也支持一个可选的第二个参数，即当前项的索引。

### `v-for` 与对象

你也可以使用 `v-for` 来遍历一个对象的 property。

```vue
<li v-for="(value, key, index) in myObject">
  {{ index }}. {{ key }}: {{ value }}
</li>
```

### `key`

为了给 Vue 一个提示，以便它能跟踪每个节点的身份，从而重用和重新排序现有元素，你需要为每项提供一个唯一的 `key` attribute。

```vue
<div v-for="item in items" :key="item.id">
  <!-- 内容 -->
</div>
```

`key` 绑定的值期望是字符串或数字类型。不要使用对象或数组作为 `v-for` 的 key。

**强烈建议**尽可能在使用 `v-for` 时提供 `key` attribute，除非遍历输出的 DOM 内容非常简单，或者是刻意依赖默认行为以获取性能上的提升。 