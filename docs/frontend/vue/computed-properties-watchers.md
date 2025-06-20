# 5. 计算属性与侦听器

在 Vue 中，我们有两种主要的方式来响应数据的变化：计算属性 (Computed Properties) 和侦听器 (Watchers)。它们都允许我们处理依赖数据的变更，但使用场景有所不同。

## 计算属性 (Computed Properties)

模板内的表达式非常便利，但如果包含了过于复杂的逻辑，模板就会变得臃肿且难以维护。对于任何包含响应式数据的复杂逻辑，你都应该使用**计算属性**。

计算属性是基于它们的响应式依赖进行缓存的。一个计算属性只会在其相关依赖变更时才会重新求值。

### 基础示例

```vue
<script setup>
import { reactive, computed } from 'vue'

const author = reactive({
  name: 'John Doe',
  books: [
    'Vue 2 - Advanced Guide',
    'Vue 3 - Basic Guide',
    'Vue 4 - The Mystery'
  ]
})

// 一个计算属性的 ref
const publishedBooksMessage = computed(() => {
  return author.books.length > 0 ? 'Yes' : 'No'
})
</script>

<template>
  <p>Has published books:</p>
  <span>{{ publishedBooksMessage }}</span>
</template>
```

`publishedBooksMessage` 会依赖 `author.books`。只要 `author.books` 不改变，多次访问 `publishedBooksMessage` 都会立即返回先前的计算结果，而不会重复执行 getter 函数。

### 计算属性 vs. 方法

你可能已经注意到我们可以通过在表达式中调用一个方法来达到同样的效果。

```vue
<!-- 调用方法 -->
<p>{{ calculateBooksMessage() }}</p>

// 组件内
public calculateBooksMessage() {
  return author.books.length > 0 ? 'Yes' : 'No'
}
```

从结果上来说，两种方式确实是完全相同的。然而，不同之处在于**计算属性是基于其响应式依赖进行缓存的**。相比之下，每当触发重新渲染时，方法调用**总会**再次执行函数。

**我们为什么需要缓存？** 想象一下我们有一个性能开销比较大的计算属性 A，它需要遍历一个巨大的数组并做大量的计算。然后我们可能还有其他的计算属性依赖于 A。如果没有缓存，我们将不可避免地重复执行 A 的 getter！

## 侦听器 (Watchers)

虽然计算属性在大多数情况下更合适，但有时我们也需要一个"侦听器"来响应数据的变化。当你需要在数据变化时执行**异步**或**开销较大**的操作时，侦听器是最有用的。

`watch` 函数可以侦听一个或多个响应式数据源，并在数据源变化时调用一个回调函数。

### 基础示例

```vue
<script setup>
import { ref, watch } from 'vue'

const question = ref('')
const answer = ref('Questions usually contain a question mark. ;-)')

// 可以直接侦听一个 ref
watch(question, async (newQuestion, oldQuestion) => {
  if (newQuestion.indexOf('?') > -1) {
    answer.value = 'Thinking...'
    try {
      const res = await fetch('https://yesno.wtf/api')
      answer.value = (await res.json()).answer
    } catch (error) {
      answer.value = 'Error! Could not reach the API. ' + error
    }
  }
})
</script>

<template>
  <p>
    Ask a yes/no question:
    <input v-model="question" />
  </p>
  <p>{{ answer }}</p>
</template>
```

### 侦听来源类型

`watch` 的第一个参数可以是不同形式的"来源"：它可以是一个 ref (包括计算属性)、一个响应式对象、一个 getter 函数、或由以上类型的值组成的数组。

### 深层侦听器

直接给 `watch`() 传入一个响应式对象，会隐式地创建一个深层侦听器——该回调函数在所有嵌套的 property 变更时都会被触发。

```js
const obj = reactive({ count: 0 })

watch(obj, (newValue, oldValue) => {
  // 在 obj.count 改变时触发
})
```

## 计算属性 vs. 侦听器

-   **计算属性 (Computed)**:
    -   **同步的**。
    -   用于派生新的数据，强调的是"计算"出一个值。
    -   有缓存，只有在依赖变化时才重新计算。
    -   适用于模板中需要复杂逻辑的场景。

-   **侦听器 (Watch)**:
    -   可以**异步**执行。
    -   用于观察某个数据的变化并执行"副作用"(side effects)，如发起网络请求、操作 DOM (尽管不推荐) 等。
    -   不产生新的值，而是触发一个过程。

通常来说，当需要根据现有数据声明式地创建新数据时，优先使用计算属性。当需要在数据变化时执行特定的、有副作用的逻辑时，使用侦听器。 