# 9. Composition API: `setup` 与响应式基础

Composition API 是 Vue 3 引入的一种新的组件选项，用于更好地组织和重用组件逻辑。它与 Vue 2 中的 Options API 并存，提供了更灵活和更强大的组件编写方式。

## 为什么使用 Composition API？

- **更好的逻辑复用**：逻辑可以抽离到可复用的函数中，而不是依赖 mixins 或其他模式。
- **更好的类型推导**：TypeScript 对 Composition API 有更好的支持。
- **更小的生产包体积**：通过 tree-shaking，未使用的 API 可以被完全移除。
- **更灵活的代码组织**：相关的逻辑可以放在一起，而不是分散在不同的选项中。

## `<script setup>`

`<script setup>` 是在单文件组件 (SFC) 中使用 Composition API 的编译时语法糖。它提供了更简洁的语法和更好的性能。

### 基础语法

```vue
<script setup>
// 导入的组件可以直接在模板中使用
import { ref, computed, onMounted } from 'vue'
import ChildComponent from './ChildComponent.vue'

// 变量会直接暴露给模板
const count = ref(0)

// 计算属性
const doubleCount = computed(() => count.value * 2)

// 函数也可以直接在模板中使用
function increment() {
  count.value++
}

// 生命周期钩子
onMounted(() => {
  console.log('Component mounted!')
})
</script>

<template>
  <div>
    <p>Count: {{ count }}</p>
    <p>Double Count: {{ doubleCount }}</p>
    <button @click="increment">Increment</button>
    <ChildComponent />
  </div>
</template>
```

## 响应式核心：`ref` 和 `reactive`

在 Composition API 中，Vue 提供了两个基本函数来创建响应式状态：`ref` 和 `reactive`。

### `ref`

`ref` 函数接收一个参数并返回一个响应式的、可变的 ref 对象。ref 对象只有一个 `.value` property，指向该内部值。

```js
import { ref } from 'vue'

const count = ref(0)
console.log(count.value) // 0

count.value++
console.log(count.value) // 1
```

在 `<template>` 中，ref 会自动"解包"，所以不需要使用 `.value`：

```vue
<template>
  <p>{{ count }}</p> <!-- 不需要 .value -->
</template>
```

### `reactive`

`reactive` 函数接收一个对象（或数组）并返回一个响应式的代理。

```js
import { reactive } from 'vue'

const state = reactive({
  count: 0,
  message: 'Hello'
})

console.log(state.count) // 0
state.count++
console.log(state.count) // 1
```

与 `ref` 不同，`reactive` 是深度响应式的，它会将对象的所有嵌套属性也转换为响应式。

### `ref` vs `reactive`

- `ref` 可以包装任何类型的值（包括基本类型如 `number`、`string`），并使其成为响应式。但需要使用 `.value` 来访问或修改。
- `reactive` 只能用于对象类型（包括数组和集合类型如 `Map` 和 `Set`），不需要使用 `.value`，但不能直接替换整个对象（会丢失响应性）。

一般来说：
- 对于基本类型，使用 `ref`。
- 对于对象类型，可以使用 `reactive` 或 `ref`（取决于是否需要整体替换对象）。

## `toRefs` 和 `toRef`

有时我们想从一个响应式对象中解构属性，但这样做会失去响应性。为了解决这个问题，Vue 提供了 `toRefs` 和 `toRef` 函数。

```js
import { reactive, toRefs, toRef } from 'vue'

const state = reactive({
  count: 0,
  message: 'Hello'
})

// 将整个对象的属性转换为 ref
const { count, message } = toRefs(state)

// 现在 count 和 message 都是 ref，它们将与原始对象保持同步
count.value++ // state.count 也会被更新

// 只转换单个属性为 ref
const countRef = toRef(state, 'count')
```

## 与 Options API 的对比

让我们看看同一个简单计数器组件，用 Options API 和 Composition API 分别实现：

**Options API:**
```vue
<script>
export default {
  data() {
    return {
      count: 0
    }
  },
  computed: {
    doubleCount() {
      return this.count * 2
    }
  },
  methods: {
    increment() {
      this.count++
    }
  },
  mounted() {
    console.log('Component mounted!')
  }
}
</script>
```

**Composition API (使用 `<script setup>`):**
```vue
<script setup>
import { ref, computed, onMounted } from 'vue'

const count = ref(0)
const doubleCount = computed(() => count.value * 2)

function increment() {
  count.value++
}

onMounted(() => {
  console.log('Component mounted!')
})
</script>
```

虽然在这个简单的例子中，Options API 看起来更简洁，但是随着组件复杂度的增加，Composition API 的优势会更加明显，尤其是在逻辑复用和代码组织方面。 