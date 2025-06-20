# 10. Composition API: 生命周期钩子

生命周期钩子是 Vue 组件中特定阶段会被自动调用的函数。通过这些钩子，你可以在组件的不同生命周期阶段执行自定义的逻辑，例如设置数据、调用 API、清理资源等。

在 Composition API 中，生命周期钩子需要按需引入，它们以 `on` 开头的函数形式存在，提供了比 Options API 更加灵活的组织方式。

## 生命周期钩子的映射关系

以下是 Options API 和 Composition API 生命周期钩子的对应关系：

| Options API      | Composition API    | 调用时机                        |
|------------------|-------------------|-------------------------------|
| `beforeCreate`   | `setup()`        | 组件实例被创建之前                |
| `created`        | `setup()`        | 组件实例已创建                    |
| `beforeMount`    | `onBeforeMount`  | 组件挂载之前                     |
| `mounted`        | `onMounted`      | 组件挂载完成                     |
| `beforeUpdate`   | `onBeforeUpdate` | 组件更新之前                     |
| `updated`        | `onUpdated`      | 组件更新完成                     |
| `beforeUnmount`  | `onBeforeUnmount`| 组件卸载之前                     |
| `unmounted`      | `onUnmounted`    | 组件卸载完成                     |
| `errorCaptured`  | `onErrorCaptured`| 捕获了后代组件传递的错误时          |
| `activated`      | `onActivated`    | 被 keep-alive 缓存的组件激活时     |
| `deactivated`    | `onDeactivated`  | 被 keep-alive 缓存的组件停用时     |

注意：
- 在 Composition API 中，`beforeCreate` 和 `created` 生命周期钩子不再需要，因为 `setup()` 函数会在这两个钩子之间执行。
- 当使用 `<script setup>` 时，`setup()` 函数会自动执行，所以你直接在 `<script setup>` 中写代码就相当于在 `setup()` 函数中写代码。

## 基本用法

```vue
<script setup>
import { ref, onMounted, onBeforeMount, onBeforeUpdate, onUpdated, onBeforeUnmount, onUnmounted } from 'vue'

const count = ref(0)

// 在组件挂载之前
onBeforeMount(() => {
  console.log('Component is about to be mounted.')
})

// 在组件挂载之后
onMounted(() => {
  console.log('Component is mounted.')
  // 这是进行API调用、DOM操作、设置定时器等操作的好时机
  setTimeout(() => {
    count.value = 1
  }, 1000)
})

// 在组件更新之前
onBeforeUpdate(() => {
  console.log('Component is about to update.')
})

// 在组件更新之后
onUpdated(() => {
  console.log('Component is updated.')
})

// 在组件卸载之前
onBeforeUnmount(() => {
  console.log('Component is about to be unmounted.')
  // 这是清理资源的好时机，例如清除定时器
})

// 在组件卸载之后
onUnmounted(() => {
  console.log('Component is unmounted.')
})
</script>

<template>
  <div>Count: {{ count }}</div>
</template>
```

## 调用多次同一个生命周期钩子

与 Options API 不同，在 Composition API 中，你可以多次调用同一个生命周期钩子。这些钩子会按照它们被注册的顺序依次执行。

```vue
<script setup>
import { onMounted } from 'vue'

onMounted(() => {
  console.log('First onMounted')
})

onMounted(() => {
  console.log('Second onMounted')
})

// 输出:
// "First onMounted"
// "Second onMounted"
</script>
```

这个特性使得我们可以更好地组织和分离关注点，将相关的逻辑放在一起。

## 生命周期钩子与可复用的组合式函数

生命周期钩子在抽离逻辑到可复用的组合式函数 (Composables) 中特别有用。例如，一个简单的鼠标跟踪器：

```js
// useMousePosition.js
import { ref, onMounted, onUnmounted } from 'vue'

export function useMousePosition() {
  const x = ref(0)
  const y = ref(0)

  function update(event) {
    x.value = event.pageX
    y.value = event.pageY
  }

  onMounted(() => {
    window.addEventListener('mousemove', update)
  })

  onUnmounted(() => {
    window.removeEventListener('mousemove', update)
  })

  return { x, y }
}
```

这个组合式函数可以在多个组件中重用：

```vue
<script setup>
import { useMousePosition } from './useMousePosition'

const { x, y } = useMousePosition()
</script>

<template>
  Mouse position: {{ x }}, {{ y }}
</template>
```

通过生命周期钩子，我们能够确保在组件挂载时添加事件监听器，并在组件卸载时移除，从而防止内存泄漏，这是一种非常常见且强大的模式。 