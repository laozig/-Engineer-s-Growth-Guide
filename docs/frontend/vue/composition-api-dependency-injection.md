# 11. Composition API: 依赖注入

依赖注入是 Vue 提供的一种组件通信机制，它允许祖先组件向其所有子孙组件传递数据，而不需要通过 props 层层传递，这对于深层嵌套的组件树特别有用。

在 Composition API 中，依赖注入是通过 `provide` 和 `inject` 函数实现的。

## 基本使用

### Provide（提供）

祖先组件可以使用 `provide` 函数来提供数据：

```vue
<script setup>
import { provide } from 'vue'

// 提供静态值
provide('message', 'Hello from ancestor!')

// 提供响应式的值
const count = ref(0)
provide('count', count)

// 提供可更新的值
provide('increment', () => {
  count.value++
})
</script>
```

### Inject（注入）

后代组件可以使用 `inject` 函数来注入祖先组件提供的数据：

```vue
<script setup>
import { inject } from 'vue'

// 注入值
const message = inject('message')

// 注入响应式的值
const count = inject('count')

// 注入方法
const increment = inject('increment')
</script>

<template>
  <div>
    <p>Message: {{ message }}</p>
    <p>Count: {{ count }}</p>
    <button @click="increment">Increment</button>
  </div>
</template>
```

### 默认值

如果祖先组件没有提供某个值，你可以为 `inject` 指定一个默认值：

```js
// 注入值，如果不存在，则使用默认值
const message = inject('message', 'Default message')

// 使用工厂函数创建默认值
const count = inject('count', () => 0)
```

## 处理响应式

当提供响应式的数据时，后代组件可以直接使用并保持响应性：

```vue
<!-- 祖先组件 -->
<script setup>
import { ref, provide } from 'vue'

const count = ref(0)
provide('count', count) // 直接提供 ref
</script>

<!-- 后代组件 -->
<script setup>
import { inject } from 'vue'

const count = inject('count') // 注入的是 ref，保持响应性
</script>

<template>
  <div>Count: {{ count }}</div>
</template>
```

当祖先组件中的 `count` 变更时，所有注入了 `count` 的后代组件都会自动更新。

## 应用场景：主题切换

依赖注入是实现全局状态或功能的理想方式，例如主题切换功能：

```vue
<!-- App.vue (祖先组件) -->
<script setup>
import { ref, provide, computed } from 'vue'

const theme = ref('light')

const themeClasses = computed(() => {
  return {
    'theme-light': theme.value === 'light',
    'theme-dark': theme.value === 'dark'
  }
})

const toggleTheme = () => {
  theme.value = theme.value === 'light' ? 'dark' : 'light'
}

provide('theme', {
  current: theme,
  classes: themeClasses,
  toggle: toggleTheme
})
</script>

<template>
  <div :class="themeClasses">
    <slot></slot>
  </div>
</template>
```

```vue
<!-- ThemeSwitcher.vue (后代组件) -->
<script setup>
import { inject } from 'vue'

const theme = inject('theme')
</script>

<template>
  <button @click="theme.toggle">
    Switch to {{ theme.current === 'light' ? 'dark' : 'light' }} theme
  </button>
</template>
```

## 使用 Symbol 作为 key

为了避免名称冲突，特别是在大型应用或插件中，我们可以使用 Symbol 作为 provide/inject 的 key：

```js
// theme.js
export const themeSymbol = Symbol('theme')
```

```vue
<!-- 祖先组件 -->
<script setup>
import { provide, ref } from 'vue'
import { themeSymbol } from './theme'

const theme = ref('light')
provide(themeSymbol, theme)
</script>

<!-- 后代组件 -->
<script setup>
import { inject } from 'vue'
import { themeSymbol } from './theme'

const theme = inject(themeSymbol)
</script>
```

## 与 Options API 的对比

在 Options API 中，依赖注入是通过 `provide` 和 `inject` 选项实现的：

```js
// 祖先组件
export default {
  data() {
    return {
      message: 'Hello from ancestor!'
    }
  },
  provide() {
    // 使用函数形式，可以访问组件实例
    return {
      message: this.message
    }
  }
}

// 后代组件
export default {
  inject: ['message']
}
```

Composition API 的 `provide` 和 `inject` 函数提供了更灵活的使用方式，特别是与响应式系统的集成。

## 注意事项

1. **避免滥用**：依赖注入使组件之间的关系不那么明显，可能使代码难以理解。只在需要跨多层级传递数据时使用它。

2. **数据流向**：尽管可以在子组件中修改注入的值，但最好遵循单向数据流，即只在提供数据的组件中修改数据。

3. **响应式**：确保在需要响应式的场景中正确地处理响应式数据。 