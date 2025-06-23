# 项目实战：组件重构与代码优化

在前面的章节中，我们已经构建了一个功能完整的待办事项应用。随着应用的发展，重构和优化代码变得越来越重要。本章将介绍一些重构技巧和性能优化策略，帮助我们提高代码质量和应用性能。

## 1. 代码重构的目标

重构的主要目标包括：

- 提高代码可读性和可维护性
- 消除重复代码
- 优化组件结构
- 提高应用性能
- 增强代码的可测试性

## 2. 提取可复用的组合式函数

Vue 3的Composition API允许我们轻松提取和复用逻辑。让我们创建一个`useTodo.js`组合式函数，封装单个任务项的逻辑：

```js
// src/composables/useTodo.js
import { ref, nextTick } from 'vue'
import { useTodosStore } from '../store/todos'

export function useTodo(todo) {
  const todosStore = useTodosStore()
  const isEditing = ref(false)
  const editedTitle = ref('')
  const editField = ref(null)

  function toggleCompleted() {
    todosStore.toggleTodo(todo.id)
  }

  function removeTodo() {
    todosStore.removeTodo(todo.id)
  }

  function startEditing() {
    isEditing.value = true
    editedTitle.value = todo.title
    nextTick(() => {
      editField.value.focus()
    })
  }

  function doneEditing() {
    if (isEditing.value) {
      isEditing.value = false
      const title = editedTitle.value.trim()
      if (title) {
        todosStore.updateTodoTitle(todo.id, title)
      } else {
        removeTodo()
      }
    }
  }

  function cancelEditing() {
    isEditing.value = false
    editedTitle.value = todo.title
  }

  return {
    isEditing,
    editedTitle,
    editField,
    toggleCompleted,
    removeTodo,
    startEditing,
    doneEditing,
    cancelEditing
  }
}
```

然后在`TodoItem.vue`中使用这个组合式函数：

```vue
<script setup>
import { useTodo } from '../composables/useTodo'

const props = defineProps({
  todo: {
    type: Object,
    required: true
  }
})

const {
  isEditing,
  editedTitle,
  editField,
  toggleCompleted,
  removeTodo,
  startEditing,
  doneEditing,
  cancelEditing
} = useTodo(props.todo)
</script>
```

## 3. 使用 defineEmits 和 defineProps 提高组件通信的清晰度

在Vue 3中，我们应该使用`defineEmits`和`defineProps`来明确组件的输入和输出：

```vue
<script setup>
const props = defineProps({
  todo: {
    type: Object,
    required: true
  }
})

const emit = defineEmits(['delete', 'toggle', 'edit'])

function handleDelete() {
  emit('delete', props.todo.id)
}

function handleToggle() {
  emit('toggle', props.todo.id)
}

function handleEdit(title) {
  emit('edit', { id: props.todo.id, title })
}
</script>
```

## 4. 使用 v-once 优化静态内容

对于不会改变的内容，我们可以使用`v-once`指令来避免重新渲染：

```vue
<template>
  <header v-once>
    <h1>待办事项</h1>
  </header>
  <!-- 动态内容 -->
</template>
```

## 5. 使用 computed 缓存计算结果

对于需要复杂计算的值，应该使用`computed`属性而不是方法，以便缓存结果：

```js
// 不好的做法
function getCompletedTodos() {
  return todos.value.filter(todo => todo.completed)
}

// 好的做法
const completedTodos = computed(() => {
  return todos.value.filter(todo => todo.completed)
})
```

## 6. 使用 v-memo 优化列表渲染

对于大型列表，我们可以使用`v-memo`来跳过不必要的重新渲染：

```vue
<template>
  <ul class="todo-list">
    <TodoItem
      v-for="todo in todos"
      :key="todo.id"
      :todo="todo"
      v-memo="[todo.completed, todo.title]"
    />
  </ul>
</template>
```

## 7. 拆分大型组件

如果一个组件变得过于复杂，我们应该考虑将其拆分为更小的组件。例如，我们可以将`TodoFooter.vue`拆分为`TodoCount.vue`和`TodoFilters.vue`：

```vue
<!-- TodoCount.vue -->
<template>
  <span class="todo-count">
    <strong>{{ activeCount }}</strong> 项待办
  </span>
</template>

<script setup>
defineProps({
  activeCount: {
    type: Number,
    required: true
  }
})
</script>
```

```vue
<!-- TodoFilters.vue -->
<template>
  <ul class="filters">
    <li>
      <router-link to="/" exact>全部</router-link>
    </li>
    <li>
      <router-link to="/active">进行中</router-link>
    </li>
    <li>
      <router-link to="/completed">已完成</router-link>
    </li>
  </ul>
</template>
```

然后在`TodoFooter.vue`中使用这些组件：

```vue
<template>
  <div v-if="todosStore.totalCount > 0" class="todo-footer">
    <TodoCount :activeCount="todosStore.activeCount" />
    <TodoFilters />
    <button 
      v-if="todosStore.completedCount > 0" 
      class="clear-completed"
      @click="todosStore.clearCompleted"
    >
      清除已完成
    </button>
  </div>
</template>

<script setup>
import { useTodosStore } from '../store/todos'
import TodoCount from './TodoCount.vue'
import TodoFilters from './TodoFilters.vue'

const todosStore = useTodosStore()
</script>
```

## 8. 使用 shallowRef 优化大型对象

对于包含大量数据但不需要深层响应性的对象，可以使用`shallowRef`来提高性能：

```js
import { shallowRef } from 'vue'

// 如果不需要深层响应性，使用shallowRef
const todoStatistics = shallowRef({
  totalCount: 0,
  activeCount: 0,
  completedCount: 0,
  // ...其他统计数据
})
```

## 9. 使用异步组件

对于较大的组件，可以使用异步组件来分割代码，减少初始加载时间：

```js
// src/router/index.js
import { defineAsyncComponent } from 'vue'

const TodoStatistics = defineAsyncComponent(() =>
  import('../components/TodoStatistics.vue')
)
```

## 10. 优化事件处理

为了避免频繁触发事件处理函数，可以使用防抖或节流技术：

```js
// src/composables/useDebounce.js
import { ref } from 'vue'

export function useDebounce(fn, delay = 300) {
  const timeoutId = ref(null)
  
  function debounced(...args) {
    clearTimeout(timeoutId.value)
    timeoutId.value = setTimeout(() => {
      fn(...args)
    }, delay)
  }
  
  return debounced
}
```

使用示例：

```vue
<script setup>
import { ref } from 'vue'
import { useDebounce } from '../composables/useDebounce'
import { useTodosStore } from '../store/todos'

const todosStore = useTodosStore()
const searchTerm = ref('')

const debouncedSearch = useDebounce((term) => {
  console.log('Searching for:', term)
  // 执行搜索逻辑
}, 500)

function handleInput(e) {
  searchTerm.value = e.target.value
  debouncedSearch(searchTerm.value)
}
</script>

<template>
  <input
    type="text"
    :value="searchTerm"
    @input="handleInput"
    placeholder="搜索任务..."
  />
</template>
```

## 11. 使用 Suspense 处理异步数据

Vue 3的`Suspense`组件可以帮助我们处理异步数据加载：

```vue
<template>
  <Suspense>
    <template #default>
      <TodoList />
    </template>
    <template #fallback>
      <div class="loading">加载中...</div>
    </template>
  </Suspense>
</template>
```

在`TodoList.vue`中使用异步`setup`函数：

```vue
<script setup>
import { ref } from 'vue'
import TodoItem from './TodoItem.vue'

// 模拟异步数据获取
const todos = await new Promise(resolve => {
  setTimeout(() => {
    resolve(ref([
      { id: 1, title: '学习Vue 3', completed: false },
      { id: 2, title: '完成项目', completed: false }
    ]))
  }, 1000)
})
</script>
```

## 12. 代码优化检查清单

以下是一个简单的检查清单，可以帮助我们确保代码质量：

1. **组件职责单一**：每个组件只做一件事
2. **逻辑复用**：将重复逻辑提取为组合式函数
3. **性能优化**：使用`computed`、`v-once`、`v-memo`等优化渲染
4. **类型检查**：使用`defineProps`和`defineEmits`明确组件API
5. **错误处理**：添加适当的错误处理逻辑
6. **代码分割**：使用异步组件和路由懒加载
7. **命名规范**：使用一致的命名约定
8. **注释**：为复杂逻辑添加注释
9. **测试覆盖**：编写单元测试和集成测试
10. **无副作用**：确保组件在卸载时清理资源

## 总结

在本章中，我们学习了多种重构和优化Vue 3应用的技术：

1. 提取可复用的组合式函数
2. 使用`defineProps`和`defineEmits`明确组件API
3. 使用`v-once`和`v-memo`优化渲染
4. 拆分大型组件
5. 使用`shallowRef`优化大型对象
6. 使用异步组件和`Suspense`
7. 优化事件处理

通过这些技术，我们的待办事项应用现在更加高效、可维护和可扩展。在下一章中，我们将探讨 **[最终部署](project-deployment.md)** 过程，将应用发布到生产环境。
