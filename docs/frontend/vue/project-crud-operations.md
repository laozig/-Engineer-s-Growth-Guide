# 项目实战：核心功能 - 任务列表的增删改查

在上一章中，我们搭建了项目的基础结构。现在，让我们开始实现待办事项应用的核心功能：任务的增加、删除、修改和查询。

## 1. 创建任务输入组件

首先，我们需要创建一个组件用于添加新任务。在`src/components`目录下创建`TodoInput.vue`：

```vue
<template>
  <div class="todo-input">
    <input 
      type="text" 
      placeholder="添加新任务..." 
      v-model="newTodo"
      @keyup.enter="addTodo"
      autofocus
    />
    <button @click="addTodo" class="add-btn">添加</button>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useTodosStore } from '../store/todos'

const todosStore = useTodosStore()
const newTodo = ref('')

function addTodo() {
  todosStore.addTodo(newTodo.value)
  newTodo.value = '' // 清空输入框
}
</script>

<style scoped>
.todo-input {
  display: flex;
  padding: 10px;
  border-bottom: 1px solid #eee;
}

input {
  flex: 1;
  padding: 10px;
  border: 1px solid #ddd;
  border-radius: 4px 0 0 4px;
  font-size: 16px;
}

.add-btn {
  padding: 10px 15px;
  background-color: #4CAF50;
  color: white;
  border: none;
  border-radius: 0 4px 4px 0;
  cursor: pointer;
  font-size: 16px;
  transition: background-color 0.3s;
}

.add-btn:hover {
  background-color: #45a049;
}
</style>
```

## 2. 创建单个任务项组件

接下来，创建一个组件来表示单个任务项。在`src/components`目录下创建`TodoItem.vue`：

```vue
<template>
  <div class="todo-item" :class="{ completed: todo.completed, editing: isEditing }">
    <div class="view" v-if="!isEditing">
      <input 
        type="checkbox" 
        class="toggle" 
        :checked="todo.completed"
        @change="toggleCompleted"
      />
      <label @dblclick="startEditing">{{ todo.title }}</label>
      <button class="delete-btn" @click="removeTodo">×</button>
    </div>
    <div v-else class="edit">
      <input 
        type="text" 
        class="edit-input"
        v-model="editedTitle"
        @blur="doneEditing"
        @keyup.enter="doneEditing"
        @keyup.escape="cancelEditing"
        ref="editField"
      />
    </div>
  </div>
</template>

<script setup>
import { ref, nextTick } from 'vue'
import { useTodosStore } from '../store/todos'

const props = defineProps({
  todo: {
    type: Object,
    required: true
  }
})

const todosStore = useTodosStore()
const isEditing = ref(false)
const editedTitle = ref('')
const editField = ref(null)

function toggleCompleted() {
  todosStore.toggleTodo(props.todo.id)
}

function removeTodo() {
  todosStore.removeTodo(props.todo.id)
}

function startEditing() {
  isEditing.value = true
  editedTitle.value = props.todo.title
  nextTick(() => {
    editField.value.focus()
  })
}

function doneEditing() {
  if (isEditing.value) {
    isEditing.value = false
    const title = editedTitle.value.trim()
    if (title) {
      todosStore.updateTodoTitle(props.todo.id, title)
    } else {
      removeTodo()
    }
  }
}

function cancelEditing() {
  isEditing.value = false
  editedTitle.value = props.todo.title
}
</script>

<style scoped>
.todo-item {
  display: flex;
  padding: 10px;
  border-bottom: 1px solid #eee;
  position: relative;
}

.view {
  display: flex;
  align-items: center;
  width: 100%;
}

.toggle {
  margin-right: 10px;
  height: 20px;
  width: 20px;
}

label {
  flex: 1;
  padding: 5px 0;
  word-break: break-all;
  transition: color 0.4s;
}

.completed label {
  color: #d9d9d9;
  text-decoration: line-through;
}

.delete-btn {
  color: #cc9a9a;
  font-size: 22px;
  border: none;
  background: none;
  cursor: pointer;
  padding: 0 5px;
  opacity: 0;
  transition: opacity 0.3s;
}

.todo-item:hover .delete-btn {
  opacity: 1;
}

.edit {
  width: 100%;
}

.edit-input {
  width: 100%;
  padding: 5px;
  font-size: 16px;
  border: 1px solid #999;
  border-radius: 4px;
}
</style>
```

## 3. 创建任务列表组件

现在，创建一个组件来展示所有任务。在`src/components`目录下创建`TodoList.vue`：

```vue
<template>
  <div class="todo-list">
    <p v-if="filteredTodos.length === 0" class="empty-list">
      {{ emptyMessage }}
    </p>
    <TodoItem 
      v-for="todo in filteredTodos" 
      :key="todo.id" 
      :todo="todo" 
    />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import TodoItem from './TodoItem.vue'
import { useTodosStore } from '../store/todos'

const props = defineProps({
  filter: {
    type: String,
    default: 'all'
  }
})

const todosStore = useTodosStore()

const filteredTodos = computed(() => {
  switch (props.filter) {
    case 'active':
      return todosStore.activeTodos
    case 'completed':
      return todosStore.completedTodos
    default:
      return todosStore.todos
  }
})

const emptyMessage = computed(() => {
  switch (props.filter) {
    case 'active':
      return '没有待完成的任务'
    case 'completed':
      return '没有已完成的任务'
    default:
      return '暂无任务，请添加新任务'
  }
})
</script>

<style scoped>
.todo-list {
  min-height: 100px;
}

.empty-list {
  text-align: center;
  color: #aaa;
  padding: 20px;
}
</style>
```

## 4. 创建任务统计和过滤组件

接下来，创建一个组件来显示任务统计信息和过滤选项。在`src/components`目录下创建`TodoFooter.vue`：

```vue
<template>
  <div v-if="todosStore.totalCount > 0" class="todo-footer">
    <span class="todo-count">
      <strong>{{ todosStore.activeCount }}</strong> 项待办
    </span>
    <ul class="filters">
      <li>
        <router-link to="/">全部</router-link>
      </li>
      <li>
        <router-link to="/active">进行中</router-link>
      </li>
      <li>
        <router-link to="/completed">已完成</router-link>
      </li>
    </ul>
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

const todosStore = useTodosStore()
</script>

<style scoped>
.todo-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px;
  border-top: 1px solid #e6e6e6;
  color: #777;
  font-size: 14px;
}

.todo-count {
  flex: 1;
}

.filters {
  display: flex;
  list-style: none;
  margin: 0;
  padding: 0;
}

.filters li {
  margin: 0 5px;
}

.filters a {
  color: inherit;
  text-decoration: none;
  padding: 3px 7px;
  border-radius: 3px;
}

.filters a.active {
  border: 1px solid rgba(175, 47, 47, 0.2);
}

.clear-completed {
  background: none;
  border: none;
  color: #777;
  cursor: pointer;
}

.clear-completed:hover {
  text-decoration: underline;
}
</style>
```

## 5. 更新主视图组件

现在，更新`src/views/HomeView.vue`文件，集成我们刚刚创建的组件：

```vue
<template>
  <div class="todo-app">
    <h1>待办事项</h1>
    <div class="container">
      <TodoInput />
      <TodoList :filter="currentFilter" />
      <TodoFooter />
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import TodoInput from '../components/TodoInput.vue'
import TodoList from '../components/TodoList.vue'
import TodoFooter from '../components/TodoFooter.vue'

// 接收路由传递的props
const props = defineProps({
  filter: {
    type: String,
    default: 'all'
  }
})

const route = useRoute()

// 根据当前路由过滤任务
const currentFilter = computed(() => props.filter || route.name || 'all')
</script>

<style>
/* 基础样式保持不变 */
body {
  font-family: 'Arial', sans-serif;
  background-color: #f5f5f5;
  margin: 0;
  padding: 0;
}

.todo-app {
  max-width: 550px;
  margin: 0 auto;
  padding: 20px;
}

h1 {
  text-align: center;
  color: #333;
}

.container {
  background-color: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  overflow: hidden;
}
</style>
```

## 6. 测试功能

现在我们已经实现了待办事项应用的核心功能。启动项目，测试以下功能：

- 添加新任务
- 标记任务为已完成/未完成
- 编辑任务（双击任务文本）
- 删除任务
- 查看任务统计信息
- 清除已完成任务

```bash
npm run dev
```

访问 http://localhost:5173/ 并测试所有功能。

## 功能总结

我们已经成功实现了待办事项应用的核心CRUD功能：

- **创建（Create）**：通过`TodoInput`组件添加新任务
- **读取（Read）**：通过`TodoList`和`TodoItem`组件显示任务
- **更新（Update）**：通过双击任务文本编辑任务，或通过复选框切换任务状态
- **删除（Delete）**：通过点击任务项上的删除按钮删除任务

此外，我们还实现了：
- 任务计数统计
- 清除已完成任务的功能

## 下一步

在下一章中，我们将更深入地探讨 **[状态管理：使用 Pinia 管理应用状态](project-state-management.md)**，并了解如何更高效地组织和管理应用状态。
