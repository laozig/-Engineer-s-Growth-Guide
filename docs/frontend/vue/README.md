# Vue.js 应用开发指南

本指南旨在为开发者提供一个从入门到精通的Vue.js学习路径，全面覆盖Vue.js的核心概念、现代化的Composition API、庞大的生态系统以及企业级的最佳实践。

## 学习路径

### 第一部分：Vue.js 基础与核心概念

1.  [√] [Vue.js 简介与环境搭建](introduction-setup.md)
2.  [√] [模板语法与指令](template-syntax.md)
3.  [√] [组件基础与 Props](components-props.md)
4.  [√] [事件处理与v-model](event-handling-v-model.md)
5.  [√] [计算属性与侦听器](computed-properties-watchers.md)
6.  [√] [条件渲染与列表渲染](conditional-rendering-lists.md)
7.  [√] [Class 与 Style 绑定](class-style-binding.md)

### 第二部分：深入 Vue.js 组件

8.  [√] [组件深入：插槽、动态组件、异步组件](components-deep-dive.md)
9.  [√] [Composition API: `setup` 与响应式基础](composition-api-setup.md)
10. [√] [Composition API: 生命周期钩子](composition-api-lifecycle-hooks.md)
11. [√] [Composition API: 依赖注入](composition-api-dependency-injection.md)
12. [√] [自定义指令](custom-directives.md)

### 第三部分：Vue.js 生态系统与工具

13. [√] [路由管理: Vue Router](vue-router.md)
14. [√] [状态管理: Pinia](state-management-pinia.md)
15. [√] [状态管理: Vuex (传统方案)](state-management-vuex.md)
16. [√] [UI 组件库: Element Plus & Ant Design Vue](ui-component-libraries.md)
17. [√] [构建工具: Vite](build-tool-vite.md)
18. [√] [测试: Vitest & Vue Testing Library](testing-vue-apps.md)

### 第四部分：高级主题与最佳实践

19. [√] [性能优化](performance-optimization.md)
20. [√] [TypeScript 集成](typescript-integration.md)
21. [√] [服务端渲染 (SSR) 与 Nuxt.js](ssr-with-nuxtjs.md)
22. [√] [高级状态管理模式](advanced-state-management.md)

### 第五部分：Vue.js 项目实战

23. [√] [项目规划与技术选型](project-planning-stack.md)
24. [√] [构建项目骨架与基础配置](project-scaffolding.md)
25. [√] [核心功能：任务列表的增删改查](project-crud-operations.md)
26. [√] [状态管理：使用 Pinia 管理应用状态](project-state-management.md)
27. [√] [路由实现：任务过滤与视图切换](project-routing.md)
28. [√] [组件重构与代码优化](project-refactoring.md)
29. [√] [最终部署](project-deployment.md)

## Vue.js 学习路径图

```mermaid
graph TD
    A[开始 Vue.js 学习之旅] --> B[基础与核心概念]
    B --> B1[Vue.js 简介与环境搭建]
    B --> B2[模板语法与指令]
    B --> B3[组件基础与 Props]
    B --> B4[事件处理与v-model]
    B --> B5[计算属性与侦听器]
    B --> B6[条件渲染与列表渲染]
    B --> B7[Class 与 Style 绑定]
    
    A --> C[深入 Vue.js 组件]
    C --> C1[组件深入：插槽、动态组件、异步组件]
    C --> C2[Composition API: setup 与响应式基础]
    C --> C3[Composition API: 生命周期钩子]
    C --> C4[Composition API: 依赖注入]
    C --> C5[自定义指令]
    
    A --> D[Vue.js 生态系统与工具]
    D --> D1[路由管理: Vue Router]
    D --> D2[状态管理: Pinia]
    D --> D3[状态管理: Vuex]
    D --> D4[UI 组件库]
    D --> D5[构建工具: Vite]
    D --> D6[测试: Vitest & Vue Testing Library]
    
    A --> E[高级主题与最佳实践]
    E --> E1[性能优化]
    E --> E2[TypeScript 集成]
    E --> E3[服务端渲染 (SSR) 与 Nuxt.js]
    E --> E4[高级状态管理模式]

    A --> F[Vue.js 项目实战]
    F --> F1[项目规划与技术选型]
    F --> F2[构建项目骨架与基础配置]
    F --> F3[核心功能：任务列表的增删改查]
    F --> F4[状态管理：使用 Pinia 管理应用状态]
    F --> F5[路由实现：任务过滤与视图切换]
    F --> F6[组件重构与代码优化]
    F --> F7[最终部署]
    
    style B1 fill:#d4f4dd
    style B2 fill:#d4f4dd
    style B3 fill:#d4f4dd
    style B4 fill:#d4f4dd
    style B5 fill:#d4f4dd
    style B6 fill:#d4f4dd
    style B7 fill:#d4f4dd
    
    style C1 fill:#d4f4dd
    style C2 fill:#d4f4dd
    style C3 fill:#d4f4dd
    style C4 fill:#d4f4dd
    style C5 fill:#d4f4dd
    
    style D1 fill:#d4f4dd
    style D2 fill:#d4f4dd
    style D3 fill:#d4f4dd
    style D4 fill:#d4f4dd
    style D5 fill:#d4f4dd
    style D6 fill:#d4f4dd
    
    style E1 fill:#d4f4dd
    style E2 fill:#d4f4dd
    style E3 fill:#d4f4dd
    style E4 fill:#d4f4dd
    
    style F1 fill:#d4f4dd
    style F2 fill:#d4f4dd
    style F3 fill:#d4f4dd
    style F4 fill:#d4f4dd
    style F5 fill:#d4f4dd
    style F6 fill:#d4f4dd
    style F7 fill:#d4f4dd
```

## 如何贡献

欢迎您通过提交Pull Request来改进本指南。详情请参阅 [CONTRIBUTING.md](../../../CONTRIBUTING.md)。 