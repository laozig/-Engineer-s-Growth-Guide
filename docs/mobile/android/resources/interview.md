# 面试准备

本文档整理了Android开发面试中常见的问题和准备技巧，帮助开发者在面试中展现专业能力和技术深度。

## 核心面试题

### Android基础

#### 四大组件相关

1. **描述Activity的生命周期及各阶段的应用场景**
   - `onCreate()`: 初始化视图、绑定数据
   - `onStart()`: 可见但不可交互
   - `onResume()`: 可见可交互
   - `onPause()`: 部分可见，即将被覆盖
   - `onStop()`: 完全不可见
   - `onDestroy()`: 资源释放

2. **Activity启动模式及使用场景**
   - `standard`: 默认模式，每次创建新实例
   - `singleTop`: 栈顶复用，如通知点击
   - `singleTask`: 栈内复用，如主页
   - `singleInstance`: 独立栈，如来电界面

3. **Service与Thread的区别**
   - Service是组件，有生命周期，Thread是执行体
   - Service可在后台运行，而普通Thread不行
   - Service可被其他组件调用，Thread相对独立

4. **BroadcastReceiver使用场景与注册方式**
   - 静态注册: 在AndroidManifest中声明，应用未启动也能接收
   - 动态注册: 在代码中注册，应用运行期间有效
   - 本地广播: 只在应用内传递，更安全高效

5. **ContentProvider的作用**
   - 提供跨应用数据共享机制
   - 统一的数据访问接口(CRUD)
   - 数据访问权限控制

#### 架构与设计

1. **MVC、MVP和MVVM的区别与适用场景**
   - MVC: Controller和View耦合严重，适合简单应用
   - MVP: 解耦View和Model，便于测试，但Presenter臃肿
   - MVVM: 双向绑定，更好的关注点分离，适合复杂UI

2. **依赖注入原理及框架比较**
   - Dagger2/Hilt: 编译期生成代码，更高效但配置复杂
   - Koin: 纯Kotlin轻量级框架，运行时解析，适合中小项目

3. **设计模式在Android开发中的应用**
   - 单例模式: SharedPreferences管理
   - 观察者模式: LiveData/RxJava
   - 建造者模式: AlertDialog.Builder
   - 适配器模式: RecyclerView.Adapter

#### UI和布局

1. **RecyclerView与ListView的区别**
   - RecyclerView强制使用ViewHolder，性能更好
   - RecyclerView支持多种布局管理器和动画
   - RecyclerView解耦更彻底，更灵活可定制

2. **布局优化方法**
   - 使用ConstraintLayout减少嵌套
   - 合理使用include和merge标签
   - ViewStub延迟加载
   - 避免过度绘制(Overdraw)

3. **自定义View的实现步骤**
   - 继承View或现有控件
   - 重写onMeasure(), onLayout(), onDraw()方法
   - 处理交互(onTouchEvent)
   - 添加自定义属性

#### 性能优化

1. **内存优化方法**
   - 避免内存泄漏：防止Context引用不当
   - 减少内存占用：合理使用缓存，避免频繁创建大对象
   - 使用WeakReference引用外部对象
   - 图片优化：按需加载，压缩，缓存

2. **ANR原因及解决方案**
   - 原因：主线程阻塞(网络操作，密集计算，死锁)
   - 解决：耗时操作放入子线程，合理使用协程/RxJava
   - 优化Handler使用，避免过多消息堆积

3. **启动优化技术**
   - 延迟初始化非核心组件
   - 使用启动器，任务分级并行
   - 减少应用冷启动时间，使用App Startup

#### 异步与并发

1. **Handler机制原理**
   - 由MessageQueue, Looper, Handler组成
   - Looper循环从MessageQueue取出Message
   - Handler发送和处理Message，实现线程通信

2. **Kotlin协程的优势及使用场景**
   - 相比线程更轻量，避免回调地狱
   - 结构化并发，生命周期管理
   - 内置取消和异常处理机制
   - 各种调度器(Dispatchers)满足不同需求

3. **多线程同步方法**
   - synchronized关键字
   - ReentrantLock可重入锁
   - volatile关键字
   - 原子类(AtomicInteger等)

#### Jetpack组件

1. **ViewModel的生命周期**
   - 比Activity/Fragment生命周期长
   - 配置变更(如旋转)时不会重建
   - 在onCleared()中清理资源

2. **LiveData的工作原理**
   - 具有生命周期感知能力
   - 仅在活跃状态(STARTED/RESUMED)时通知观察者
   - 确保UI与数据状态一致

3. **Room的主要组件**
   - Entity: 数据库表映射的实体类
   - DAO: 数据访问对象，定义SQL操作
   - Database: 数据库持有者，提供连接

## 面试技巧

### 技术面试应对策略

1. **理解问题**
   - 确保完全理解问题再回答
   - 需要时请求澄清
   - 表达思考过程，即使不能立即给出完整答案

2. **代码编写注意事项**
   - 注重可读性和命名
   - 考虑边界情况和异常处理
   - 优先给出可工作的解决方案，再优化

3. **项目经验讲解**
   - 使用STAR法则(情景-任务-行动-结果)
   - 强调你的具体贡献和解决的技术难题
   - 说明技术选型和架构决策的理由

### 行为面试准备

1. **常见行为问题**
   - 描述一个你解决的技术挑战
   - 如何处理与团队成员的分歧
   - 如何平衡质量和deadline
   - 如何学习新技术

2. **展示软技能**
   - 沟通能力：与不同角色合作的经验
   - 学习能力：快速掌握新技术的案例
   - 解决问题：面对复杂问题的方法论
   - 主动性：自我驱动的项目或改进

## 准备清单

### 面试前准备

1. **技术复习**
   - 复习核心Android知识点
   - 重温自己项目中使用的技术
   - 了解目标公司使用的技术栈

2. **项目梳理**
   - 准备2-3个可深入讨论的项目
   - 每个项目准备技术挑战、解决方案、结果
   - 思考项目中的架构决策和取舍

3. **模拟练习**
   - 口头回答常见问题
   - 在白板/纸上练习算法题
   - 模拟系统设计题

### 面试后跟进

1. **复盘分析**
   - 记录面试中的难点和不足
   - 分析可改进的知识领域
   - 查漏补缺，针对性学习

2. **感谢邮件**
   - 发送简短感谢邮件
   - 表达对职位的持续兴趣
   - 补充面试中未完整表达的点

## 结论

Android面试既考察基础知识，也考察实际问题解决能力。通过系统准备，梳理知识体系，结合实际项目经验，可以更好地展示自己的技术能力和发展潜力。保持学习的态度，了解行业最新动态和技术趋势同样重要。 