# Redis 高性能缓存

欢迎来到 Redis 高性能缓存指南！本指南旨在为开发者和运维人员提供一个全面的学习路径，内容涵盖从 Redis 基础概念到高级应用与优化的各个方面。

## 学习路线图

为了方便您系统地学习，我们将内容分为四个部分，共 20 个主题。您可以按照顺序学习，也可以直接选择您感兴趣的主题。

### 🚀 第一部分：Redis 基础 (Part 1: Redis Basics)

- [√] 1. [Redis 简介](./introduction.md)
- [√] 2. [安装与配置](./installation.md)
- [√] 3. [Redis 架构](./architecture.md)
- [√] 4. [数据类型](./data-types.md)
- [√] 5. [基本命令](./basic-commands.md)

### 💾 第二部分：数据操作与管理 (Part 2: Data Operations & Management)

- [√] 6. [字符串操作](./string-operations.md)
- [√] 7. [列表操作](./list-operations.md)
- [√] 8. [集合操作](./set-operations.md)
- [√] 9. [有序集合操作](./sorted-set-operations.md)
- [√] 10. [哈希表操作](./hash-operations.md)

### 🔧 第三部分：高级特性 (Part 3: Advanced Features)

- [√] 11. [发布订阅](./pubsub.md)
- [√] 12. [事务处理](./transactions.md)
- [√] 13. [Lua 脚本](./lua-scripting.md)
- [√] 14. [持久化](./persistence.md)
- [√] 15. [Pipeline 与批量处理](./pipeline-batching.md)

### ⚙️ 第四部分：部署与优化 (Part 4: Deployment & Optimization)

- [√] 16. [主从复制](./replication.md)
- [√] 17. [哨兵模式](./sentinel.md)
- [√] 18. [集群模式](./cluster.md)
- [√] 19. [性能调优](./performance-tuning.md)
- [√] 20. [安全与监控](./security-monitoring.md)

## 学习建议

- **初学者**：请从第一部分开始，按顺序学习，以建立坚实的基础知识
- **已有基础**：可以直接查阅第二、三部分的特定主题，深化对数据操作和高级特性的理解
- **实施部署**：如果您需要在生产环境中部署和优化Redis，第四部分的内容将对您特别有用
- **实践**：为了巩固理解，强烈建议在学习每个主题后进行实践操作

## 常见问题

- **Redis最适合什么场景?** Redis 特别适合缓存、会话存储、排行榜、实时分析和消息队列等场景
- **Redis与其他NoSQL数据库的区别?** Redis 主要在内存中操作，提供更低的延迟，并支持丰富的数据结构和操作
- **如何选择合适的数据类型?** 根据数据的使用模式选择:
  - 键值对：使用字符串
  - 存储对象：使用哈希
  - 列表数据：使用列表
  - 唯一元素集：使用集合
  - 带权重排序：使用有序集合 