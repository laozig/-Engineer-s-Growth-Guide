# 数据库交互：从原生驱动到 ORM

在现代全栈开发中，与数据库的交互是后端服务的核心。本指南将深入探讨 Node.js 环境下如何与不同类型的数据库通信，涵盖从使用原生驱动程序执行底层操作，到利用对象关系映射（ORM）/对象文档映射（ODM）进行高效开发的全部过程。

---

## 目录

1.  [关系型数据库 (SQL)](#1-关系型数据库-sql)
    -   [使用 `node-postgres` (pg)](#使用-node-postgres-pg)
    -   [安装与配置](#安装与配置)
    -   [执行 CRUD 操作](#执行-crud-操作)
2.  [NoSQL 数据库](#2-nosql-数据库)
    -   [使用 `mongodb`](#使用-mongodb)
    -   [安装与配置](#安装与配置-1)
    -   [执行 CRUD 操作](#执行-crud-操作-1)
3.  [ORM 与 ODM：更高级的抽象](#3-orm-与-odm更高级的抽象)
    -   [Sequelize (SQL ORM)](#sequelize-sql-orm)
    -   [Mongoose (MongoDB ODM)](#mongoose-mongodb-odm)
4.  [最佳实践](#4-最佳实践)
5.  [总结](#5-总结)

---

## 1. 关系型数据库 (SQL)

关系型数据库（如 PostgreSQL, MySQL）以其结构化、事务性和一致性而闻名。在 Node.js 中，我们通常使用特定的驱动程序来与它们交互。

### 使用 `node-postgres` (pg)

`node-postgres`（通常称为 `pg`）是 Node.js 社区中最流行、最稳定、功能最丰富的 PostgreSQL 客户端。它支持回调、Promise 和 `async/await`。

### 安装与配置

首先，安装 `pg` 库：
```bash
npm install pg
```

为了高效管理数据库连接，最佳实践是使用**连接池**。连接池会预先创建并维护一组数据库连接，当需要执行查询时，从池中获取一个连接，使用完毕后归还，而不是每次都创建和销毁连接。

**配置示例 (`db.js`)**

```javascript
// db.js
import pg from 'pg';

// 建议使用环境变量来管理敏感信息
const pool = new pg.Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'mydatabase',
  password: process.env.DB_PASSWORD || 'password',
  port: process.env.DB_PORT || 5432,
});

// 导出一个可以执行查询的函数
export const query = async (text, params) => {
  const start = Date.now();
  const res = await pool.query(text, params);
  const duration = Date.now() - start;
  console.log('executed query', { text, duration, rows: res.rowCount });
  return res;
};
```

### 执行 CRUD 操作

现在让我们用上面创建的 `query` 函数来执行基本的数据库操作。假设我们有一个 `users` 表：

```sql
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL
);
```

**C - Create (创建)**

使用 `INSERT` 语句。参数化查询 (`$1`, `$2`) 是防止 SQL 注入的关键。

```javascript
// user-service.js
import { query } from './db.js';

export async function createUser(name, email) {
  const sql = 'INSERT INTO users (name, email) VALUES ($1, $2) RETURNING *';
  try {
    const result = await query(sql, [name, email]);
    console.log('User created:', result.rows[0]);
    return result.rows[0];
  } catch (err) {
    console.error('Error creating user:', err);
    throw err;
  }
}
```
*   `query(sql, [name, email])`: 第一个参数是 SQL 语句模板，第二个参数是值的数组。`pg` 驱动会自动安全地将值替换到 `$1`, `$2` 的位置。
*   `RETURNING *`: 这是 PostgreSQL 的一个特性，它可以在 `INSERT`, `UPDATE`, `DELETE` 操作后返回受影响的行数据。

**R - Read (读取)**

```javascript
// user-service.js

// 获取所有用户
export async function getAllUsers() {
  const sql = 'SELECT * FROM users ORDER BY id ASC';
  const result = await query(sql);
  return result.rows;
}

// 根据 ID 获取单个用户
export async function getUserById(id) {
  const sql = 'SELECT * FROM users WHERE id = $1';
  const result = await query(sql, [id]);
  // 如果没有找到用户，result.rows 为空数组
  return result.rows[0] || null;
}
```
*   `result.rows`: `pg` 将查询结果集放在 `rows` 数组中，每一行是一个对象。

**U - Update (更新)**

```javascript
// user-service.js
export async function updateUserEmail(id, newEmail) {
  const sql = 'UPDATE users SET email = $1 WHERE id = $2 RETURNING *';
  const result = await query(sql, [newEmail, id]);
  if (result.rowCount === 0) {
    console.warn(`No user found with id ${id} to update.`);
    return null;
  }
  console.log('User updated:', result.rows[0]);
  return result.rows[0];
}
```
*   `result.rowCount`: 表示此操作影响了多少行。我们可以用它来判断更新是否成功。

**D - Delete (删除)**

```javascript
// user-service.js
export async function deleteUser(id) {
  const sql = 'DELETE FROM users WHERE id = $1';
  const result = await query(sql, [id]);
  // rowCount 会是 1 (删除成功) 或 0 (没有找到要删除的用户)
  return result.rowCount > 0;
}
```

---

## 2. NoSQL 数据库

NoSQL 数据库（如 MongoDB, Redis）提供了更灵活的数据模型，通常用于需要高可伸缩性和快速开发的场景。

### 使用 `mongodb`

`mongodb` 是官方的 MongoDB Node.js 驱动程序，它提供了与数据库交互的底层 API。

### 安装与配置

```bash
npm install mongodb
```

**配置示例 (`mongo-client.js`)**

```javascript
// mongo-client.js
import { MongoClient } from 'mongodb';

// 使用环境变量存储连接字符串
const uri = process.env.MONGO_URI || 'mongodb://localhost:27017';
const client = new MongoClient(uri);

let db;

export async function connectToMongo() {
  if (db) {
    return db;
  }
  try {
    await client.connect();
    console.log('Connected successfully to MongoDB');
    db = client.db(process.env.MONGO_DB_NAME || 'mydatabase');
    return db;
  } catch (err) {
    console.error('Could not connect to MongoDB', err);
    process.exit(1);
  }
}

// 导出一个获取数据库实例的函数
export function getDb() {
  if (!db) {
    throw new Error('You must connect to Mongo first!');
  }
  return db;
}
```

### 执行 CRUD 操作

假设我们正在操作一个 `todos` 集合。

**C - Create (创建)**

```javascript
// todo-service.js
import { getDb } from './mongo-client.js';

export async function createTodo(task) {
  const db = getDb();
  const newTodo = {
    task,
    completed: false,
    createdAt: new Date(),
  };
  const result = await db.collection('todos').insertOne(newTodo);
  console.log(`New todo created with id: ${result.insertedId}`);
  return { id: result.insertedId, ...newTodo };
}
```
*   `collection('todos')`: 获取对 `todos` 集合的引用。如果集合不存在，MongoDB 会在第一次插入文档时自动创建它。
*   `insertOne(document)`: 插入单个文档。`result.insertedId` 包含了新创建文档的 `_id`。

**R - Read (读取)**

```javascript
// todo-service.js
import { ObjectId } from 'mongodb';

// 获取所有待办事项
export async function getAllTodos() {
  const db = getDb();
  // .find() 返回一个游标 (cursor)，.toArray() 将其转换为数组
  const todos = await db.collection('todos').find({}).toArray();
  return todos;
}

// 根据 ID 获取单个待办事项
export async function getTodoById(id) {
  const db = getDb();
  // ID 在 MongoDB 中是 ObjectId 类型，需要转换
  const todo = await db.collection('todos').findOne({ _id: new ObjectId(id) });
  return todo;
}
```
*   `find(query)`: 根据查询条件返回一个游标。`{}` 表示匹配所有文档。
*   `findOne(query)`: 只返回匹配的第一个文档，如果没有匹配则返回 `null`。
*   `new ObjectId(id)`: MongoDB 的 `_id` 是一个特殊类型，从字符串查询时必须进行转换。

**U - Update (更新)**

```javascript
// todo-service.js
import { ObjectId } from 'mongodb';

export async function markTodoAsCompleted(id) {
  const db = getDb();
  const result = await db.collection('todos').updateOne(
    { _id: new ObjectId(id) }, // Filter: 找到要更新的文档
    { $set: { completed: true } } // Update: 使用 $set 操作符更新字段
  );
  console.log(`${result.modifiedCount} document(s) updated.`);
  return result.modifiedCount > 0;
}
```
*   `updateOne(filter, update)`: 更新匹配 `filter` 的第一个文档。`update` 参数使用 MongoDB 的更新操作符（如 `$set`, `$inc`）。
*   `result.modifiedCount`: 表示成功修改的文档数量。

**D - Delete (删除)**

```javascript
// todo-service.js
import { ObjectId } from 'mongodb';

export async function deleteTodo(id) {
  const db = getDb();
  const result = await db.collection('todos').deleteOne({ _id: new ObjectId(id) });
  console.log(`${result.deletedCount} document(s) deleted.`);
  return result.deletedCount > 0;
}
```
*   `deleteOne(filter)`: 删除匹配 `filter` 的第一个文档。
*   `result.deletedCount`: 表示成功删除的文档数量。

---

## 3. ORM 与 ODM：更高级的抽象

虽然原生驱动程序功能强大，但直接使用它们意味着要手写大量 SQL 或 MongoDB 查询语句。ORM/ODM 在驱动程序之上提供了一个抽象层，允许你用更符合面向对象思想的方式与数据库交互。

### Sequelize (SQL ORM)

[Sequelize](https://sequelize.org/) 是一个成熟的、基于 Promise 的 Node.js ORM，支持 PostgreSQL, MySQL, MariaDB, SQLite 和 Microsoft SQL Server。

**核心优势**：
*   **模型定义**：将数据库表映射为 JavaScript 类（模型）。
*   **数据验证**：内置验证器。
*   **关联关系**：轻松定义一对一、一对多、多对多关系。
*   **事务管理**：强大的事务支持。

**示例**：
```javascript
// 使用 Sequelize
import { Sequelize, DataTypes } from 'sequelize';
const sequelize = new Sequelize('postgres://user:pass@example.com:5432/dbname');

// 定义模型
const User = sequelize.define('User', {
  name: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, unique: true },
});

// 查询替代了手写 SQL
async function findUser(id) {
  // SELECT * FROM "Users" WHERE id = ?;
  const user = await User.findByPk(id);
  return user;
}
```

### Mongoose (MongoDB ODM)

[Mongoose](https://mongoosejs.com/) 是一个专为 MongoDB 设计的 ODM，它在原生驱动程序之上提供了一套优雅的解决方案。

**核心优势**：
*   **Schema 设计**：强制数据结构，提供数据一致性。
*   **模型**：提供了丰富的 API 用于创建、查询、更新和删除文档。
*   **数据验证**：强大的内置和自定义验证功能。
*   **中间件 (Middleware)**：可以在保存、更新等操作前后执行挂子函数。
*   **查询构建**：链式 API 使复杂查询变得简单。

**示例**：
```javascript
// 使用 Mongoose
import mongoose from 'mongoose';
await mongoose.connect('mongodb://127.0.0.1:27017/test');

// 定义 Schema 和模型
const todoSchema = new mongoose.Schema({
  task: String,
  completed: Boolean,
  createdAt: { type: Date, default: Date.now },
});
const Todo = mongoose.model('Todo', todoSchema);

// 创建和保存文档
async function createAndSaveTodo(task) {
  const todo = new Todo({ task, completed: false });
  // .save() 方法将文档存入数据库
  await todo.save();
  return todo;
}
```

---

## 4. 最佳实践

无论你选择哪种技术，遵循以下实践都能让你的应用更健壮、安全和可维护：

1.  **使用连接池**：对于 SQL 数据库，始终使用连接池来管理连接，避免性能瓶颈。
2.  **环境变量管理凭证**：切勿将数据库地址、用户名、密码等敏感信息硬编码在代码中。使用 `.env` 文件（配合 `dotenv` 库）或云服务提供的环境变量。
3.  **防止 SQL 注入**：在使用原生 SQL 时，永远不要用字符串拼接的方式构建查询。始终使用参数化查询（如 `pg` 的 `$1, $2`）。ORM/ODM 通常会自动处理这个问题。
4.  **优雅地处理连接错误**：数据库连接可能会中断。你的应用应该能够检测到连接丢失并尝试重新连接，或者优雅地失败并记录错误。
5.  **为查询建立索引**：对于经常被查询的字段（如 `users.email` 或 `todos.userId`），在数据库中为它们创建索引可以极大地提高查询性能。
6.  **抽象数据库逻辑**：将所有数据库交互代码封装在服务层或仓库（Repository）层中，而不是散布在你的路由处理器或其他业务逻辑中。这使得代码更易于测试和维护。

---

## 5. 总结

在 Node.js 中与数据库交互有多种选择，每种都有其适用场景：

*   **原生驱动程序 (`pg`, `mongodb`)**：
    *   **优点**：性能最好，控制力最强，可以利用数据库的全部特性。
    *   **缺点**：需要手写查询语句，代码量较大，容易出错（特别是 SQL 注入）。
    *   **适用场景**：需要极致性能优化、执行复杂或非标准查询的场景。

*   **ORM/ODM (`Sequelize`, `Mongoose`)**：
    *   **优点**：开发速度快，代码更简洁且面向对象，内置验证和安全机制，跨数据库兼容性更好（仅限ORM）。
    *   **缺点**：有一定的性能开销，可能会隐藏底层数据库的复杂性，学习曲线稍陡。
    *   **适用场景**：大多数标准的 Web 应用、企业级应用、快速原型开发。

选择哪种工具取决于你的项目需求、团队熟悉度和对性能的要求。对于新项目，从 ORM/ODM 开始通常是最高效的选择。