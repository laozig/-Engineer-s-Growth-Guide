# 16. 用户与权限管理

在多用户环境中，对数据库的访问进行精细化控制是至关重要的。PostgreSQL提供了一个强大而灵活的基于角色的访问控制（Role-Based Access Control, RBAC）系统。

## 角色 (Roles)

在PostgreSQL中，不再区分"用户"和"组"。只有一个统一的概念：**角色 (Role)**。一个角色可以是一个数据库用户，一个用户组，或者两者兼备。

- 角色可以拥有数据库对象（如表、函数）。
- 角色可以被授予对这些对象的特定权限。
- 角色可以成为其他角色的成员，从而继承该角色的权限。

### 创建角色

`CREATE ROLE` 命令用于创建新角色。

```sql
-- 创建一个可以登录的用户角色
CREATE ROLE alice WITH LOGIN PASSWORD 'a_secure_password';

-- 创建一个不能登录的组角色
CREATE ROLE engineering_team;

-- 创建一个拥有创建数据库权限的超级用户（需谨慎授予）
CREATE ROLE admin WITH LOGIN SUPERUSER PASSWORD 'super_secret';
```

**常用角色属性**:
- `LOGIN`: 允许角色登录数据库。没有此属性的角色通常用作"组"。
- `SUPERUSER`: 拥有数据库实例的所有权限，可以绕过所有权限检查。
- `CREATEDB`: 允许角色创建新的数据库。
- `CREATEROLE`: 允许角色创建、修改和删除其他角色。
- `PASSWORD`: 为可以登录的角色设置密码。

## 权限授予 (GRANT)

`GRANT` 命令用于将特定操作的权限授予角色。

### 对象级权限

这是最常见的权限类型，用于控制对表、视图、序列、函数等数据库对象的访问。

```sql
-- 授予 engineering_team 角色对 employees 表的 SELECT 权限
GRANT SELECT ON employees TO engineering_team;

-- 授予所有权限
GRANT ALL PRIVILEGES ON employees TO admin;

-- 授予特定列的 UPDATE 权限
GRANT UPDATE (salary) ON employees TO alice;
```

**常用对象权限**:
- `SELECT`: 读取数据
- `INSERT`: 插入新数据
- `UPDATE`: 更新现有数据
- `DELETE`: 删除数据
- `TRUNCATE`: 清空表
- `REFERENCES`: 创建外键约束
- `TRIGGER`: 创建触发器
- `USAGE`: 对序列、模式等对象的"使用"权限
- `EXECUTE`: 执行函数或过程的权限

### 成员关系授予

您可以将一个角色授予给另一个角色，从而实现权限继承。

```sql
-- 让用户 alice 成为 engineering_team 组的成员
GRANT engineering_team TO alice;
```
现在，`alice` 继承了 `engineering_team` 拥有的所有权限（例如，对`employees`表的`SELECT`权限）。

## 权限撤销 (REVOKE)

`REVOKE` 命令用于收回之前授予的权限。

```sql
-- 从 alice 角色收回对 employees 表的 UPDATE 权限
REVOKE UPDATE ON employees FROM alice;

-- 从 alice 角色中移除其 engineering_team 组成员的身份
REVOKE engineering_team FROM alice;
```

## 默认权限 (`ALTER DEFAULT PRIVILEGES`)

每次创建新对象（如表）时，都需要为其手动设置权限，这可能非常繁琐。`ALTER DEFAULT PRIVILEGES` 命令允许您为**未来**创建的对象设置默认权限。

这对于确保某个角色（如Web应用的用户）自动获得在新表上的`SELECT`、`INSERT`等权限非常有用。

```sql
-- 假设我们有一个 web_app 角色
CREATE ROLE web_app WITH LOGIN PASSWORD '...';

-- 为 web_app 角色设置默认权限
-- 对于未来由 admin 角色在 public 模式下创建的表
-- 自动授予 web_app 角色 SELECT, INSERT, UPDATE, DELETE 权限
ALTER DEFAULT PRIVILEGES FOR ROLE admin IN SCHEMA public
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO web_app;

-- 对于序列也是如此
ALTER DEFAULT PRIVILEGES FOR ROLE admin IN SCHEMA public
GRANT USAGE ON SEQUENCES TO web_app;
```
现在，当`admin`用户创建一个新表时，`web_app`角色将自动拥有对该表的增删改查权限，无需再手动`GRANT`。

## 行级安全 (Row-Level Security - RLS)

传统的对象级权限控制了用户是否**能**访问整张表，而行级安全（RLS）控制了用户能访问表中的**哪些行**。

RLS通过策略（Policy）来实现。一个策略是一个返回布尔值的表达式，对于每一行数据，如果表达式为真，则该行对当前用户可见或可操作。

**示例：用户只能看到自己的数据**
假设`employees`表有一个`username`列，与当前数据库用户匹配。

1.  **在表上启用RLS**:
    ```sql
    ALTER TABLE employees ENABLE ROW LEVEL SECURITY;
    ```

2.  **创建策略**:
    ```sql
    CREATE POLICY user_can_see_own_data
    ON employees
    FOR SELECT -- 此策略仅对SELECT操作生效
    USING (username = current_user); -- 如果行的username等于当前登录的用户名，则可见
    ```

现在，当一个普通用户（非超级用户或表所有者）查询`employees`表时，他们将只能看到`username`列与自己数据库用户名匹配的行。

RLS是一个非常强大的特性，用于构建多租户应用或需要复杂数据访问规则的系统。

通过组合使用角色、`GRANT`/`REVOKE`、默认权限和行级安全，PostgreSQL提供了一个全面而强大的安全模型，能够满足几乎所有应用场景的权限控制需求。 