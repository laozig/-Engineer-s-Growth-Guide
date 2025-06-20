# 16. 用户与权限管理 (User & Security Management)

数据库安全是系统管理的核心部分。MySQL 提供了一套强大而灵活的权限系统，允许数据库管理员（DBA）精确地控制每个用户可以执行的操作。

## 用户账户管理

MySQL 用户账户由两部分组成：`'username'@'hostname'`。
- **`username`**: 用户名。
- **`hostname`**: 指定了该用户可以从哪个主机连接到 MySQL 服务器。可以是 IP 地址、主机名或通配符（如 `'%'` 表示任何主机，`'192.168.1.%'` 表示一个网段）。

`'user1'@'localhost'` 和 `'user1'@'192.168.1.100'` 是两个完全不同的用户。

### 创建用户

使用 `CREATE USER` 语句。

```sql
-- 创建一个只能从本地主机连接的用户
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'a_strong_password';

-- 创建一个可以从任何主机连接的用户 (通常不推荐用于生产环境)
CREATE USER 'remote_admin'@'%' IDENTIFIED BY 'another_secure_password';

-- 创建一个不需要密码的用户 (非常不安全，仅用于特殊情况)
CREATE USER 'guest'@'localhost';
```
> **MySQL 8.0+ 默认认证插件**: 从 MySQL 8.0 开始，默认的认证插件是 `caching_sha2_password`，它比之前的 `mysql_native_password` 更安全。如果你的客户端或应用连接器不支持新插件，可以在创建用户时指定旧插件：
> `CREATE USER 'legacy_user'@'localhost' IDENTIFIED WITH mysql_native_password BY 'password';`

### 查看用户

所有用户账户信息都存储在 `mysql` 数据库的 `user` 表中。

```sql
SELECT user, host FROM mysql.user;
```

### 修改用户

- **重命名用户**:
  ```sql
  RENAME USER 'webapp'@'localhost' TO 'app_user'@'localhost';
  ```
- **修改密码**:
  ```sql
  ALTER USER 'app_user'@'localhost' IDENTIFIED BY 'a_new_stronger_password';
  ```

### 删除用户

使用 `DROP USER` 语句。

```sql
DROP USER 'guest'@'localhost';
```

## 权限管理 (Privileges)

权限决定了用户能对数据库对象（如数据库、表、列、存储过程）执行哪些操作。

### 授予权限 - `GRANT`

`GRANT` 语句用于给用户赋予权限。

**语法**:
`GRANT privilege_type [(columns)] ON database.object TO 'user'@'host';`

- **`privilege_type`**: 权限类型，如 `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `ALL PRIVILEGES` 等。
- **`ON database.object`**: 指定权限的作用域。
    - `*.*`: 全局权限，适用于所有数据库。
    - `dbname.*`: 适用于特定数据库中的所有对象。
    - `dbname.tablename`: 适用于特定表。
    - `dbname.proc_name`: 适用于特定存储过程。

**示例**:
```sql
-- 授予 app_user 对 'my_project' 数据库中所有表的 SELECT, INSERT, UPDATE 权限
GRANT SELECT, INSERT, UPDATE ON my_project.* TO 'app_user'@'localhost';

-- 授予 backup_user 对所有数据库的只读权限 (SELECT)
GRANT SELECT ON *.* TO 'backup_user'@'localhost';

-- 授予一个用户 'my_project' 数据库的所有权限，并允许他将这些权限授予其他用户
GRANT ALL PRIVILEGES ON my_project.* TO 'project_admin'@'localhost' WITH GRANT OPTION;
```
- **`WITH GRANT OPTION`**: 允许该用户将他自己拥有的权限授予其他用户，这是一个非常强大的权限，应谨慎使用。

### 查看权限 - `SHOW GRANTS`

查看一个用户当前拥有的所有权限。

```sql
SHOW GRANTS FOR 'app_user'@'localhost';
```

### 撤销权限 - `REVOKE`

`REVOKE` 语句用于收回已授予的权限。其语法与 `GRANT` 非常相似。

```sql
-- 撤销 app_user 对 'my_project' 数据库的 UPDATE 权限
REVOKE UPDATE ON my_project.* FROM 'app_user'@'localhost';

-- 撤销 project_admin 的授权权限
REVOKE GRANT OPTION ON my_project.* FROM 'project_admin'@'localhost';

-- 撤销所有权限
REVOKE ALL PRIVILEGES ON my_project.* FROM 'project_admin'@'localhost';
```
**重要**: 在修改权限后，最好执行 `FLUSH PRIVILEGES;` 来重新加载授权表，以确保更改立即生效。虽然在 `GRANT`, `REVOKE`, `CREATE USER` 等操作后，权限通常会自动重载，但在某些旧版本或复杂情况下，手动刷新是好习惯。

## 角色管理 (Roles) - MySQL 8.0+

角色是一组权限的集合。你可以创建一个角色，将多个权限授予该角色，然后再将这个角色授予一个或多个用户。这极大地简化了权限管理。

**工作流程**:
1.  **创建角色**:
    ```sql
    CREATE ROLE 'read_only_role', 'app_developer_role';
    ```
2.  **给角色授予权限**:
    ```sql
    -- 给只读角色授予 SELECT 权限
    GRANT SELECT ON my_project.* TO 'read_only_role';

    -- 给开发者角色授予读写权限
    GRANT SELECT, INSERT, UPDATE, DELETE ON my_project.* TO 'app_developer_role';
    ```
3.  **将角色授予用户**:
    ```sql
    CREATE USER 'analyst'@'localhost' IDENTIFIED BY 'password';
    CREATE USER 'dev1'@'localhost' IDENTIFIED BY 'password';

    GRANT 'read_only_role' TO 'analyst'@'localhost';
    GRANT 'app_developer_role' TO 'dev1'@'localhost';
    ```
4.  **激活角色**:
    用户在登录后需要设置默认角色才能使其权限生效。
    ```sql
    -- 设置用户登录后自动激活的角色
    SET DEFAULT ROLE 'app_developer_role' TO 'dev1'@'localhost';
    -- 或者 SET DEFAULT ROLE ALL TO 'user'@'host';

    -- 在当前会话中手动激活角色
    -- SET ROLE 'role_name';
    ```

## 安全最佳实践

- **最小权限原则**: 只授予用户完成其工作所必需的最小权限。
- **为不同应用创建不同用户**: 不要所有应用都使用 `root` 或同一个高权限用户。
- **限制主机**: 尽量使用 `localhost` 或具体的 IP 地址，避免使用 `'%'`。
- **使用强密码**: 并定期更换。
- **删除匿名用户和 `test` 数据库**: 在生产环境中，运行 `mysql_secure_installation` 脚本来完成这些基础安全设置。
- **定期审计权限**: 使用 `SHOW GRANTS` 定期检查用户权限，确保没有过度的授权。
- **使用角色**: 在 MySQL 8.0+ 中，优先使用角色来管理权限。 