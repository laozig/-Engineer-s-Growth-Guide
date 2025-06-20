# 14. 存储过程与函数 (Stored Procedures & Functions)

存储过程和存储函数是预先编译好并存储在数据库中的一组 SQL 语句。它们可以在需要时通过名称来调用，类似于编程语言中的函数或方法。这允许你将复杂的业务逻辑封装在数据库层面，从而提高代码的重用性、简化应用逻辑并可能提升性能。

## 存储过程 (Stored Procedures) vs. 存储函数 (Stored Functions)

| 特性 | 存储过程 (Stored Procedure) | 存储函数 (Stored Function) |
| :--- | :--- | :--- |
| **返回值** | 不能直接返回值。可以通过 `OUT` 或 `INOUT` 参数返回多个值。 | **必须**返回一个单一的值。 |
| **调用方式** | 使用 `CALL` 语句调用。 | 可以在 SQL 语句中直接使用，就像内置函数一样（如 `SELECT my_func()`）。 |
| **用途** | 主要用于执行一个操作或一系列操作（如批量数据更新、复杂的数据处理）。 | 主要用于计算并返回一个值，以便在查询中使用。 |

---

## 存储过程 (Stored Procedures)

### 创建存储过程

```sql
DELIMITER $$

CREATE PROCEDURE procedure_name (
    [IN | OUT | INOUT] parameter_name data_type,
    ...
)
BEGIN
    -- 声明变量
    -- SQL 语句和逻辑控制
END$$

DELIMITER ;
```

- **`DELIMITER $$`**: MySQL 默认的语句结束符是分号 `;`。由于存储过程内部可能包含多条以分号结尾的 SQL 语句，我们需要临时改变结束符，以免在定义过程中断。这里我们将其改为 `$$`，在 `END` 之后再改回分号。
- **参数模式**:
    - `IN`: 输入参数（默认）。值由调用者传入，在过程内部只读。
    - `OUT`: 输出参数。过程可以修改它，并将最终值返回给调用者。
    - `INOUT`: 输入输出参数。调用者传入初始值，过程可以修改它，并返回最终值。
- **`BEGIN ... END`**: 包含了过程的主体逻辑。

**示例 1：一个简单的无参存储过程**

```sql
DELIMITER $$
CREATE PROCEDURE GetAllEmployees()
BEGIN
    SELECT * FROM employees;
END$$
DELIMITER ;
```

**调用它**:
```sql
CALL GetAllEmployees();
```

**示例 2：带 `IN` 和 `OUT` 参数的存储过程**
这个过程接收一个部门 ID，并返回该部门的员工数量。

```sql
DELIMITER $$
CREATE PROCEDURE GetEmployeeCountByDept(IN dept_id INT, OUT employee_count INT)
BEGIN
    SELECT COUNT(*) INTO employee_count
    FROM employees
    WHERE department_id = dept_id;
END$$
DELIMITER ;
```

**调用它**:
```sql
-- @employee_count 是一个用户定义的会话变量
CALL GetEmployeeCountByDept(1, @employee_count);

-- 查看返回的结果
SELECT @employee_count;
```

### 变量和流程控制

在存储过程中，你可以声明变量并使用流程控制语句。

```sql
DELIMITER $$
CREATE PROCEDURE CheckSalaryLevel(IN emp_id INT, OUT salary_level VARCHAR(20))
BEGIN
    -- 声明一个局部变量来存储薪水
    DECLARE emp_salary DECIMAL(10, 2);

    -- 从表中获取薪水并存入变量
    SELECT salary INTO emp_salary FROM employees WHERE id = emp_id;

    -- 使用 IF-ELSEIF-ELSE 逻辑
    IF emp_salary > 100000 THEN
        SET salary_level = 'Executive';
    ELSEIF emp_salary > 70000 THEN
        SET salary_level = 'Senior';
    ELSE
        SET salary_level = 'Junior';
    END IF;
END$$
DELIMITER ;
```
**调用**:
```sql
CALL CheckSalaryLevel(1, @level);
SELECT @level;
```

---

## 存储函数 (Stored Functions)

### 创建存储函数

```sql
DELIMITER $$
CREATE FUNCTION function_name (
    parameter_name data_type,
    ...
)
RETURNS return_data_type
[DETERMINISTIC | NOT DETERMINISTIC]
BEGIN
    -- 声明、逻辑...
    RETURN (value);
END$$
DELIMITER ;
```
- **`RETURNS`**: 必须指定函数返回的数据类型。
- **`DETERMINISTIC`**: 一个重要的属性。
    - `DETERMINISTIC`: 确定性函数。对于相同的输入参数，总是产生相同的结果（例如，一个数学计算函数）。
    - `NOT DETERMINISTIC`: 非确定性函数。对于相同的输入，可能会产生不同的结果（例如，函数内部查询了表，而表的数据可能变化，或者像 `NOW()` 这样的函数）。
    - 明确指定这个属性有助于优化器做出更好的决策。

**示例：创建一个计算全名的函数**

```sql
DELIMITER $$
CREATE FUNCTION GetFullName(first_name VARCHAR(50), last_name VARCHAR(50))
RETURNS VARCHAR(101)
DETERMINISTIC
BEGIN
    RETURN CONCAT(first_name, ' ', last_name);
END$$
DELIMITER ;
```
**在查询中使用它**:
```sql
SELECT GetFullName(first_name, last_name) AS full_name, salary
FROM employees;
```

## 管理存储过程和函数

- **查看状态**:
  ```sql
  -- 查看所有存储过程和函数的状态
  SHOW PROCEDURE STATUS;
  SHOW FUNCTION STATUS;

  -- 筛选
  SHOW PROCEDURE STATUS WHERE Db = 'my_project';
  ```

- **查看创建语句**:
  ```sql
  SHOW CREATE PROCEDURE GetAllEmployees;
  SHOW CREATE FUNCTION GetFullName;
  ```

- **删除**:
  ```sql
  DROP PROCEDURE IF EXISTS GetAllEmployees;
  DROP FUNCTION IF EXISTS GetFullName;
  ```

## 优缺点

**优点**:
- **代码重用**: 将通用逻辑封装起来，供多个应用或查询调用。
- **减少网络流量**: 应用只需发送一个 `CALL` 语句，而不是多条复杂的 SQL 语句。
- **更好的安全性**: 可以授予用户执行存储过程的权限，而不是直接访问基表的权限。
- **封装性**: 应用开发者无需关心底层的复杂表结构。

**缺点**:
- **可移植性差**: 语法在不同数据库（如 Oracle, SQL Server）之间可能不兼容。
- **调试困难**: 调试存储过程通常比调试应用层代码更复杂。
- **业务逻辑分散**: 将业务逻辑放在数据库中，可能会导致应用和数据库之间的逻辑耦合和分散，使维护变得复杂。
- **资源消耗**: 复杂的存储过程会消耗数据库服务器的 CPU 资源。

总的来说，对于通用的、与数据紧密相关的、性能敏感的操作，使用存储过程和函数是一个不错的选择。但应避免将过多的纯业务应用逻辑放入其中。 