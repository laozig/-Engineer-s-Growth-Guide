# 10. 常用函数 (Common Functions)

SQL 提供了大量的内置函数，用于处理字符串、数值和日期等数据类型。熟练使用这些函数可以极大地简化数据处理和查询的复杂度。

## 字符串函数 (String Functions)

这些函数用于操作字符串。

- **`CONCAT(str1, str2, ...)`**: 连接两个或多个字符串。
  ```sql
  SELECT CONCAT(first_name, ' ', last_name) AS full_name FROM employees;
  ```
- **`CONCAT_WS(separator, str1, str2, ...)`**: 使用指定的分隔符连接字符串。
  ```sql
  SELECT CONCAT_WS(', ', last_name, first_name) AS name_csv FROM employees;
  ```
- **`LENGTH(str)`**: 返回字符串的字节长度。
- **`CHAR_LENGTH(str)`** 或 **`CHARACTER_LENGTH(str)`**: 返回字符串的字符数（对于多字节字符集如 `utf8mb4`，这比 `LENGTH` 更准确）。
  ```sql
  SELECT name, LENGTH(name), CHAR_LENGTH(name) FROM departments;
  ```
- **`UPPER(str)`** 或 **`UCASE(str)`**: 将字符串转换为大写。
- **`LOWER(str)`** 或 **`LCASE(str)`**: 将字符串转换为小写。
  ```sql
  SELECT UPPER('Hello World'); -- 'HELLO WORLD'
  ```
- **`SUBSTRING(str, pos, len)`** 或 **`SUBSTR(str, pos, len)`**: 提取子字符串。`pos` 是起始位置（从 1 开始）。
  ```sql
  SELECT SUBSTRING('MySQL is fun', 1, 5); -- 'MySQL'
  ```
- **`TRIM([{BOTH | LEADING | TRAILING} [remstr] FROM] str)`**: 去除字符串两端或指定端的空格或特定字符。
  ```sql
  SELECT TRIM('  hello  '); -- 'hello'
  SELECT TRIM(LEADING 'x' FROM 'xxxhellobcxxx'); -- 'hellobcxxx'
  ```
- **`REPLACE(str, from_str, to_str)`**: 替换字符串中所有出现的子串。
  ```sql
  SELECT REPLACE('I love SQL', 'SQL', 'MySQL'); -- 'I love MySQL'
  ```
- **`LOCATE(substr, str, [pos])`** 或 **`POSITION(substr IN str)`**: 查找子串在字符串中首次出现的位置。
  ```sql

  SELECT LOCATE('fun', 'MySQL is fun'); -- 10
  ```
- **`LPAD(str, len, padstr)`** 和 **`RPAD(str, len, padstr)`**: 左/右填充字符串到指定长度。
  ```sql
  SELECT LPAD('5', 3, '0'); -- '005'
  ```

## 数值函数 (Numeric Functions)

这些函数用于执行数学运算。

- **`ROUND(X, [D])`**: 四舍五入到指定的小数位数 `D`（默认为 0）。
  ```sql
  SELECT ROUND(123.456, 2); -- 123.46
  SELECT ROUND(123.456);   -- 123
  ```
- **`CEIL(X)`** 或 **`CEILING(X)`**: 向上取整，返回大于或等于 `X` 的最小整数。
- **`FLOOR(X)`**: 向下取整，返回小于或等于 `X` 的最大整数。
  ```sql
  SELECT CEIL(45.1);  -- 46
  SELECT FLOOR(45.9); -- 45
  ```
- **`ABS(X)`**: 返回 `X` 的绝对值。
- **`MOD(N, M)`** 或 **`N % M`**: 取模运算，返回 `N` 除以 `M` 的余数。
  ```sql
  SELECT MOD(10, 3); -- 1
  ```
- **`RAND()`**: 生成一个 0 到 1 之间的随机浮点数。
  ```sql
  -- 获取一个随机员工
  SELECT * FROM employees ORDER BY RAND() LIMIT 1;
  ```
- **`POW(X, Y)`** 或 **`POWER(X, Y)`**: 返回 `X` 的 `Y` 次方。
- **`SQRT(X)`**: 返回 `X` 的平方根。

## 日期和时间函数 (Date and Time Functions)

这些函数用于处理日期和时间值。

- **`NOW()`**: 返回当前的日期和时间 (`YYYY-MM-DD HH:MM:SS`)。
- **`CURDATE()`**: 返回当前的日期 (`YYYY-MM-DD`)。
- **`CURTIME()`**: 返回当前的时间 (`HH:MM:SS`)。
- **`DATE(expr)`**: 提取日期或日期时间表达式的日期部分。
- **`TIME(expr)`**: 提取日期时间表达式的时间部分。
- **`YEAR(date)`, `MONTH(date)`, `DAY(date)`**: 分别提取年、月、日。
  ```sql
  SELECT YEAR(hire_date), MONTH(hire_date) FROM employees;
  ```
- **`DATE_FORMAT(date, format)`**: 将日期按指定格式格式化为字符串。
  ```sql
  -- 格式化为 'Mon dd, yyyy'
  SELECT DATE_FORMAT(hire_date, '%b %d, %Y') FROM employees;
  ```
  **常用格式符**:
    - `%Y`: 四位年份 (e.g., 2023)
    - `%y`: 两位年份 (e.g., 23)
    - `%m`: 月份 (01-12)
    - `%b`: 缩写月份名 (Jan, Feb, ...)
    - `%M`: 完整月份名 (January, February, ...)
    - `%d`: 月份中的天数 (01-31)
    - `%H`: 24 小时制小时 (00-23)
    - `%h` or `%I`: 12 小时制小时 (01-12)
    - `%i`: 分钟 (00-59)
    - `%s`: 秒 (00-59)
    - `%p`: AM 或 PM

- **`DATEDIFF(date1, date2)`**: 返回两个日期之间的天数 (`date1` - `date2`)。
  ```sql
  SELECT DATEDIFF(CURDATE(), '2023-01-01');
  ```
- **`DATE_ADD(date, INTERVAL expr unit)`** 和 **`DATE_SUB(date, INTERVAL expr unit)`**: 在日期上增加或减少一个时间间隔。
  ```sql
  -- 找到 30 天前入职的员工
  SELECT * FROM employees WHERE hire_date = DATE_SUB(CURDATE(), INTERVAL 30 DAY);

  -- 计算下个月的今天
  SELECT DATE_ADD(CURDATE(), INTERVAL 1 MONTH);
  ```

## 控制流函数 (Control Flow Functions)

- **`IF(expr1, expr2, expr3)`**: 如果 `expr1` 为真，返回 `expr2`，否则返回 `expr3`。
  ```sql
  SELECT first_name, IF(salary > 70000, 'High', 'Normal') AS salary_level FROM employees;
  ```
- **`IFNULL(expr1, expr2)`**: 如果 `expr1` 不为 `NULL`，返回 `expr1`，否则返回 `expr2`。
  ```sql
  SELECT name, IFNULL(department_id, 'N/A') FROM departments;
  ```
- **`NULLIF(expr1, expr2)`**: 如果 `expr1` 等于 `expr2`，返回 `NULL`，否则返回 `expr1`。
- **`CASE ... WHEN ... THEN ... ELSE ... END`**: 复杂的条件逻辑，类似于编程语言中的 `switch` 或 `if/elif/else`。
  ```sql
  SELECT first_name, salary,
      CASE
          WHEN salary > 100000 THEN 'Executive'
          WHEN salary > 70000 THEN 'Senior'
          WHEN salary > 50000 THEN 'Junior'
          ELSE 'Intern'
      END AS seniority_level
  FROM employees;
  ```

这些常用函数是 SQL 查询中不可或缺的工具。灵活地组合使用它们，可以让你用简洁的语句完成复杂的任务。 