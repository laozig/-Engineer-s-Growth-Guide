# PHP 数据库交互 (PDO)

与数据库交互是绝大多数Web应用的核心功能。PHP提供了多种方式来连接和操作数据库，但现代PHP开发中，**PHP Data Objects (PDO)** 扩展是推荐的首选方法。

## 为什么使用PDO？

-   **可移植性/数据库无关性**: PDO提供了一个统一的数据访问抽象层。这意味着，只要你使用PDO提供的API，你就可以在不改变大量PHP代码的情况下，轻松地从一个数据库（如MySQL）切换到另一个数据库（如PostgreSQL或SQLite）。
-   **安全性**: PDO支持**预处理语句 (Prepared Statements)**，这是防止SQL注入攻击的最有效方法。
-   **功能丰富**: 支持事务、多种数据获取模式等高级功能。

## 连接到数据库

使用PDO的第一步是创建一个PDO对象，这代表了与数据库的连接。构造函数需要一个**DSN (Data Source Name)**、用户名和密码。

DSN是一个字符串，它指定了数据库驱动、主机名、数据库名等信息。

**连接到MySQL的示例:**
```php
<?php
$host = '127.0.0.1'; // 或 'localhost'
$db   = 'my_database';
$user = 'db_user';
$pass = 'db_password';
$charset = 'utf8mb4';

// Data Source Name (DSN)
$dsn = "mysql:host=$host;dbname=$db;charset=$charset";

// PDO 连接选项
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION, // 推荐：在出错时抛出异常
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,       // 推荐：默认以关联数组形式返回结果
    PDO::ATTR_EMULATE_PREPARES   => false,                  // 推荐：禁用模拟预处理，使用真正的预处理
];

try {
     $pdo = new PDO($dsn, $user, $pass, $options);
     echo "数据库连接成功!";
} catch (\PDOException $e) {
     // 抛出PDOException，而不是普通的Exception
     throw new \PDOException($e->getMessage(), (int)$e->getCode());
}
?>
```
将数据库连接代码放在`try...catch`块中是一个好习惯。我们还将PDO的错误模式设置为`PDO::ERRMODE_EXCEPTION`，这样当数据库操作出错时，PDO会抛出一个`PDOException`，我们可以捕获并处理它。

## 执行查询

### 简单查询 (不推荐用于带变量的查询)
对于不包含任何用户输入的、静态的查询，可以使用`query()`方法。
```php
<?php
// ... 假设 $pdo 已连接 ...
$stmt = $pdo->query('SELECT name FROM users');

while ($row = $stmt->fetch()) {
    echo $row['name'] . "<br>";
}
?>
```

### 执行 INSERT, UPDATE, DELETE
对于没有结果集的写操作，可以使用`exec()`方法。它返回受影响的行数。
```php
<?php
// ... 假设 $pdo 已连接 ...
$sql = "UPDATE users SET email = 'new.email@example.com' WHERE id = 1";
$affectedRows = $pdo->exec($sql);
echo $affectedRows . " 行被更新。";
?>
```
**警告**: `query()`和`exec()`都不应该直接用于包含变量（尤其是用户输入）的SQL语句，因为这会使你的应用容易受到SQL注入攻击。对于这种情况，**必须使用预处理语句**。

## 预处理语句 (Prepared Statements)

预处理语句是防止SQL注入的关键。它的工作原理是将SQL查询和数据分开传输到数据库服务器。

1.  **准备 (Prepare)**: 发送一个不包含具体值的SQL查询模板到数据库。
2.  **绑定 (Bind)**: 将变量绑定到查询模板中的占位符。
3.  **执行 (Execute)**: 执行查询。

这样，用户输入的数据永远不会被当作可执行的SQL代码，从而杜绝了SQL注入的风险。

### 使用方法

```php
<?php
// ... 假设 $pdo 已连接 ...

// 1. 准备SQL语句，使用命名占位符 (如 :id)
$sql = "SELECT id, name, email FROM users WHERE id = :id";
$stmt = $pdo->prepare($sql);

// 2. 绑定参数并执行
$user_id = 1;
$stmt->execute(['id' => $user_id]);

// 3. 获取结果
$user = $stmt->fetch(); // 获取单行结果

if ($user) {
    echo "ID: " . $user['id'] . ", 姓名: " . $user['name'];
} else {
    echo "未找到用户。";
}
?>
```

### 绑定参数的方式

-   **在`execute()`中传递数组**: 如上例所示，这是最简洁、最常用的方式。
-   **使用`bindParam()`**: 将一个变量的引用绑定到一个参数。
-   **使用`bindValue()`**: 将一个具体的值绑定到一个参数。

**使用 `bindParam()`:**
```php
<?php
$stmt = $pdo->prepare("INSERT INTO users (name, email) VALUES (:name, :email)");

$name = 'John Doe';
$email = 'john.doe@example.com';

$stmt->bindParam(':name', $name);
$stmt->bindParam(':email', $email);

$stmt->execute();

// 改变变量的值，可以再次执行
$name = 'Jane Doe';
$email = 'jane.doe@example.com';
$stmt->execute();
?>
```
`bindParam()`在`execute()`被调用时才获取变量的值。

## 获取数据 (Fetching Data)

`PDOStatement`对象（由`query()`或`prepare()`返回）提供了多种方法来获取查询结果。

-   **`fetch()`**: 获取结果集中的下一行。
-   **`fetchAll()`**: 获取结果集中所有剩余的行，返回一个数组。

### Fetch 模式
`fetch()`和`fetchAll()`可以接受一个参数来指定返回数据的格式。
-   **`PDO::FETCH_ASSOC`**: 返回一个以列名为键的关联数组。
    `['name' => 'John', 'email' => 'john@example.com']`
-   **`PDO::FETCH_OBJ`**: 返回一个匿名对象，其属性名对应于列名。
    `$row->name`
-   **`PDO::FETCH_NUM`**: 返回一个以列号为索引的数组。
    `[0 => 'John', 1 => 'john@example.com']`
-   **`PDO::FETCH_CLASS`**: 返回一个指定类的新实例，将结果集的列映射到类的属性。

**`fetchAll()` 示例:**
```php
<?php
$stmt = $pdo->query('SELECT name, email FROM users LIMIT 5');

// 获取所有用户到一个关联数组中
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);

foreach ($users as $user) {
    echo $user['name'] . ' - ' . $user['email'] . '<br>';
}
?>
```
**注意**: `fetchAll()`会一次性将所有结果加载到内存中，对于非常大的结果集，可能会消耗大量内存。在这种情况下，最好使用`while`循环和`fetch()`来逐行处理。

## 事务 (Transactions)

事务是一组需要全部成功执行或全部不执行的SQL操作。例如，在银行转账中，从一个账户扣款和向另一个账户存款必须同时成功。

1.  **`beginTransaction()`**: 开始一个事务。
2.  **`commit()`**: 提交事务，将所有更改永久保存到数据库。
3.  **`rollBack()`**: 回滚事务，撤销自事务开始以来所做的所有更改。

```php
<?php
try {
    $pdo->beginTransaction();

    $pdo->exec("UPDATE accounts SET balance = balance - 100 WHERE id = 1");
    $pdo->exec("UPDATE accounts SET balance = balance + 100 WHERE id = 2");

    $pdo->commit();
    echo "转账成功!";
} catch (Exception $e) {
    $pdo->rollBack();
    echo "转账失败: " . $e->getMessage();
}
?>
```
PDO为PHP提供了一个安全、高效且灵活的数据库操作接口，是现代PHP应用开发的首选。 