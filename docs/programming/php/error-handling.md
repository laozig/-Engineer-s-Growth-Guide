# PHP 错误处理与异常

健壮的应用程序需要能够优雅地处理错误和意外情况。PHP提供了多种机制来报告和处理错误，从传统的错误报告到现代的异常处理。

## 错误报告 (Error Reporting)

在PHP的早期版本中，错误处理主要通过错误报告机制来完成。
-   **`error_reporting()`**: 设置PHP应报告哪些错误。
-   **`display_errors` (php.ini指令)**: 控制是否将错误信息显示给用户。

在**开发环境**中，建议开启所有错误报告，以便及时发现和修复问题。
```php
<?php
// 在脚本开头设置
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// 这将产生一个 "Warning: Division by zero" 的警告
$result = 10 / 0; 
echo "这行代码在警告后仍然会执行。";
?>
```
在**生产环境**中，**绝对不能**将错误信息直接显示给用户，因为这可能暴露敏感信息。应该禁用`display_errors`，并将错误记录到文件中。
```ini
; 在 php.ini 中设置
display_errors = Off
log_errors = On
error_log = /var/log/php_errors.log
```

## 异常处理 (Exception Handling)

从PHP 5开始，引入了更现代的、面向对象的异常处理模型。异常处理允许你将错误处理代码与主要业务逻辑分离开，使代码更清晰。

### `try...catch` 语句
-   **`try`**: 包含可能抛出异常的代码块。
-   **`catch`**: 如果`try`块中的代码抛出了一个异常，`catch`块会捕获它并执行相应的处理代码。
-   **`finally`**: 无论是否发生异常，`finally`块中的代码总会被执行（PHP 5.5+）。

```php
<?php
function divide($numerator, $denominator) {
    if ($denominator === 0) {
        // 抛出一个新的异常
        throw new Exception("除数不能为零!");
    }
    return $numerator / $denominator;
}

try {
    echo "尝试进行除法运算...<br>";
    $result = divide(10, 0);
    echo "结果是: " . $result . "<br>"; // 这行不会执行
} catch (Exception $e) {
    // 捕获异常并处理
    echo "捕获到异常: " . $e->getMessage() . "<br>";
} finally {
    echo "这个 finally 块总会执行。<br>";
}

echo "程序继续执行...";
?>
```
与传统错误不同，未被捕获的异常会导致脚本立即终止。

## `Exception` 类

内置的`Exception`类提供了一些有用的方法来获取关于异常的详细信息：
-   **`getMessage()`**: 返回异常消息。
-   **`getCode()`**: 返回异常代码（一个整数）。
-   **`getFile()`**: 返回抛出异常的文件的完整路径。
-   **`getLine()``**: 返回抛出异常的代码在文件中的行号。
-   **`getTraceAsString()`**: 获取异常追踪信息的字符串。

```php
<?php
try {
    // ...
    throw new Exception("这是一个错误", 101);
} catch (Exception $e) {
    echo "消息: " . $e->getMessage() . "<br>";
    echo "代码: " . $e->getCode() . "<br>";
    echo "文件: " . $e->getFile() . "<br>";
    echo "行号: " . $e->getLine() . "<br>";
    // echo "<pre>" . $e->getTraceAsString() . "</pre>"; // 打印完整的堆栈跟踪
}
?>
```

## 多重 `catch` 块 (PHP 7.1+)

你可以设置多个`catch`块来捕获不同类型的异常。
```php
<?php
class NetworkException extends Exception {}
class DatabaseException extends Exception {}

try {
    // 假设这里的代码可能抛出不同类型的异常
    throw new DatabaseException("数据库连接失败");
} catch (NetworkException $e) {
    echo "网络错误: " . $e->getMessage();
} catch (DatabaseException $e) {
    echo "数据库错误: " . $e->getMessage();
} catch (Exception $e) {
    echo "未知错误: " . $e->getMessage();
}
?>
```
PHP会执行第一个匹配异常类型的`catch`块。

## `Throwable` 接口 (PHP 7+)

在PHP 7中，引入了`Throwable`接口，它是所有可以在PHP中被`throw`抛出的对象的基接口。`Exception`和`Error`都实现了`Throwable`接口。
-   **`Exception`**: 代表可在程序中正常处理的异常（如无效输入、数据库错误等）。
-   **`Error`**: 代表PHP引擎内部的错误（如调用未定义函数、内存耗尽等）。在PHP 7之前，这些是致命错误，无法被捕获。

现在，你可以捕获`Error`了，但这通常只用于记录日志或进行最后的清理工作，而不是尝试从中恢复。
```php
<?php
try {
    // 尝试调用一个不存在的函数，这将抛出一个Error
    non_existent_function();
} catch (Throwable $t) {
    // 这个catch块可以捕获Exception和Error
    echo "捕获到一个Throwable: " . $t->getMessage();
}
?>
```

## 自定义异常 (Custom Exceptions)

创建自定义异常类是一种很好的实践，它可以让你的错误处理更具描述性。自定义异常类应该继承自内置的`Exception`类。
```php
<?php
// 创建一个自定义异常类
class InvalidEmailException extends Exception {
    public function __construct($email, $code = 0, Throwable $previous = null) {
        $message = "邮箱地址 '{$email}' 无效。";
        parent::__construct($message, $code, $previous);
    }

    public function getDetailedMessage() {
        return "提供了一个格式不正确的邮箱地址。";
    }
}

function sendEmail($email, $message) {
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        throw new InvalidEmailException($email);
    }
    echo "正在向 {$email} 发送邮件...";
    // ... 发送邮件的逻辑 ...
}

try {
    sendEmail("not-an-email", "你好");
} catch (InvalidEmailException $e) {
    echo "错误: " . $e->getMessage() . "<br>";
    echo "详情: " . $e->getDetailedMessage() . "<br>";
}
?>
```

**最佳实践**:
-   在开发中，显示所有错误。
-   在生产中，隐藏错误，但记录所有错误。
-   使用`try...catch`来处理可预见的、可恢复的错误（如文件未找到、API请求失败）。
-   创建具体的自定义异常，使你的代码能够对不同类型的错误做出不同的反应。 