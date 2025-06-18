# PHP 变量与数据类型

变量是用于存储信息的"容器"，例如字符串、数字或数组。数据类型是指变量可以存储的数据种类。PHP是一种弱类型语言，这意味着你不需要在声明变量时指定其数据类型，PHP会根据变量的值自动进行转换。

## 变量 (Variables)

### 1. 声明变量

在PHP中，变量以 `$` 符号开头，后跟变量的名称。
```php
<?php
$myVariable = "你好, PHP!";
$number = 100;
$floatNumber = 3.14;
?>
```

### 2. 变量命名规则

-   变量名必须以美元符号 `$` 开头。
-   `$` 之后，名称必须以字母或下划线 `_` 开头。
-   名称不能以数字开头。
-   名称只能包含字母、数字和下划线 (A-z, 0-9, and _)。
-   变量名是**区分大小写**的 (`$name` 和 `$NAME` 是两个不同的变量)。

```php
<?php
// 合法的变量名
$name = "John";
$_age = 25;
$user_email = "john@example.com";
$user2 = "Jane";

// 非法的变量名
// $2user = "Invalid"; // 不能以数字开头
// $user-name = "Invalid"; // 不能包含连字符
?>
```

### 3. 变量赋值

-   **按值赋值 (Assignment by Value)**: 这是默认方式。当你将一个变量赋给另一个变量时，PHP会复制原始变量的值。
    ```php
    <?php
    $x = 10;
    $y = $x; // $y是$x的一个副本
    $y = 20; // 修改$y不会影响$x
    echo $x; // 输出 10
    ?>
    ```

-   **按引用赋值 (Assignment by Reference)**: 如果你想让两个变量指向同一个值，可以在赋值时使用 `&` 符号。修改其中一个变量会影响另一个。
    ```php
    <?php
    $a = 10;
    $b = &$a; // $b是$a的一个引用
    $b = 20; // 修改$b会影响$a
    echo $a; // 输出 20
    ?>
    ```

## PHP数据类型

PHP支持以下数据类型：

### 1. 标量类型 (Scalar Types)

标量类型是只包含单个值的类型。

-   **`string` (字符串)**: 
    一系列字符，可以使用单引号 (`'`) 或双引号 (`"`) 包含。
    -   单引号字符串按字面意义解析。
    -   双引号字符串会解析其中的变量和转义序列（如`\n`, `\t`）。
    ```php
    <?php
    $name = 'PHP';
    $single_quoted = '你好, $name!'; // 输出: 你好, $name!
    $double_quoted = "你好, $name!"; // 输出: 你好, PHP!
    echo $single_quoted;
    echo "<br>";
    echo $double_quoted;
    ?>
    ```

-   **`integer` (整数)**:
    没有小数部分的数字。可以是正数或负数。
    ```php
    <?php
    $int1 = 123;   // 十进制
    $int2 = -45;   // 负数
    $int3 = 0x1A;  // 十六进制 (等于 26)
    $int4 = 0123;  // 八进制 (等于 83)
    ?>
    ```

-   **`float` (浮点数，也称 `double`)**:
    带小数部分的数字，或指数形式的数字。
    ```php
    <?php
    $pi = 3.14159;
    $e = 2.718e3; // 2.718 * 10^3
    ?>
    ```

-   **`boolean` (布尔型)**:
    表示两个可能的状态：`true` 或 `false`。常用于条件判断。
    ```php
    <?php
    $is_active = true;
    $is_logged_in = false;
    ?>
    ```

### 2. 复合类型 (Compound Types)

复合类型可以存储多个值。

-   **`array` (数组)**:
    在一个变量中存储多个值的有序集合。
    ```php
    <?php
    // 索引数组
    $colors = array("Red", "Green", "Blue");
    $fruits = ["Apple", "Banana", "Orange"]; // 短数组语法 (推荐)
    echo $fruits[0]; // 输出: Apple

    // 关联数组
    $user = [
        "name" => "John Doe",
        "email" => "john.doe@example.com",
        "age" => 30
    ];
    echo $user["email"]; // 输出: john.doe@example.com
    ?>
    ```

-   **`object` (对象)**:
    对象是类的实例，可以包含属性（变量）和方法（函数）。
    ```php
    <?php
    class Car {
        public $color;
        public function __construct($color) {
            $this->color = $color;
        }
        public function displayColor() {
            return "This car is " . $this->color;
        }
    }

    $myCar = new Car("red");
    echo $myCar->displayColor(); // 输出: This car is red
    ?>
    ```

-   **`callable` (可调用)**:
    可以像函数一样被调用的变量。
    ```php
    <?php
    $myFunction = function($text) {
        echo $text;
    };
    $myFunction('Hello from a callable!');
    ?>
    ```
    
-   **`iterable` (可迭代)**:
    任何可以用 `foreach` 循环遍历的值，主要是数组和实现了 `Traversable` 接口的对象。

### 3. 特殊类型 (Special Types)

-   **`null` (空)**:
    表示一个变量没有值。`null` 是 `NULL` 类型唯一可能的值。
    ```php
    <?php
    $empty_var = null;
    $undefined_var; // 未赋值的变量也会被认为是null

    var_dump($empty_var); // 输出: NULL
    ?>
    ```

-   **`resource` (资源)**:
    一种特殊的变量，用于保存到外部资源（如数据库连接、文件句柄）的引用。

## 类型戏法 (Type Juggling)

PHP会根据上下文自动转换变量类型。
```php
<?php
$foo = "10"; // $foo 是一个字符串
$bar = $foo + 5; // PHP会自动将$foo转换为整数进行计算
echo $bar; // 输出: 15 (整数)
echo gettype($bar); // 输出: integer
?>
```

## 类型转换 (Type Casting)

你也可以在变量前使用括号来强制转换类型。
```php
<?php
$score_str = "123.45";
$score_int = (int) $score_str;
$score_float = (float) $score_str;

echo $score_int;   // 输出: 123
echo "<br>";
echo $score_float; // 输出: 123.45
?>
```
可用的转换类型包括：`(int)`, `(bool)`, `(float)`, `(string)`, `(array)`, `(object)`。

## 调试工具

-   **`gettype()`**: 返回变量的类型。
-   **`var_dump()`**: 打印变量的类型、值和长度等详细信息。这是调试时最常用的工具之一。
-   **`print_r()`**: 以易于理解的方式打印变量信息，特别是数组和对象。

```php
<?php
$data = ["PHP", 8, true];
var_dump($data);
echo "<hr>";
print_r($data);
?>
``` 