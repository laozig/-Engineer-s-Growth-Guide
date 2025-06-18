# PHP 函数 (Functions)

函数是一段可重用的代码块，它执行特定的任务。函数可以接受输入（参数）并返回一个值。在PHP中，有数千个内置函数，同时你也可以创建自己的函数。

## 定义和调用函数

### 用户定义函数

使用 `function` 关键字来创建一个新函数。函数名应遵循与变量相同的规则，但不区分大小写。

**语法:**
```php
function functionName($param1, $param2, ...) {
    // 要执行的代码
    return $value; // 可选的返回语句
}
```

**示例:**
```php
<?php
// 定义一个不带参数的函数
function sayHello() {
    echo "你好, PHP!<br>";
}

// 定义一个带参数的函数
function greetUser($name) {
    echo "你好, $name!<br>";
}

// 调用函数
sayHello();       // 输出: 你好, PHP!
greetUser("Alice"); // 输出: 你好, Alice!
greetUser("Bob");   // 输出: 你好, Bob!
?>
```

## 函数参数 (Arguments)

信息可以通过参数传递给函数，参数在函数名后的括号内声明。

### 1. 按值传递 (Pass by Value)

这是默认方式。函数内部对参数值的任何更改都不会影响函数外部的原始变量。
```php
<?php
function addFive($number) {
    $number += 5;
}

$original_num = 10;
addFive($original_num);
echo $original_num; // 输出: 10 (原始值未改变)
?>
```

### 2. 按引用传递 (Pass by Reference)

如果你希望函数能够修改其参数，必须在参数名前加上 `&` 符号。
```php
<?php
function addTen(&$number) {
    $number += 10;
}

$original_num = 10;
addTen($original_num);
echo $original_num; // 输出: 20 (原始值被改变)
?>
```

### 3. 默认参数值

你可以为参数指定一个默认值。如果调用函数时没有提供该参数的值，则会使用默认值。
```php
<?php
function setHeight($min_height = 50) {
    echo "高度是: $min_height <br>";
}

setHeight(350); // 输出: 高度是: 350
setHeight();    // 输出: 高度是: 50 (使用默认值)
?>
```

## 返回值 (Return Values)

函数可以使用 `return` 语句返回一个值。`return`会立即中止函数的执行并将值返回给调用方。
```php
<?php
function sum($x, $y) {
    $z = $x + $y;
    return $z;
}

$result = sum(5, 10);
echo "5 + 10 = " . $result; // 输出: 5 + 10 = 15
?>
```
一个函数可以返回任何类型的数据，包括数组和对象。

## 类型声明 (Type Declarations)

自PHP 7起，你可以为函数参数和返回值指定类型。这有助于提高代码的健壮性和可读性。
-   **参数类型声明 (Argument Type Hinting)**
-   **返回类型声明 (Return Type Hinting)**

```php
<?php
// declare(strict_types=1); // 开启严格模式

function add(float $a, float $b) : float {
    return $a + $b;
}

// echo add(5, "5 days"); // 在严格模式下会抛出致命错误
echo add(5.2, 3.1); // 输出: 8.3
?>
```
`declare(strict_types=1);` 必须放在文件的第一行。在严格模式下，PHP要求值与类型声明完全匹配；在弱模式（默认）下，它会尝试进行类型转换。

## 变量作用域 (Variable Scope)

作用域是指一个变量可以被访问的范围。

-   **`local` (局部作用域)**:
    在函数内部声明的变量只能在该函数内部访问。
    ```php
    <?php
    function myFunc() {
        $x = 5; // 局部变量
        echo "函数内部的变量 x 是: $x";
    }
    myFunc();
    // echo "函数外部的变量 x 是: $x"; // 会产生错误，因为$x未定义
    ?>
    ```

-   **`global` (全局作用域)**:
    在函数外部声明的变量拥有全局作用域，但默认情况下在函数内部无法直接访问。要在一个函数中访问一个全局变量，需要使用 `global` 关键字。
    ```php
    <?php
    $y = 10; // 全局变量

    function myOtherFunc() {
        global $y;
        echo "函数内部的变量 y 是: $y";
    }
    myOtherFunc(); // 输出: 函数内部的变量 y 是: 10
    ?>
    ```
    PHP将所有全局变量存储在一个名为 `$GLOBALS` 的数组中。你也可以用 `$GLOBALS['y']` 来访问它。

-   **`static` (静态作用域)**:
    当一个函数执行完毕后，其所有局部变量都会被删除。如果你希望某个局部变量在函数调用结束后不被删除，可以在第一次声明它时使用 `static` 关键字。
    ```php
    <?php
    function visitCounter() {
        static $count = 0;
        $count++;
        echo $count . "<br>";
    }

    visitCounter(); // 输出: 1
    visitCounter(); // 输出: 2
    visitCounter(); // 输出: 3
    ?>
    ```

## 匿名函数 (Anonymous Functions / Closures)

匿名函数，也称为闭包 (Closures)，是没有函数名称的函数。它们对于作为回调函数或一次性任务非常有用。
```php
<?php
// 将一个闭包赋给变量
$say = function($name) {
    echo "你好, " . $name;
};

$say("世界"); // 输出: 你好, 世界

// 从父作用域继承变量
$message = "这是一个消息。";
$closure = function() use ($message) {
    echo $message;
};
$closure(); // 输出: 这是一个消息。
?>
```

## 箭头函数 (Arrow Functions) (PHP 7.4+)

箭头函数为编写单行匿名函数提供了一种更简洁的语法。它们可以自动访问父作用域的变量，无需使用 `use` 关键字。

**语法:** `fn(parameters) => expression`

```php
<?php
$numbers = [1, 2, 3, 4, 5];
$multiplier = 10;

// 使用箭头函数
$multiplied_numbers = array_map(
    fn($n) => $n * $multiplier,
    $numbers
);

print_r($multiplied_numbers);
// 输出: Array ( [0] => 10 [1] => 20 [2] => 30 [3] => 40 [4] => 50 )
?>
```
这在需要向 `array_map`, `array_filter` 等函数传递简单回调时非常方便。 