# PHP 控制结构

控制结构是编程语言中用于控制代码执行流程的部分。它们允许你根据特定条件执行代码块，或者重复执行代码块。PHP拥有与C语言类似的丰富控制结构。

## 条件语句 (Conditional Statements)

### 1. `if` 语句
如果条件为真，则执行代码块。
```php
<?php
$hour = date('H'); // 获取当前小时 (24小时制)

if ($hour < 18) {
    echo "祝您有美好的一天!";
}
?>
```

### 2. `if...else` 语句
如果条件为真，执行一个代码块；如果条件为假，执行另一个代码块。
```php
<?php
$age = 20;

if ($age >= 18) {
    echo "你是成年人。";
} else {
    echo "你是未成年人。";
}
?>
```

### 3. `if...elseif...else` 语句
用于检查多个条件。
```php
<?php
$score = 85;

if ($score >= 90) {
    echo "优秀 (A)";
} elseif ($score >= 80) {
    echo "良好 (B)";
} elseif ($score >= 70) {
    echo "中等 (C)";
} elseif ($score >= 60) {
    echo "及格 (D)";
} else {
    echo "不及格 (F)";
}
?>
```

### 4. `switch` 语句
用于替代包含多个 `elseif` 的语句，使代码更清晰。它将一个变量的值与多个可能的值进行比较。
```php
<?php
$favorite_color = "red";

switch ($favorite_color) {
    case "red":
        echo "你最喜欢的颜色是红色!";
        break; // break 防止代码继续执行到下一个case
    case "blue":
        echo "你最喜欢的颜色是蓝色!";
        break;
    case "green":
        echo "你最喜欢的颜色是绿色!";
        break;
    default: // 如果没有匹配的case，则执行default
        echo "你最喜欢的颜色既不是红、蓝，也不是绿色!";
}
?>
```

## 循环语句 (Loop Statements)

循环用于重复执行一个代码块，直到满足特定条件。

### 1. `while` 循环
只要指定的条件为真，就会循环执行代码块。
```php
<?php
$i = 1;

while ($i <= 5) {
    echo "数字是 " . $i . "<br>";
    $i++; // 重要的是要有一个改变循环条件的语句，否则会造成死循环
}
?>
```

### 2. `do...while` 循环
这个循环会**至少执行一次**代码块，然后在每次迭代结束时检查条件，如果条件为真，则继续循环。
```php
<?php
$i = 8;

do {
    echo "数字是 " . $i . "<br>";
    $i++;
} while ($i <= 5); // 条件为假，但代码块已执行一次
?>
```
在这个例子中，即使`$i`的初始值`8`不满足条件`$i <= 5`，代码块也执行了一次。

### 3. `for` 循环
当你预先知道代码块应该运行的次数时，使用`for`循环。
它有三个主要部分：
-   **初始化**: 在循环开始前执行一次（例如 `$i = 0;`）。
-   **条件**: 在每次循环迭代前检查。如果为真，则执行循环。
-   **增量**: 在每次循环迭代后执行（例如 `$i++`）。

```php
<?php
for ($i = 0; $i < 10; $i++) {
    echo "数字是 " . $i . "<br>";
}
?>
```

### 4. `foreach` 循环
`foreach` 循环专门用于遍历数组和对象。这是处理数组最简单、最推荐的方式。

**遍历值:**
```php
<?php
$colors = ["red", "green", "blue", "yellow"];

foreach ($colors as $color) {
    echo $color . "<br>";
}
?>
```

**遍历键和值:**
```php
<?php
$user = [
    "name" => "John Doe",
    "email" => "john.doe@example.com",
    "age" => 30
];

foreach ($user as $key => $value) {
    echo ucfirst($key) . ": " . $value . "<br>";
}
?>
```

## 流程控制关键字

### `break`
`break` 用于立即跳出当前的 `for`, `foreach`, `while`, `do-while` 或 `switch` 结构。

```php
<?php
for ($i = 0; $i < 10; $i++) {
    if ($i == 4) {
        break; // 当 $i 等于 4 时，终止循环
    }
    echo "数字是 " . $i . "<br>";
}
// 输出 0, 1, 2, 3
?>
```

### `continue`
`continue` 用于跳过当前循环的剩余部分，并开始下一次迭代。

```php
<?php
for ($i = 0; $i < 10; $i++) {
    if ($i % 2 == 0) {
        continue; // 如果 $i 是偶数，跳过本次迭代
    }
    echo $i . "<br>"; // 只会输出奇数
}
// 输出 1, 3, 5, 7, 9
?>
```

## `match` 表达式 (PHP 8.0+)
PHP 8.0 引入了`match`表达式，它是`switch`语句的一个更强大、更安全的替代品。

-   `match`是表达式，它的结果可以赋给一个变量。
-   它进行严格类型比较（`===`），而`switch`使用松散比较（`==`）。
-   它不需要`break`语句。
-   它必须是详尽的；如果输入值没有匹配的分支，它会抛出一个`UnhandledMatchError`错误（除非有`default`分支）。

```php
<?php
$http_status = 200;

$message = match ($http_status) {
    200, 201 => '成功',
    301, 302 => '重定向',
    404 => '未找到',
    500 => '服务器错误',
    default => '未知状态',
};

echo $message; // 输出: 成功
?>
```
`match`表达式使代码更简洁、更具可读性，并且由于其严格的行为而更不容易出错。 