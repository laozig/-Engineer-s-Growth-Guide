# PHP 数组 (Arrays)

在PHP中，数组是一种非常强大和灵活的数据结构。它是一个有序的映射（map），可以将值（value）与键（key）关联起来。数组可以用来在一个变量中存储多个值。

## 数组类型

PHP支持三种类型的数组：
1.  **索引数组 (Indexed arrays)**: 使用数字索引的数组。
2.  **关联数组 (Associative arrays)**: 使用命名的键的数组。
3.  **多维数组 (Multidimensional arrays)**: 包含一个或多个其他数组的数组。

## 创建数组

### 1. 使用 `array()` 结构
```php
<?php
// 索引数组
$cars = array("Volvo", "BMW", "Toyota");

// 关联数组
$user = array("name" => "John", "age" => 30, "email" => "john@example.com");
?>
```

### 2. 使用短数组语法 `[]` (自PHP 5.4起)
这是现代PHP代码中推荐的、更简洁的语法。
```php
<?php
// 索引数组
$fruits = ["Apple", "Banana", "Orange"];

// 关联数组
$person = [
    "first_name" => "Jane",
    "last_name" => "Doe",
    "city" => "New York"
];
?>
```

## 访问数组元素

通过在方括号 `[]` 中指定键或索引来访问数组元素。
```php
<?php
$fruits = ["Apple", "Banana", "Orange"];
echo $fruits[0]; // 输出: Apple

$person = ["first_name" => "Jane", "last_name" => "Doe"];
echo $person["first_name"]; // 输出: Jane
?>
```

## 遍历数组

最常用、最方便的遍历数组的方法是使用 `foreach` 循环。

```php
<?php
// 遍历索引数组的值
$colors = ["Red", "Green", "Blue"];
foreach ($colors as $color) {
    echo $color . "<br>";
}

// 遍历关联数组的键和值
$user_age = ["Peter" => 35, "Ben" => 37, "Joe" => 43];
foreach ($user_age as $name => $age) {
    echo "$name is $age years old.<br>";
}
?>
```

## 常用数组函数

PHP提供了一套丰富的内置函数来操作数组。

### 1. 获取数组大小
-   **`count()`**: 返回数组中元素的数量。
    ```php
    <?php
    $fruits = ["Apple", "Banana", "Orange"];
    echo count($fruits); // 输出: 3
    ?>
    ```

### 2. 添加和移除元素
-   **`array_push()`**: 在数组的末尾添加一个或多个元素。
    ```php
    <?php
    $stack = ["orange", "banana"];
    array_push($stack, "apple", "raspberry");
    print_r($stack); // Array ( [0] => orange [1] => banana [2] => apple [3] => raspberry )
    ?>
    ```
-   **`array_pop()`**: 弹出并返回数组的最后一个元素。
    ```php
    <?php
    $stack = ["orange", "banana", "apple"];
    $fruit = array_pop($stack);
    echo $fruit; // 输出: apple
    print_r($stack); // Array ( [0] => orange [1] => banana )
    ?>
    ```
-   **`array_unshift()`**: 在数组的开头插入一个或多个元素。
-   **`array_shift()`**: 移除并返回数组的第一个元素。

### 3. 排序数组

PHP提供了多种函数来对数组进行排序。
-   **`sort()`**: 对索引数组按值升序排序。
-   **`rsort()`**: 对索引数组按值降序排序。
-   **`asort()`**: 对关联数组按值升序排序，并保持键值关联。
-   **`ksort()`**: 对关联数组按键升序排序。
-   **`arsort()`**: 对关联数组按值降序排序，并保持键值关联。
-   **`krsort()`**: 对关联数组按键降序排序。

**示例:**
```php
<?php
// sort() - 索引数组
$numbers = [4, 6, 2, 22, 11];
sort($numbers);
print_r($numbers); // Array ( [0] => 2 [1] => 4 [2] => 6 [3] => 11 [4] => 22 )

// asort() - 关联数组
$age = ["Peter" => 35, "Ben" => 37, "Joe" => 43];
asort($age);
print_r($age); // Array ( [Peter] => 35 [Ben] => 37 [Joe] => 43 )
?>
```

### 4. 检查与搜索
-   **`in_array()`**: 检查数组中是否存在某个值。
    ```php
    <?php
    $people = ["Peter", "Joe", "Glenn", "Cleveland"];
    if (in_array("Glenn", $people)) {
        echo "Match found";
    }
    ?>
    ```
-   **`array_key_exists()`**: 检查数组中是否存在指定的键。
-   **`array_search()`**: 在数组中搜索给定的值，如果成功则返回相应的键。

### 5. 数组转换与迭代
-   **`array_map()`**: 对数组的每个元素应用一个回调函数，并返回一个包含新值的新数组。
    ```php
    <?php
    function doubleNumber($n) {
        return $n * 2;
    }
    $numbers = [1, 2, 3, 4, 5];
    $doubled = array_map('doubleNumber', $numbers);
    print_r($doubled); // Array ( [0] => 2 [1] => 4 [2] => 6 [3] => 8 [4] => 10 )
    ?>
    ```
-   **`array_filter()`**: 使用回调函数过滤数组中的元素。
    ```php
    <?php
    $numbers = [1, 2, 3, 4, 5, 6];
    $even = array_filter($numbers, fn($n) => $n % 2 == 0);
    print_r($even); // Array ( [1] => 2 [3] => 4 [5] => 6 ) (注意键名被保留)
    ?>
    ```
-   **`array_reduce()`**: 使用回调函数将数组迭代地简化为单一的值。
-   **`array_keys()`**: 返回数组中所有的键。
-   **`array_values()`**: 返回数组中所有的值。

## 多维数组

多维数组是包含其他数组的数组。它允许我们存储更复杂的数据结构，例如表格数据。

```php
<?php
$students = [
    [
        "name" => "Alice",
        "age" => 20,
        "major" => "Computer Science"
    ],
    [
        "name" => "Bob",
        "age" => 22,
        "major" => "Mathematics"
    ],
    [
        "name" => "Charlie",
        "age" => 21,
        "major" => "Physics"
    ]
];

// 访问多维数组的元素
echo $students[1]["name"]; // 输出: Bob

// 遍历多维数组
foreach ($students as $student) {
    echo "Name: " . $student["name"] . ", Age: " . $student["age"] . "<br>";
}
?>
```
数组是PHP中最重要、最常用的数据结构之一。熟练掌握数组及其操作函数对于高效的PHP编程至关重要。 