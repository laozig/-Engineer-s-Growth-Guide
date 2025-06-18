# C 语言：控制流程

控制流程结构是编程语言的骨架，它允许程序根据不同的条件执行不同的代码路径，或者重复执行某段代码。C 语言主要提供以下几种控制流程结构：

- **条件语句**: `if`, `if-else`, `switch`
- **循环语句**: `for`, `while`, `do-while`
- **跳转语句**: `break`, `continue`, `goto`

## 1. 条件语句

### `if` 语句

`if` 语句用于在满足某个条件时执行一段代码。如果条件表达式的值为非零（即 `true`），则执行 `if` 后的代码块。

**语法:**
```c
if (condition) {
    // 如果 condition 为 true，则执行这里的代码
}
```

**示例:**
```c
int score = 85;
if (score >= 60) {
    printf("恭喜，考试及格了！\n");
}
```

### `if-else` 语句

`if-else` 语句在条件为 `true` 时执行一个代码块，在条件为 `false` 时执行另一个代码块。

**语法:**
```c
if (condition) {
    // 如果 condition 为 true，执行这里
} else {
    // 如果 condition 为 false，执行这里
}
```

**示例:**
```c
int temperature = 15;
if (temperature > 25) {
    printf("今天很热，适合穿短袖。\n");
} else {
    printf("天气有点凉，建议穿外套。\n");
}
```

### `if-else if-else` 链

当有多个互斥的条件需要判断时，可以使用 `if-else if-else` 结构。

**语法:**
```c
if (condition1) {
    // ...
} else if (condition2) {
    // ...
} else {
    // 所有条件都不满足时执行
}
```

**示例:**
```c
int score = 78;
if (score >= 90) {
    printf("优秀\n");
} else if (score >= 80) {
    printf("良好\n");
} else if (score >= 60) {
    printf("及格\n");
} else {
    printf("不及格\n");
}
```

### `switch` 语句

当需要根据一个整数或字符变量的不同取值来执行不同操作时，`switch` 语句通常比一长串 `if-else if` 更清晰、更高效。

**语法:**
```c
switch (variable) {
    case value1:
        // variable 的值等于 value1 时执行
        break;
    case value2:
        // variable 的值等于 value2 时执行
        break;
    // ... 更多 case
    default:
        // 所有 case 都不匹配时执行
        break;
}
```
**关键点**:
- **`break`**: `case` 块通常以 `break` 结尾。如果没有 `break`，程序会继续执行下一个 `case` 的代码，这被称为"穿透"(fall-through)，有时是故意为之，但多数情况是错误的来源。
- **`default`**: `default` 子句是可选的，用于处理所有其他未明确列出的情况。

**示例:**
```c
char grade = 'B';
switch (grade) {
    case 'A':
        printf("优秀!\n");
        break;
    case 'B':
        printf("良好!\n");
        break;
    case 'C':
        printf("及格。\n");
        break;
    default:
        printf("不及格。\n");
        break;
}
```

## 2. 循环语句

### `for` 循环

`for` 循环是在循环次数已知或可以计算的情况下最常用的循环结构。它将初始化、条件判断和更新这三个部分集中在了一起。

**语法:**
```c
for (initialization; condition; update) {
    // 循环体
}
```
- **initialization**: 在循环开始前仅执行一次。
- **condition**: 在每次循环开始前检查。如果为 `true`，则执行循环体。
- **update**: 在每次循环体执行完毕后执行。

**示例：打印 0 到 4**
```c
for (int i = 0; i < 5; i++) {
    printf("i = %d\n", i);
}
```

### `while` 循环

`while` 循环在循环开始前检查条件。只要条件为 `true`，循环体就会一直执行。它适用于循环次数不确定的情况。

**语法:**
```c
while (condition) {
    // 循环体
    // (通常在循环体内部需要有更新条件的操作)
}
```

**示例：模拟用户输入**
```c
int number = 0;
while (number <= 0) {
    printf("请输入一个正数: ");
    scanf("%d", &number);
}
printf("你输入的正数是: %d\n", number);
```

### `do-while` 循环

`do-while` 循环与 `while` 循环类似，但它保证循环体**至少执行一次**，因为条件判断是在循环体执行之后进行的。

**语法:**
```c
do {
    // 循环体
} while (condition);
```

**示例：菜单选择**
```c
int choice;
do {
    printf("菜单:\n1. 开始游戏\n2. 查看帮助\n3. 退出\n");
    printf("请输入你的选择: ");
    scanf("%d", &choice);
} while (choice < 1 || choice > 3);
```

## 3. 跳转语句

### `break`

`break` 语句有两个主要用途：
1.  在 `switch` 语句中，用于跳出 `case` 块。
2.  在循环（`for`, `while`, `do-while`）中，用于立即终止并跳出当前循环。

**示例:**
```c
// 找到第一个能被 7 整除的数
for (int i = 1; i <= 100; i++) {
    if (i % 7 == 0) {
        printf("找到了: %d\n", i);
        break; // 找到后立即跳出 for 循环
    }
}
```

### `continue`

`continue` 语句用于跳过当前循环的剩余部分，直接开始下一次循环。

**示例：只打印奇数**
```c
for (int i = 1; i <= 10; i++) {
    if (i % 2 == 0) {
        continue; // 如果是偶数，跳过本次循环的 printf
    }
    printf("%d ", i); // 输出: 1 3 5 7 9
}
```

---

掌握了控制流程，你就可以编写出能够执行复杂任务的程序了。下一步是学习如何将代码组织成可重用的单元，即 [C 语言函数](c-functions.md)。 