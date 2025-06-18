# C 语言：变量与数据类型

变量是程序中用于存储数据的命名空间。在 C 语言中，使用任何变量之前，都必须先**声明**它，并指定其**数据类型**。数据类型决定了变量可以存储什么样的数据以及可以对这些数据执行哪些操作。

## 1. 变量的声明与初始化

### 声明 (Declaration)

声明一个变量就是告诉编译器变量的名字和它将要存储的数据类型。
语法：`数据类型 变量名;`

```c
int age;
float salary;
char initial;
```

你也可以在一行中声明多个同类型的变量：
```c
int x, y, z;
```

### 初始化 (Initialization)

初始化是在声明变量的同时给它赋一个初始值。
语法：`数据类型 变量名 = 初始值;`

```c
int age = 30; // 声明并初始化 age
float salary = 55000.50;
char initial = 'J';
```
在 C 语言中，如果一个局部变量（在函数内部声明的变量）没有被初始化，它的值是未定义的（通常是一些随机的垃圾值）。**因此，在声明变量时进行初始化是一个非常好的编程习惯。**

## 2. 基本数据类型

C 语言提供了多种基本数据类型来处理整数、浮点数和字符。

### 整型 (Integer Types)

用于存储整数。C 语言提供了不同大小的整型来满足不同的存储需求。

| 类型 | 大小 (典型) | 范围 (典型) | 格式说明符 |
| :--- | :--- | :--- | :--- |
| `char` | 1 字节 | -128 到 127 或 0 到 255 | `%c` |
| `short` | 2 字节 | -32,768 到 32,767 | `%hd` |
| `int` | 4 字节 | -2,147,483,648 到 2,147,483,647 | `%d` |
| `long` | 4 或 8 字节 | 取决于系统 | `%ld` |
| `long long`| 8 字节 | 约 -9e18 到 9e18 | `%lld` |

**注意**：`char` 类型在 C 语言中很特殊，它本质上是一个 1 字节的整数，因此既可以用来存储小整数，也可以用来存储 ASCII 字符。

```c
int population = 1400000000;
short year = 2023;
char grade = 'A'; // 字符用单引号括起来
```

### 浮点型 (Floating-Point Types)

用于存储带有小数部分的数字。

| 类型 | 大小 (典型) | 精度 (约) | 格式说明符 |
| :--- | :--- | :--- | :--- |
| `float` | 4 字节 | 7 位十进制数字 | `%f` |
| `double`| 8 字节 | 15 位十进制数字 | `%lf` |

- `float`：单精度浮点数。
- `double`：双精度浮点数，提供比 `float`更高的精度和范围。

```c
float pi_approx = 3.14f; // 'f' 后缀表示这是一个 float 类型
double pi_precise = 3.141592653589793;
```
**在 C 语言中，默认的浮点数字面量是 `double` 类型。**

### 布尔型 (`_Bool`)

C99 标准引入了 `_Bool` 类型，用于表示布尔值 `true` 和 `false`。为了更方便地使用，可以包含头文件 `<stdbool.h>`，它定义了 `bool`、`true` 和 `false` 这几个宏。

```c
#include <stdbool.h> // 引入布尔类型支持

bool is_student = true;
bool has_license = false;
```
在底层，`true` 的值是 1，`false` 的值是 0。

## 3. 类型修饰符

修饰符可以用来改变基本类型的含义。

### `signed` 和 `unsigned`

这两个修饰符用于整型（`char`, `short`, `int`, `long`）。
- `signed` (默认)：变量可以存储正数、负数和零。
- `unsigned`：变量只能存储正数和零。这使得变量可以存储的最大值大约是对应 `signed` 类型的两倍。

```c
unsigned int positive_value = 4000000000; // int 存不下，但 unsigned int 可以
// signed int negative_value = -100; // 这是合法的
```
`unsigned char` 常用于处理原始字节数据。

### `const`

`const` 修饰符用于创建一个**常量**，意味着变量的值在初始化后就不能被修改。

```c
const double PI = 3.14159;
// PI = 3.14; // 编译错误！不能修改 const 变量
```
使用 `const` 可以增强程序的健壮性和可读性。

## 4. `sizeof` 操作符

`sizeof` 是一个非常有用的操作符，它返回一个变量或数据类型在当前系统上所占用的内存大小（以字节为单位）。

```c
#include <stdio.h>

int main() {
    printf("Size of int: %zu bytes\n", sizeof(int));
    printf("Size of char: %zu bytes\n", sizeof(char));
    printf("Size of double: %zu bytes\n", sizeof(double));

    int age;
    printf("Size of variable age: %zu bytes\n", sizeof(age));
    
    return 0;
}
```
**注意**：`sizeof` 的返回值类型是 `size_t`，打印它推荐的格式说明符是 `%zu`。

`sizeof` 在内存分配和处理数据结构时非常重要。

---

掌握了变量和数据类型，下一步是学习如何对这些数据进行操作，即 [C 语言运算符](c-operators.md)。 