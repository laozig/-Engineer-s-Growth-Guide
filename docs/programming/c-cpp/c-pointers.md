# C 语言：指针

指针是 C 语言最核心、最强大也是最容易引起混淆的特性。从本质上讲，**指针就是一个存储了另一个变量内存地址的变量**。

通过指针，我们可以间接地读取和修改其他变量的值，实现对内存的底层、高效控制。这是 C 语言如此适用于系统编程和性能攸关领域的核心原因。

## 1. 内存地址

要理解指针，首先要理解内存地址。计算机的内存可以被看作是一系列连续的、带有编号的字节单元。每个字节都有一个唯一的数字标识，这个数字就是它的**地址**。

当你声明一个变量时，计算机会为它在内存中分配一块空间，这块空间的起始位置就是该变量的地址。

## 2. 指针变量与运算符

### 地址运算符 `&`

`&` 运算符用于获取一个变量的内存地址。

```c
#include <stdio.h>

int main() {
    int var = 10;
    
    // 使用 & 获取 var 的地址，并使用 %p 格式说明符打印它
    // %p 用于打印指针/地址
    printf("Value of var: %d\n", var);
    printf("Address of var: %p\n", &var); 
    
    return 0;
}
```

### 声明指针变量

指针变量用于存储地址。声明一个指针变量时，你需要指定它将要指向的数据的类型。

**语法:**
`数据类型* 指针名;`
星号 `*` 告诉编译器这是一个指针变量。

```c
int* p_int;   // 一个指向 int 类型数据的指针
char* p_char; // 一个指向 char 类型数据的指针
double* p_double; // 一个指向 double 类型数据的指针
```
这个 `*` 可以靠近类型，也可以靠近变量名，效果一样：`int *p_int;` 也是合法的。

### 初始化指针

指针可以被初始化为：
1.  一个变量的地址。
2.  `NULL`，表示它不指向任何东西。
3.  另一个已初始化的同类型指针。

```c
int var = 20;
int* p_var = &var; // p_var 现在存储了 var 的地址，我们称 "p_var 指向 var"

int* p_null = NULL; // NULL 指针，一个表示"无处可指"的特殊值
```
**警告**：一个未被初始化的指针被称为**野指针**，它指向一个随机的内存地址。解引用野指针是极其危险的操作，会导致程序崩溃或不可预测的行为。**务必在使用指针前对其进行初始化。**

### 解引用运算符 `*`

`*` 运算符用于访问指针**所指向的地址上存储的值**。这个过程称为**解引用 (dereferencing)**。

```c
int var = 20;
int* p_var = &var; // p_var 指向 var

// 使用解引用操作符 * 获取 p_var 指向的值
int value_from_pointer = *p_var; 
printf("Value via pointer: %d\n", value_from_pointer); // 输出: 20

// 也可以通过指针修改原变量的值
*p_var = 50; // 将 p_var 指向的地址（即 var 的地址）上的值修改为 50
printf("New value of var: %d\n", var); // 输出: 50
```

`*` 和 `&` 是互逆的操作。`*(&var)` 就等价于 `var`。

## 3. 指针与数组

指针和数组在 C 语言中关系非常紧密。实际上，**数组名本身就可以被看作是一个指向数组第一个元素的常量指针**。

```c
int numbers[] = {10, 20, 30, 40};

// numbers 和 &numbers[0] 的值是相同的，都是数组首元素的地址
printf("Address of numbers[0]: %p\n", &numbers[0]);
printf("Value of numbers:      %p\n", numbers);

// 可以将数组名赋值给指针
int* p_numbers = numbers;

// 通过指针访问数组元素
printf("First element via pointer: %d\n", *p_numbers); // 输出: 10
```

### 指针算术 (Pointer Arithmetic)

可以对指针进行加减运算。对一个指针加 1，意味着将指针移动到内存中的下一个**元素**的位置，而不是仅仅移动一个字节。移动的字节数取决于指针所指向的数据类型的大小。

```c
int numbers[] = {10, 20, 30, 40};
int* p_numbers = numbers; // p_numbers 指向 numbers[0]

// p_numbers + 1 指向 numbers[1]
printf("Second element: %d\n", *(p_numbers + 1)); // 输出: 20

// p_numbers + 3 指向 numbers[3]
printf("Fourth element: %d\n", *(p_numbers + 3)); // 输出: 40
```
`*(p_numbers + i)` 等价于 `p_numbers[i]`，也等价于 `numbers[i]`。

## 4. 指针与函数

指针在函数中的应用是其强大功能的集中体现。

### 模拟"传引用调用"

我们之前知道，C 语言默认是传值调用，函数内部无法修改外部的原始变量。通过传递变量的**地址（即指针）**，我们就可以在函数内部通过解引用来修改原始变量的值。

**示例：一个交换两个数的值的函数**
```c
// 函数接收两个整数指针作为参数
void swap(int* a, int* b) {
    int temp = *a; // 取出 a 指向的值
    *a = *b;       // 将 b 指向的值赋给 a 指向的地址
    *b = temp;     // 将临时值赋给 b 指向的地址
}

int main() {
    int x = 10;
    int y = 20;
    printf("Before swap: x = %d, y = %d\n", x, y);
    
    // 传递 x 和 y 的地址给 swap 函数
    swap(&x, &y);
    
    printf("After swap: x = %d, y = %d\n", x, y);
    return 0;
}
```
**输出:**
```
Before swap: x = 10, y = 20
After swap: x = 20, y = 10
```

### 从函数返回指针

函数也可以返回一个指针，但必须非常小心。**绝对不能返回一个指向函数内部局部变量的指针**，因为函数执行完毕后，其局部变量的内存会被释放，返回的指针将成为一个指向无效内存的悬空指针。通常，返回的指针应该指向：
- 静态（`static`）变量
- 全局变量
- 动态分配的内存（将在后续章节讲解）

---

指针是 C 语言的精髓。熟练掌握指针是成为一名合格 C 程序员的必经之路。接下来，我们将学习如何创建自定义的数据类型，即 [结构体与联合体](c-structs-unions.md)。 