# C 语言：函数

函数是一段执行特定任务的、可重用的代码块。通过使用函数，我们可以将复杂的程序分解成一个个更小、更易于管理的部分。这种做法被称为**模块化编程**，它可以提高代码的可读性、可维护性和复用性。

在 C 语言中，一个程序本质上就是一系列函数的集合。我们已经一直在使用一个最重要的函数：`main` 函数。

## 1. 函数的定义与调用

### 函数定义 (Function Definition)

定义一个函数就是提供该函数的完整实现。

**语法:**
```c
返回类型 函数名(参数列表) {
    // 函数体: 执行任务的代码
    return 返回值; // 如果返回类型不是 void
}
```
- **返回类型 (Return Type)**: 函数执行完毕后返回的数据的类型。如果函数不返回任何值，则使用 `void`。
- **函数名 (Function Name)**: 函数的唯一标识符。
- **参数列表 (Parameter List)**: 函数接收的输入值。每个参数都像一个局部变量，包含类型和名称。如果函数不接收任何参数，可以使用 `void` 或留空。
- **函数体 (Function Body)**: 包含在花括号 `{}` 内的代码，用于实现函数的功能。
- **`return` 语句**: 用于结束函数执行，并（可选地）向调用者返回一个值。

**示例：一个计算两数之和的函数**
```c
int add(int a, int b) {
    int sum = a + b;
    return sum; // 返回计算结果
}
```

### 函数调用 (Function Call)

定义好函数后，你可以在程序的其他地方（例如 `main` 函数或其他函数中）**调用**它来执行其任务。

**示例：调用 `add` 函数**
```c
#include <stdio.h>

// 定义 add 函数
int add(int a, int b) {
    return a + b;
}

int main() {
    int x = 10;
    int y = 20;
    
    // 调用 add 函数，并将返回值存储在 result 变量中
    int result = add(x, y); 
    
    printf("The sum of %d and %d is %d\n", x, y, result); // 输出: The sum of 10 and 20 is 30
    
    // 也可以直接在表达式中调用函数
    printf("The sum is %d\n", add(5, 7)); // 输出: The sum is 12
    
    return 0;
}
```

## 2. 函数声明 (函数原型)

在 C 语言中，如果你在调用一个函数**之前**没有定义它，编译器会报错。为了解决这个问题，我们需要在任何调用发生之前**声明**该函数。函数声明（也称为**函数原型**）告诉编译器函数的名称、返回类型以及它需要哪些参数。

函数原型本质上就是函数定义的第一行，以分号结尾，并且不需要函数体。

**语法:**
`返回类型 函数名(参数类型列表);`
参数名是可选的，但写上可以增加可读性。

**示例：使用函数原型**
```c
#include <stdio.h>

// 函数原型 (声明)
// 告诉编译器，后面会有一个叫 add 的函数
int add(int, int); 

int main() {
    int result = add(10, 20); // 此处可以调用，因为编译器已经通过原型知道了 add 的存在
    printf("Result: %d\n", result);
    return 0;
}

// 函数定义
// 提供了 add 函数的具体实现
int add(int a, int b) {
    return a + b;
}
```
将函数原型放在头文件（`.h` 文件）中是一种常见的良好实践。

## 3. 参数传递：传值调用 (Pass by Value)

在 C 语言中，默认的参数传递方式是**传值调用**。这意味着当你将一个变量作为参数传递给函数时，实际上传递的是该变量的**一个副本 (a copy)**，而不是变量本身。

因此，在函数内部对参数所做的任何修改，**都不会影响**到函数外部的原始变量。

**示例:**
```c
#include <stdio.h>

void modify_value(int x) {
    printf("Inside function (before modification): x = %d\n", x);
    x = 100; // 修改的是 x 的副本
    printf("Inside function (after modification): x = %d\n", x);
}

int main() {
    int original_value = 10;
    printf("Outside function (before call): original_value = %d\n", original_value);
    
    modify_value(original_value); // 传递的是 10 这个值的副本
    
    printf("Outside function (after call): original_value = %d\n", original_value);
    return 0;
}
```
**输出:**
```
Outside function (before call): original_value = 10
Inside function (before modification): x = 10
Inside function (after modification): x = 100
Outside function (after call): original_value = 10
```
可以看到，`main` 函数中的 `original_value` 并没有被改变。要实现函数内修改外部变量，我们需要使用指针，这将在后续章节中讲解。

## 4. 递归函数 (Recursive Functions)

递归是指一个函数直接或间接地调用自身的行为。递归函数必须包含两个部分：
1.  **基线条件 (Base Case)**: 一个或多个使函数停止递归的条件。
2.  **递归步骤 (Recursive Step)**: 函数调用自身，通常处理一个更小的问题。

**示例：使用递归计算阶乘 (n!)**
```c
long long factorial(int n) {
    // 基线条件: 0 的阶乘是 1
    if (n == 0) {
        return 1;
    } 
    // 递归步骤: n! = n * (n-1)!
    else {
        return n * factorial(n - 1);
    }
}
```

## 5. 变量作用域

作用域决定了变量的可见性和生命周期。
- **局部变量 (Local Variables)**: 在函数内部或代码块内部声明的变量。它们只能在其被声明的函数或代码块内部被访问。当函数执行结束时，局部变量会被销毁。
- **全局变量 (Global Variables)**: 在所有函数外部声明的变量。它们可以被程序中的任何函数访问。全局变量的生命周期是整个程序的运行时间。

**过度使用全局变量会使程序难以理解和维护，应尽量避免。**

---

函数是 C 语言编程的基石。接下来，我们将学习如何处理一组相同类型的数据，即 [数组与字符串](c-arrays-strings.md)。 