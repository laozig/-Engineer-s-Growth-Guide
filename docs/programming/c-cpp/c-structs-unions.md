# C 语言：结构体与联合体

C 语言的数组允许我们将多个**相同类型**的数据组合在一起。但现实世界中的对象通常由多种不同类型的数据组成，例如，一个“学生”有姓名（字符串）、年龄（整数）、成绩（浮点数）等。为了表示这种复杂的对象，C 语言提供了**结构体 (Struct)**。

## 1. 结构体 (Struct)

结构体是一种用户自定义的数据类型，它允许我们将多个不同类型的变量捆绑成一个单一的、有意义的单元。

### 定义结构体

使用 `struct` 关键字来定义一个新的结构体类型。

**语法:**
```c
struct 结构体标签 {
    数据类型 成员1;
    数据类型 成员2;
    // ...
};
```

**示例：定义一个 `Student` 结构体**
```c
struct Student {
    char name[50];
    int age;
    float gpa;
};
```
这定义了一个名为 `Student` 的新数据类型模板，但此时还没有创建任何变量。

### 声明结构体变量

一旦定义了结构体类型，就可以用它来声明变量。

```c
// 声明一个 Student 类型的变量 s1
struct Student s1;
```

### 初始化结构体变量与访问成员

可以在声明时初始化结构体，类似于数组。

```c
// 使用初始化列表
struct Student s2 = {"Alice", 20, 3.8f};

// 指定成员初始化 (C99+)
struct Student s3 = {.name = "Bob", .age = 22, .gpa = 3.5f};
```

使用**点运算符 `.`** 来访问或修改结构体的成员。

```c
// 访问成员
printf("Student Name: %s\n", s2.name);
printf("Student Age: %d\n", s2.age);

// 修改成员
strcpy(s1.name, "Charlie"); // 对于字符串，需要使用 strcpy
s1.age = 21;
s1.gpa = 3.9f;
```

### 指向结构体的指针

在处理大型结构体时，为了效率，我们通常使用指向结构体的指针，而不是直接复制整个结构体。

```c
struct Student s1 = {"David", 23, 3.7f};

// 创建一个指向 s1 的指针
struct Student* p_student = &s1;
```

当通过指针访问结构体成员时，有两种方式：
1.  **解引用和点运算符 `(*p).member`**: `(*p_student).age`
2.  **箭头运算符 `->` (推荐)**: 这是一个语法糖，更简洁易读。`p->member`

```c
// 使用箭头运算符访问成员
printf("Name via pointer: %s\n", p_student->name);
printf("Age via pointer: %d\n", p_student->age);

// 使用箭头运算符修改成员
p_student->gpa = 4.0f;
printf("New GPA of s1: %.2f\n", s1.gpa); // 输出 4.00
```

### `typedef`：为类型创建别名

每次都写 `struct Student` 可能有些繁琐。`typedef` 关键字可以为已有的数据类型创建一个新的、更简洁的别名。

```c
// 定义结构体并立即为其创建别名 Person
typedef struct {
    char name[100];
    int age;
} Person;

// 现在可以像使用内置类型一样使用 Person
Person p1;
p1.age = 30;
strcpy(p1.name, "Eve");

// 也可以这样写
/*
struct _Person {
    char name[100];
    int age;
};
typedef struct _Person Person;
*/
```
使用 `typedef` 可以让代码更清晰、更易于维护。

## 2. 联合体 (Union)

联合体是一种特殊的数据结构，它允许在**同一块内存空间**中存储不同类型的数据。联合体的大小由其**最大的成员**决定。

这意味着，在任何时候，联合体只能有效地存储其**一个成员**的值。给一个成员赋值会覆盖掉其他成员的值。

**语法:**
```c
union 联合体标签 {
    数据类型 成员1;
    数据类型 成员2;
    // ...
};
```

**示例：**
```c
#include <stdio.h>

typedef union {
    int i;
    float f;
    char str[20];
} Data;

int main() {
    Data data;
    
    data.i = 10;
    printf("data.i: %d\n", data.i);
    
    data.f = 220.5;
    // 此时 data.i 的值已经被破坏了
    printf("data.f: %f\n", data.f);
    
    strcpy(data.str, "Hello");
    // 此时 data.i 和 data.f 的值也都被破坏了
    printf("data.str: %s\n", data.str);

    printf("Size of data union: %zu bytes\n", sizeof(Data)); // 大小为 20
    
    return 0;
}
```

联合体主要用于以下场景：
- **节省内存**：当你知道某个数据结构在不同时间只需要用到其中一个成员时。
- **类型双关 (Type Punning)**：以不同的数据类型来解释同一块内存区域，这是一种高级且需要谨慎使用的技巧。

---

结构体是构建复杂程序的基础数据模型。但要创建动态的、大小可变的数据结构（如链表、树），我们还需要学习如何在运行时请求和释放内存，这就是 [C 语言内存管理](c-memory-management.md) 的内容。 