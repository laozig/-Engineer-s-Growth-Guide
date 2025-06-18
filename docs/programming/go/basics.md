# Go基础语法

本文档介绍Go语言的基本语法和核心概念，帮助初学者快速入门Go开发。

## 目录

- [变量与常量](#变量与常量)
- [基本数据类型](#基本数据类型)
- [运算符](#运算符)
- [控制结构](#控制结构)
- [函数](#函数)
- [包与导入](#包与导入)
- [注释](#注释)

## 变量与常量

### 变量声明

Go语言中有多种声明变量的方式：

```go
// 1. 声明变量但不初始化
var name string
var age int

// 2. 声明变量并初始化
var name string = "张三"
var age int = 25

// 3. 类型推断 - 声明时省略类型
var name = "张三" // 字符串类型
var age = 25     // 整数类型

// 4. 短变量声明（仅在函数内部使用）
func main() {
    name := "张三"
    age := 25
    
    // 一次声明多个变量
    name, age := "李四", 30
}
```

### 常量声明

常量使用`const`关键字声明：

```go
// 单个常量声明
const PI = 3.14159
const MaxUsers = 100

// 多个常量声明
const (
    StatusOK = 200
    StatusNotFound = 404
    StatusServerError = 500
)

// iota 常量生成器
const (
    Monday = iota + 1 // 1
    Tuesday           // 2
    Wednesday         // 3
    Thursday          // 4
    Friday            // 5
)
```

## 基本数据类型

Go语言中常用的基本数据类型：

### 布尔型

```go
var isActive bool = true
var isEnabled = false
```

### 数值类型

```go
// 整型
var age int = 25       // 根据系统架构可能是32位或64位
var count int32 = 1000 // 明确指定32位
var total int64 = 9999999999 // 64位整数

// 无符号整型
var flags uint8 = 255  // 0-255
var port uint16 = 8080 // 无符号16位整数

// 浮点型
var price float32 = 9.99
var pi float64 = 3.14159265358979
```

### 字符和字符串

```go
// 字符
var char byte = 'A'    // ASCII字符
var emoji rune = '😊'  // Unicode字符

// 字符串
var name string = "张三"
var multiLine string = `
这是一个
多行字符串
支持换行
`
```

### 复合类型

```go
// 数组 - 固定长度
var numbers [5]int = [5]int{1, 2, 3, 4, 5}
scores := [3]float64{98.5, 93.7, 87.2}

// 切片 - 动态长度
var fruits []string = []string{"苹果", "香蕉", "橙子"}
names := []string{"张三", "李四", "王五"}
```

## 运算符

Go语言支持常见的算术、逻辑和比较运算符：

### 算术运算符

```go
a := 10
b := 3

sum := a + b      // 加法: 13
difference := a - b // 减法: 7
product := a * b   // 乘法: 30
quotient := a / b  // 整数除法: 3
remainder := a % b // 取余: 1

a++  // 自增: a 变为 11
b--  // 自减: b 变为 2
```

### 比较运算符

```go
a := 10
b := 5

a == b // 等于: false
a != b // 不等于: true
a > b  // 大于: true
a < b  // 小于: false
a >= b // 大于等于: true
a <= b // 小于等于: false
```

### 逻辑运算符

```go
condition1 := true
condition2 := false

result1 := condition1 && condition2 // 逻辑与: false
result2 := condition1 || condition2 // 逻辑或: true
result3 := !condition1             // 逻辑非: false
```

## 控制结构

### if 条件语句

```go
age := 18

// 基本if语句
if age >= 18 {
    fmt.Println("成年人")
} else {
    fmt.Println("未成年")
}

// if语句带初始化语句
if score := getScore(); score >= 60 {
    fmt.Println("及格")
} else if score >= 80 {
    fmt.Println("良好")
} else {
    fmt.Println("不及格")
}
```

### for 循环

```go
// 基本for循环
for i := 0; i < 5; i++ {
    fmt.Println(i)
}

// 类似while循环
i := 0
for i < 5 {
    fmt.Println(i)
    i++
}

// 无限循环
for {
    fmt.Println("无限循环，需要break跳出")
    break
}

// 遍历切片
fruits := []string{"苹果", "香蕉", "橙子"}
for index, value := range fruits {
    fmt.Printf("索引: %d, 值: %s\n", index, value)
}

// 遍历map
scores := map[string]int{"张三": 95, "李四": 85, "王五": 90}
for key, value := range scores {
    fmt.Printf("姓名: %s, 分数: %d\n", key, value)
}
```

### switch 语句

```go
day := "周一"

switch day {
case "周一":
    fmt.Println("星期一")
case "周二":
    fmt.Println("星期二")
case "周三", "周四": // 多个匹配条件
    fmt.Println("星期三或星期四")
default:
    fmt.Println("其他日子")
}

// 不带表达式的switch
age := 18
switch {
case age < 18:
    fmt.Println("未成年")
case age >= 18 && age < 60:
    fmt.Println("成年人")
default:
    fmt.Println("老年人")
}
```

## 函数

### 基本函数

```go
// 无参数无返回值函数
func sayHello() {
    fmt.Println("你好，世界！")
}

// 带参数的函数
func greet(name string) {
    fmt.Printf("你好，%s！\n", name)
}

// 带返回值的函数
func add(a, b int) int {
    return a + b
}

// 多个返回值
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("除数不能为零")
    }
    return a / b, nil
}
```

### 命名返回值

```go
func calculate(width, height float64) (area, perimeter float64) {
    area = width * height
    perimeter = 2 * (width + height)
    return // 自动返回命名的返回值
}
```

### 可变参数函数

```go
func sum(numbers ...int) int {
    total := 0
    for _, num := range numbers {
        total += num
    }
    return total
}

// 调用
result1 := sum(1, 2, 3) // 6
nums := []int{4, 5, 6}
result2 := sum(nums...) // 15
```

### 匿名函数与闭包

```go
// 匿名函数
func main() {
    f := func(x, y int) int {
        return x + y
    }
    
    result := f(3, 4) // 调用匿名函数
    fmt.Println(result) // 7
    
    // 闭包
    counter := func() func() int {
        count := 0
        return func() int {
            count++
            return count
        }
    }()
    
    fmt.Println(counter()) // 1
    fmt.Println(counter()) // 2
    fmt.Println(counter()) // 3
}
```

## 包与导入

### 包声明

每个Go文件开头都必须有包声明：

```go
// main包是可执行程序的入口
package main

// 自定义包名
package util
```

### 导入包

```go
// 单个导入
import "fmt"

// 多个导入
import (
    "fmt"
    "strings"
    "time"
)

// 导入时取别名
import (
    f "fmt"
    s "strings"
)
```

### 导出标识符

在Go中，首字母大写的标识符（变量、函数、类型等）会被导出（可在包外访问）：

```go
package util

// Greeting 可在其他包中访问（首字母大写）
func Greeting(name string) string {
    return "你好, " + name
}

// formatName 不能在其他包中访问（首字母小写）
func formatName(name string) string {
    return strings.TrimSpace(name)
}
```

## 注释

Go支持单行和多行注释：

```go
// 这是单行注释

/*
这是多行注释
可以跨越多行
*/

// 文档注释 - 用于生成文档
// Add 返回两个整数的和
func Add(a, b int) int {
    return a + b
}
```

---

通过这些基础知识，您可以开始编写简单的Go程序。随着学习的深入，建议进一步了解结构体、接口、并发编程等Go的高级特性。 