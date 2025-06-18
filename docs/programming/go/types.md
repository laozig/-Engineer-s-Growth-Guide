# Go语言数据类型与结构

Go语言提供了丰富的内置数据类型和丰富的数据结构，支持各种编程需求。本文档详细介绍Go中的数据类型和常用数据结构。

## 目录
- [基本数据类型](#基本数据类型)
- [复合数据类型](#复合数据类型)
- [类型转换](#类型转换)
- [类型别名与自定义类型](#类型别名与自定义类型)
- [内存布局与大小](#内存布局与大小)
- [零值](#零值)
- [实际应用场景](#实际应用场景)

## 基本数据类型

Go语言中的基本数据类型包括：

### 布尔类型
```go
var isActive bool = true
var isEnabled = false  // 类型推断
```

布尔类型表示真值或假值，只能是`true`或`false`。

### 数值类型

#### 整数类型

Go提供了多种整数类型，分为有符号和无符号两种：

**有符号整数**：
- `int8`: 8位有符号整数，范围：-128 到 127
- `int16`: 16位有符号整数，范围：-32768 到 32767
- `int32`: 32位有符号整数，范围：-2^31 到 2^31-1
- `int64`: 64位有符号整数，范围：-2^63 到 2^63-1
- `int`: 平台相关，在32位系统上是32位，在64位系统上是64位

**无符号整数**：
- `uint8`: 8位无符号整数，范围：0 到 255 (也叫 `byte`)
- `uint16`: 16位无符号整数，范围：0 到 65535
- `uint32`: 32位无符号整数，范围：0 到 2^32-1
- `uint64`: 64位无符号整数，范围：0 到 2^64-1
- `uint`: 平台相关，在32位系统上是32位，在64位系统上是64位
- `uintptr`: 存储指针值的无符号整数

示例：
```go
var age int = 30
var count uint16 = 65535
var maxInt int64 = 9223372036854775807
var b byte = 255  // byte 是 uint8 的别名
```

#### 浮点数类型

Go提供两种浮点数类型：

- `float32`: IEEE-754 32位浮点数
- `float64`: IEEE-754 64位浮点数（默认）

示例：
```go
var height float32 = 175.5
var weight = 70.2  // 默认为 float64
```

#### 复数类型

Go还提供了复数类型：

- `complex64`: 由两个32位浮点数组成的复数
- `complex128`: 由两个64位浮点数组成的复数（默认）

示例：
```go
var c1 complex64 = complex(5, 7)  // 5+7i
var c2 = 1 + 2i  // 默认为 complex128
```

### 字符类型

在Go中，字符使用`rune`类型表示，它是`int32`的别名，用于表示Unicode码点。

```go
var char rune = 'A'
var emoji rune = '😊'
```

### 字符串类型

字符串是一个不可变的字节序列，通常代表UTF-8编码的文本。

```go
var name string = "Go编程"
var message = "Hello, World!"
```

Go中的字符串操作：
```go
// 字符串连接
fullName := firstName + " " + lastName

// 字符串长度（字节数）
length := len(message)

// 获取UTF-8字符数
count := utf8.RuneCountInString(message)

// 字符串切片
substring := message[7:12]  // "World"

// 多行字符串
multiLine := `这是第一行
这是第二行
这是第三行`
```

## 复合数据类型

### 数组

数组是具有相同类型的元素的固定长度序列。

```go
// 定义一个长度为5的整数数组
var numbers [5]int

// 数组初始化
var fruits = [3]string{"苹果", "香蕉", "橙子"}

// 使用...让编译器计算长度
colors := [...]string{"红", "绿", "蓝", "黄"}
```

数组操作：
```go
// 访问数组元素
first := fruits[0]  // "苹果"

// 修改数组元素
fruits[1] = "梨"

// 数组长度
size := len(fruits)

// 数组遍历
for i, fruit := range fruits {
    fmt.Printf("水果 %d: %s\n", i, fruit)
}
```

### 切片

切片是对数组的引用，是一个可变长度的序列，比数组更灵活常用。

```go
// 创建切片
var slice1 []int            // nil切片
slice2 := []int{1, 2, 3, 4} // 使用字面量创建
slice3 := make([]int, 5)    // 使用make创建长度为5的切片
slice4 := make([]int, 5, 10) // 长度5，容量10的切片
```

切片操作：
```go
// 从数组创建切片
arr := [5]int{1, 2, 3, 4, 5}
slice := arr[1:4]  // [2, 3, 4]

// 切片追加元素
slice = append(slice, 6, 7)

// 切片长度和容量
length := len(slice)
capacity := cap(slice)

// 切片复制
newSlice := make([]int, len(slice))
copy(newSlice, slice)

// 删除切片元素
// 删除索引为i的元素
i := 2
slice = append(slice[:i], slice[i+1:]...)
```

### 映射 (Map)

Map是键值对的无序集合，类似其他语言中的字典或哈希表。

```go
// 创建map
var m1 map[string]int           // nil map
m2 := map[string]int{}          // 空map
m3 := map[string]int{           // 带初始值的map
    "one": 1,
    "two": 2,
}
m4 := make(map[string]int, 10)  // 预分配空间的map
```

Map操作：
```go
// 添加或修改元素
m3["three"] = 3

// 获取元素
val, exists := m3["two"]
if exists {
    fmt.Println("值存在:", val)
}

// 删除元素
delete(m3, "one")

// Map长度
size := len(m3)

// 遍历Map
for key, value := range m3 {
    fmt.Printf("键: %s, 值: %d\n", key, value)
}
```

### 结构体

结构体是字段的集合，用于表示记录。

```go
// 定义结构体
type Person struct {
    Name    string
    Age     int
    Address string
}

// 创建结构体实例
var p1 Person
p2 := Person{"张三", 25, "北京"}
p3 := Person{
    Name:    "李四",
    Age:     30,
    Address: "上海",
}
p4 := Person{Name: "王五"}  // 其他字段为零值
```

结构体操作：
```go
// 访问结构体字段
name := p2.Name

// 修改结构体字段
p2.Age = 26

// 结构体指针
ptr := &p2
ptr.Address = "广州"  // 等同于 (*ptr).Address = "广州"
```

### 指针

指针存储了变量的内存地址。

```go
// 声明指针
var ptr *int

// 获取变量的地址
num := 42
ptr = &num

// 通过指针访问值（解引用）
value := *ptr

// 修改指针指向的值
*ptr = 100
```

### 函数类型

在Go中，函数也是一种类型，可以作为变量、参数或返回值。

```go
// 定义函数类型
type Operator func(a, b int) int

// 创建函数类型的变量
var add Operator = func(a, b int) int {
    return a + b
}

// 使用函数类型
result := add(5, 3)  // 8
```

### 接口类型

接口是方法的集合，用于定义行为。

```go
// 定义接口
type Greeter interface {
    Greet() string
}

// 实现接口
type EnglishGreeter struct{}

func (eg EnglishGreeter) Greet() string {
    return "Hello!"
}

// 使用接口
var greeter Greeter = EnglishGreeter{}
message := greeter.Greet()
```

### 通道 (Channel)

通道是用于在goroutine之间进行通信的管道。

```go
// 创建通道
ch1 := make(chan int)        // 无缓冲通道
ch2 := make(chan string, 10) // 带10个缓冲区的通道

// 发送数据到通道
ch1 <- 42

// 从通道接收数据
val := <-ch1

// 关闭通道
close(ch1)

// 遍历通道（直到通道关闭）
for msg := range ch2 {
    fmt.Println(msg)
}
```

## 类型转换

Go是强类型语言，不同类型之间的转换需要显式进行。

```go
// 基本类型间转换
var i int = 42
var f float64 = float64(i)
var u uint = uint(f)

// 字符串和数字转换
import "strconv"

// 整数转字符串
s1 := strconv.Itoa(42)            // "42"
s2 := strconv.FormatInt(42, 10)   // "42"（十进制）
s3 := strconv.FormatInt(42, 16)   // "2a"（十六进制）

// 字符串转整数
i1, err := strconv.Atoi("42")               // 42
i2, err := strconv.ParseInt("42", 10, 64)   // 42（十进制）

// 浮点数与字符串转换
s4 := strconv.FormatFloat(3.1415, 'f', 2, 64)  // "3.14"
f1, err := strconv.ParseFloat("3.14", 64)       // 3.14
```

## 类型别名与自定义类型

### 类型别名

```go
// 定义类型别名
type MyInt = int

var num MyInt = 100
var regular int = num  // 不需要类型转换
```

### 自定义类型

```go
// 定义新类型
type UserId int

var id UserId = 101
var regular int = int(id)  // 需要类型转换
```

## 内存布局与大小

可以使用`unsafe.Sizeof`函数来获取类型的大小：

```go
import "unsafe"

fmt.Println(unsafe.Sizeof(true))        // 1
fmt.Println(unsafe.Sizeof(int8(0)))     // 1
fmt.Println(unsafe.Sizeof(int16(0)))    // 2
fmt.Println(unsafe.Sizeof(int32(0)))    // 4
fmt.Println(unsafe.Sizeof(int64(0)))    // 8
fmt.Println(unsafe.Sizeof(float32(0)))  // 4
fmt.Println(unsafe.Sizeof(float64(0)))  // 8
fmt.Println(unsafe.Sizeof(""))          // 16（在大多数64位系统上）
```

## 零值

每种类型在Go中都有一个零值，当变量声明但未初始化时会使用零值：

- 数值类型：`0`
- 布尔类型：`false`
- 字符串：`""` (空字符串)
- 指针、函数、接口、切片、通道和映射：`nil`
- 结构体：每个字段都是其类型的零值

## 实际应用场景

### 数据处理

```go
// 使用切片和map处理数据
func processScores(names []string, scores []int) map[string]string {
    result := make(map[string]string)
    
    for i, name := range names {
        var grade string
        switch {
        case scores[i] >= 90:
            grade = "A"
        case scores[i] >= 80:
            grade = "B"
        case scores[i] >= 70:
            grade = "C"
        default:
            grade = "D"
        }
        result[name] = grade
    }
    
    return result
}
```

### 数据建模

```go
// 使用结构体建模
type Product struct {
    ID        string
    Name      string
    Price     float64
    Available bool
    Tags      []string
    Metadata  map[string]string
}

// 创建和使用产品
func createCatalog() []Product {
    return []Product{
        {
            ID:        "p1",
            Name:      "笔记本电脑",
            Price:     5999.99,
            Available: true,
            Tags:      []string{"电子", "计算机", "办公"},
            Metadata: map[string]string{
                "品牌": "ThinkPad",
                "CPU":  "Intel i5",
                "内存": "16GB",
            },
        },
        {
            ID:        "p2",
            Name:      "智能手机",
            Price:     3999.99,
            Available: true,
            Tags:      []string{"电子", "通信"},
            Metadata: map[string]string{
                "品牌": "华为",
                "屏幕": "6.7英寸",
                "存储": "256GB",
            },
        },
    }
}
```

### 自定义数据类型

```go
// 货币类型
type Money float64

func (m Money) String() string {
    return fmt.Sprintf("¥%.2f", m)
}

// 邮箱类型
type Email string

func (e Email) IsValid() bool {
    // 简单验证
    return strings.Contains(string(e), "@") && strings.Contains(string(e), ".")
}

// 使用自定义类型
func processPurchase(amount Money, contact Email) error {
    if !contact.IsValid() {
        return errors.New("无效的邮箱地址")
    }
    
    fmt.Printf("处理金额 %s 的购买，联系邮箱: %s\n", amount, contact)
    return nil
}
```

### 泛型（Go 1.18+）

```go
// 泛型函数
func Min[T constraints.Ordered](x, y T) T {
    if x < y {
        return x
    }
    return y
}

// 泛型数据结构
type Stack[T any] struct {
    elements []T
}

func (s *Stack[T]) Push(v T) {
    s.elements = append(s.elements, v)
}

func (s *Stack[T]) Pop() (T, bool) {
    var zero T
    if len(s.elements) == 0 {
        return zero, false
    }
    
    index := len(s.elements) - 1
    element := s.elements[index]
    s.elements = s.elements[:index]
    return element, true
}

// 使用泛型
func useGenerics() {
    // 泛型函数
    minInt := Min(10, 20)
    minFloat := Min(3.14, 2.71)
    
    // 泛型数据结构
    intStack := Stack[int]{}
    intStack.Push(10)
    intStack.Push(20)
    intStack.Push(30)
    
    val, ok := intStack.Pop()  // 30, true
    
    stringStack := Stack[string]{}
    stringStack.Push("Go")
    stringStack.Push("Rust")
    stringStack.Push("Python")
}
```

## 总结

Go提供了丰富的数据类型和结构，从简单的布尔值和数字到复杂的结构体、接口和通道，满足各种编程需求。理解这些类型及其操作对Go程序的开发至关重要。同时，Go的类型系统具有静态性和强类型特点，可以在编译时发现许多错误，提高代码的可靠性。 