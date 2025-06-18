# Go语言控制流

控制流语句决定了程序的执行路径。Go提供了清晰、简洁的控制流结构，本文档详细介绍Go中的条件、循环和跳转语句。

## 目录
- [条件语句](#条件语句)
- [循环语句](#循环语句)
- [跳转语句](#跳转语句)
- [延迟执行](#延迟执行)
- [错误处理](#错误处理)
- [恐慌与恢复](#恐慌与恢复)
- [实践示例](#实践示例)

## 条件语句

### if-else 语句

Go语言的`if`语句不需要小括号，但大括号是必须的：

```go
if condition {
    // 条件为真时执行
} else {
    // 条件为假时执行
}
```

**简短声明**：`if`语句可以包含一个简短的变量声明，作用域仅限于if-else块内：

```go
if value := getValue(); value > 10 {
    fmt.Println("值大于10:", value)
} else if value < 0 {
    fmt.Println("值为负数:", value)
} else {
    fmt.Println("值在0和10之间:", value)
}
// 这里不能使用value变量
```

**常见用法**：处理错误

```go
if file, err := os.Open("file.txt"); err != nil {
    fmt.Println("打开文件失败:", err)
    return
} else {
    // 使用文件
    defer file.Close()
}
```

### switch 语句

Go的`switch`语句比其他语言更灵活，默认情况下只会执行匹配的`case`（自动`break`）。

**基本用法**：

```go
switch day {
case "Monday":
    fmt.Println("星期一")
case "Tuesday":
    fmt.Println("星期二")
case "Wednesday":
    fmt.Println("星期三")
case "Thursday":
    fmt.Println("星期四")
case "Friday":
    fmt.Println("星期五")
case "Saturday", "Sunday": // 多值匹配
    fmt.Println("周末")
default:
    fmt.Println("无效的日期")
}
```

**无条件switch**：可以在`case`中使用任意条件表达式

```go
switch {
case hour < 12:
    fmt.Println("上午好")
case hour < 17:
    fmt.Println("下午好")
default:
    fmt.Println("晚上好")
}
```

**带初始化语句**：类似于`if`语句

```go
switch os := runtime.GOOS; os {
case "darwin":
    fmt.Println("MacOS")
case "linux":
    fmt.Println("Linux")
case "windows":
    fmt.Println("Windows")
default:
    fmt.Printf("未知操作系统: %s\n", os)
}
```

**fallthrough**：强制执行下一个`case`

```go
switch num := 75; {
case num >= 90:
    fmt.Println("优秀")
    fallthrough
case num >= 80:
    fmt.Println("良好")
    fallthrough
case num >= 60:
    fmt.Println("及格")
case num < 60:
    fmt.Println("不及格")
}
```

**类型switch**：用于类型断言

```go
var i interface{} = "Hello"

switch v := i.(type) {
case nil:
    fmt.Println("值为nil")
case int:
    fmt.Println("整数:", v)
case float64:
    fmt.Println("浮点数:", v)
case string:
    fmt.Println("字符串:", v)
default:
    fmt.Printf("未知类型: %T\n", v)
}
```

## 循环语句

Go语言只有`for`循环，但它非常灵活，可以实现各种循环结构。

### 标准for循环

```go
for i := 0; i < 5; i++ {
    fmt.Println(i)
}
```

### 类似while的for循环

```go
i := 0
for i < 5 {
    fmt.Println(i)
    i++
}
```

### 无限循环

```go
for {
    fmt.Println("无限循环，需要使用break退出")
    break
}
```

### for-range循环

`for-range`循环用于遍历各种数据结构：

**遍历数组或切片**：

```go
fruits := []string{"苹果", "香蕉", "橙子"}
for index, value := range fruits {
    fmt.Printf("索引: %d, 值: %s\n", index, value)
}

// 如果只需要索引
for index := range fruits {
    fmt.Printf("索引: %d\n", index)
}

// 如果只需要值
for _, value := range fruits {
    fmt.Printf("值: %s\n", value)
}
```

**遍历字符串**：按Unicode字符(rune)遍历

```go
for index, char := range "Go编程" {
    fmt.Printf("位置: %d, 字符: %c, Unicode: %U\n", index, char, char)
}
```

**遍历map**：

```go
scores := map[string]int{"Alice": 90, "Bob": 85, "Charlie": 95}
for name, score := range scores {
    fmt.Printf("%s的分数: %d\n", name, score)
}
```

**遍历通道**：

```go
ch := make(chan int)
go func() {
    ch <- 1
    ch <- 2
    ch <- 3
    close(ch)
}()

for n := range ch {
    fmt.Println(n)
}
```

## 跳转语句

Go提供了三种跳转语句：`break`、`continue`和`goto`。

### break语句

`break`用于提前结束循环或`switch`语句：

```go
for i := 0; i < 10; i++ {
    if i == 5 {
        break // 当i等于5时，终止循环
    }
    fmt.Println(i)
}
```

**带标签的break**：可以跳出多层循环

```go
OuterLoop:
    for i := 0; i < 5; i++ {
        for j := 0; j < 5; j++ {
            if i*j > 10 {
                fmt.Println("跳出外层循环")
                break OuterLoop
            }
            fmt.Printf("i=%d, j=%d\n", i, j)
        }
    }
```

### continue语句

`continue`用于跳过当前循环的剩余部分，继续下一次迭代：

```go
for i := 0; i < 10; i++ {
    if i%2 == 0 {
        continue // 跳过偶数
    }
    fmt.Println(i) // 只打印奇数
}
```

**带标签的continue**：可以跳到外层循环继续执行

```go
OuterLoop:
    for i := 0; i < 3; i++ {
        for j := 0; j < 3; j++ {
            if i == 1 && j == 1 {
                fmt.Println("跳过当前迭代，继续外层循环")
                continue OuterLoop
            }
            fmt.Printf("i=%d, j=%d\n", i, j)
        }
    }
```

### goto语句

`goto`语句可以跳转到程序中的标记位置：

```go
    i := 0
Start:
    fmt.Println(i)
    i++
    if i < 5 {
        goto Start // 跳回Start标签处
    }
```

**注意事项**：
- `goto`不能跳过变量声明
- 过度使用`goto`可能导致代码难以理解和维护
- 通常有更好的替代方案（如函数调用、循环或条件语句）

## 延迟执行

`defer`语句会延迟函数的执行，直到包含该`defer`语句的函数返回。

### 基本用法

```go
func readFile(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close() // 文件会在函数返回时关闭
    
    // 读取文件内容...
    return nil
}
```

### 多个defer语句

多个`defer`语句按照后进先出（LIFO）的顺序执行：

```go
func deferOrder() {
    fmt.Println("函数开始")
    
    defer fmt.Println("第一个defer") // 最后执行
    defer fmt.Println("第二个defer") // 倒数第二个执行
    defer fmt.Println("第三个defer") // 第一个执行
    
    fmt.Println("函数结束")
}
```

输出：
```
函数开始
函数结束
第三个defer
第二个defer
第一个defer
```

### defer与参数求值

`defer`语句的参数在`defer`语句执行时求值，而不是在函数执行时：

```go
func deferEvaluation() {
    i := 1
    defer fmt.Println("defer中的i:", i) // 输出1，而不是2
    i = 2
    fmt.Println("函数中的i:", i) // 输出2
}
```

### defer与匿名函数

`defer`经常与匿名函数一起使用，以便捕获最新的变量值：

```go
func deferClosure() {
    i := 1
    defer func() {
        fmt.Println("defer函数中的i:", i) // 输出2，因为引用了外部变量
    }()
    i = 2
}

func deferClosureWithParams() {
    i := 1
    defer func(value int) {
        fmt.Println("带参数的defer函数中的i:", value) // 输出1，因为参数在defer时已求值
    }(i)
    i = 2
}
```

## 错误处理

Go使用显式的错误返回值而非异常来处理错误情况。

### 基本错误处理模式

```go
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("除数不能为零")
    }
    return a / b, nil
}

func main() {
    result, err := divide(10, 0)
    if err != nil {
        fmt.Println("错误:", err)
        return
    }
    fmt.Println("结果:", result)
}
```

### 自定义错误类型

```go
type ValidationError struct {
    Field string
    Message string
}

func (e *ValidationError) Error() string {
    return fmt.Sprintf("字段'%s'验证失败: %s", e.Field, e.Message)
}

func validateAge(age int) error {
    if age < 0 {
        return &ValidationError{
            Field: "age",
            Message: "年龄不能为负数",
        }
    }
    if age > 150 {
        return &ValidationError{
            Field: "age",
            Message: "年龄不能超过150",
        }
    }
    return nil
}
```

### 错误包装（Go 1.13+）

```go
import "fmt"
import "errors"

func process() error {
    err := connect()
    if err != nil {
        return fmt.Errorf("连接失败: %w", err) // 包装原始错误
    }
    return nil
}

// 使用包装错误
func main() {
    err := process()
    if err != nil {
        fmt.Println(err) // 打印整个错误链
        
        // 解包错误
        var connectErr *ConnectionError
        if errors.As(err, &connectErr) {
            fmt.Println("连接错误:", connectErr.Server)
        }
        
        // 检查错误类型
        if errors.Is(err, ErrTimeout) {
            fmt.Println("超时错误")
        }
    }
}
```

## 恐慌与恢复

虽然Go推荐使用错误处理而非异常，但它提供了`panic`和`recover`机制处理不可恢复的情况。

### panic

`panic`会导致程序立即停止正常执行，开始执行所有的`defer`语句，然后程序终止：

```go
func divide(a, b int) int {
    if b == 0 {
        panic("除数不能为零") // 触发恐慌
    }
    return a / b
}
```

### recover

`recover`可以捕获`panic`并恢复正常执行，但只能在`defer`函数中使用：

```go
func safeOperation() {
    defer func() {
        if r := recover(); r != nil {
            fmt.Println("已恢复:", r) // 捕获恐慌
        }
    }()
    
    fmt.Println("执行危险操作")
    panic("发生错误") // 触发恐慌
    fmt.Println("此行不会执行")
}
```

### panic和recover的实际应用

```go
// HTTP请求处理器中恢复恐慌
func handleRequest(w http.ResponseWriter, r *http.Request) {
    defer func() {
        if err := recover(); err != nil {
            log.Printf("处理请求时恐慌: %v", err)
            http.Error(w, "内部服务器错误", http.StatusInternalServerError)
        }
    }()
    
    // 正常的请求处理...
}
```

## 实践示例

### 1. 实现重试逻辑

```go
func retryOperation(operation func() error, maxRetries int) error {
    var lastError error
    
    for i := 0; i < maxRetries; i++ {
        err := operation()
        if err == nil {
            return nil // 成功，无需重试
        }
        
        lastError = err
        fmt.Printf("操作失败(尝试%d/%d): %v\n", i+1, maxRetries, err)
        
        if i < maxRetries-1 {
            // 指数退避策略
            delay := time.Duration(math.Pow(2, float64(i))) * time.Second
            fmt.Printf("等待%v后重试...\n", delay)
            time.Sleep(delay)
        }
    }
    
    return fmt.Errorf("达到最大重试次数(%d): %w", maxRetries, lastError)
}

// 使用示例
func main() {
    err := retryOperation(func() error {
        // 尝试连接数据库或发送API请求
        return errors.New("连接失败")
    }, 3)
    
    if err != nil {
        fmt.Println("最终错误:", err)
    }
}
```

### 2. 实现状态机

```go
type State int

const (
    StateInit State = iota
    StateProcessing
    StateFinished
    StateError
)

func (s State) String() string {
    return [...]string{"初始化", "处理中", "已完成", "错误"}[s]
}

type StateMachine struct {
    currentState State
    data         map[string]interface{}
}

func NewStateMachine() *StateMachine {
    return &StateMachine{
        currentState: StateInit,
        data:         make(map[string]interface{}),
    }
}

func (sm *StateMachine) Process() {
    for {
        switch sm.currentState {
        case StateInit:
            fmt.Println("当前状态:", sm.currentState)
            // 初始化逻辑
            sm.data["initialized"] = true
            sm.currentState = StateProcessing
            
        case StateProcessing:
            fmt.Println("当前状态:", sm.currentState)
            // 处理逻辑
            if rand.Intn(10) < 8 {
                sm.data["processed"] = true
                sm.currentState = StateFinished
            } else {
                sm.data["error"] = "随机错误"
                sm.currentState = StateError
            }
            
        case StateFinished:
            fmt.Println("当前状态:", sm.currentState)
            fmt.Println("处理成功完成")
            return
            
        case StateError:
            fmt.Println("当前状态:", sm.currentState)
            fmt.Println("处理错误:", sm.data["error"])
            return
        }
    }
}
```

### 3. 使用错误处理实现验证管道

```go
type Validator func(interface{}) error

func validate(data interface{}, validators ...Validator) error {
    for _, validator := range validators {
        if err := validator(data); err != nil {
            return err
        }
    }
    return nil
}

// 验证器示例
func validateNotEmpty(data interface{}) error {
    s, ok := data.(string)
    if !ok {
        return errors.New("数据不是字符串类型")
    }
    if s == "" {
        return errors.New("字符串不能为空")
    }
    return nil
}

func validateLength(minLen, maxLen int) Validator {
    return func(data interface{}) error {
        s, ok := data.(string)
        if !ok {
            return errors.New("数据不是字符串类型")
        }
        if len(s) < minLen {
            return fmt.Errorf("字符串长度必须大于等于%d", minLen)
        }
        if len(s) > maxLen {
            return fmt.Errorf("字符串长度必须小于等于%d", maxLen)
        }
        return nil
    }
}

func validateEmail(data interface{}) error {
    s, ok := data.(string)
    if !ok {
        return errors.New("数据不是字符串类型")
    }
    if !strings.Contains(s, "@") {
        return errors.New("不是有效的电子邮箱地址")
    }
    return nil
}

// 使用验证管道
func main() {
    email := "user@example.com"
    
    err := validate(email,
        validateNotEmpty,
        validateLength(3, 100),
        validateEmail,
    )
    
    if err != nil {
        fmt.Println("验证失败:", err)
    } else {
        fmt.Println("验证通过:", email)
    }
}
```

## 总结

Go的控制流结构简洁而强大：

1. **条件语句**：`if-else`和`switch`提供了灵活的条件分支逻辑，特别是`switch`支持多种表达式和类型判断。

2. **循环语句**：统一使用`for`循环，配合`range`可以方便地遍历各种数据结构。

3. **跳转语句**：`break`、`continue`和`goto`提供了控制流跳转的功能，带标签的跳转可以处理复杂嵌套结构。

4. **错误处理**：使用返回错误值而非异常处理错误，清晰地表达了错误可能发生的地方。

5. **延迟执行**：`defer`语句确保资源释放和清理代码在函数退出时执行，提高代码的健壮性。

6. **恐慌与恢复**：`panic`和`recover`提供了处理不可恢复错误的机制，但应当谨慎使用。

这些控制流结构共同构成了Go程序清晰、高效的执行路径，是编写可靠Go程序的基础。 