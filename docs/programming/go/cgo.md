# Go语言CGO与外部调用

CGO是Go语言提供的一个强大功能，它允许Go程序与C语言代码进行互操作。通过CGO，你可以在Go中调用C函数，也可以在C中调用Go函数。这为你利用现有的C库或者在性能关键部分使用C语言提供了极大的便利。

**注意**: 使用CGO会带来额外的复杂性，包括编译时间变长、跨平台编译变难、以及函数调用的性能开销。因此，只在必要时（如需要复用成熟的C库）才应使用CGO。

## 1. CGO基础

要启用CGO，只需在Go源文件中导入一个特殊的伪包`"C"`。

```go
package main

// #include <stdio.h>
// #include <stdlib.h>
//
// void myCFunction() {
//     printf("Hello from C!\n");
// }
import "C"
import "fmt"

func main() {
    fmt.Println("Calling C function from Go...")
    C.myCFunction()
    fmt.Println("...C function returned.")
}
```

- `import "C"`语句之前的注释块是CGO的关键部分，这里面可以编写纯C代码。
- 在Go代码中，可以通过`C.`前缀来访问C代码中定义的函数、变量、类型等。

## 2. Go与C的数据类型转换

Go和C的数据类型是不同的，需要进行显式转换。

### 2.1 基本数值类型
可以直接使用`C.`前缀的类型进行转换。
- Go `int` -> C `int`: `C.int(myGoInt)`
- C `int` -> Go `int`: `int(myCInt)`

### 2.2 字符串
Go的`string`和C的`char*`之间需要特定的函数进行转换。

- **Go `string` to C `char*`**: `C.CString()`
  - `C.CString`会在C的堆上分配内存，**必须手动通过`C.free()`释放**，否则会导致内存泄漏。

- **C `char*` to Go `string`**: `C.GoString()`
  - `C.GoString`会创建一个新的Go字符串，将C字符串的内容拷贝过来。

```go
// ...
// #include <stdlib.h>
import "C"
import (
    "fmt"
    "unsafe"
)

func main() {
    goStr := "Hello from Go"
    
    // Go string to C string
    cStr := C.CString(goStr)
    defer C.free(unsafe.Pointer(cStr)) // 关键：释放内存

    // C string to Go string
    backToGoStr := C.GoString(cStr)
    
    fmt.Println(backToGoStr)
}
```
**`unsafe.Pointer`**: 在调用`C.free`时，需要将C指针转换为`unsafe.Pointer`类型。`unsafe`包提供了绕过Go类型安全限制的能力，使用时需格外小心。

## 3. 调用外部C库

CGO也可以链接系统上已安装的或本地的C库。使用`#cgo`指令来告诉编译器链接参数。

- **`#cgo CFLAGS`**: 指定编译C代码时的标志。
- **`#cgo LDFLAGS`**: 指定链接时的标志，如`-L`指定库路径，`-l`指定库名。

**示例：链接一个名为`mylib`的本地库**
假设项目结构如下：
```
my-project/
├── mylib/
│   ├── mylib.c
│   └── mylib.h
└── main.go
```

`mylib.h`:
```c
void say_hello();
```
`mylib.c`:
```c
#include <stdio.h>
void say_hello() {
    printf("Hello from mylib!\n");
}
```

`main.go`:
```go
package main

// #cgo CFLAGS: -I./mylib
// #cgo LDFLAGS: -L./mylib -lmylib
// #include "mylib.h"
import "C"

func main() {
    C.say_hello()
}
```
在编译`main.go`之前，需要先将`mylib`编译为静态库（`libmylib.a`）或动态库。
```bash
# 编译为静态库
cd mylib
gcc -c mylib.c -o mylib.o
ar rcs libmylib.a mylib.o
cd ..

# 运行Go程序 (需要设置库搜索路径)
go run main.go 
# 或者更可靠地
CGO_LDFLAGS="-L$(pwd)/mylib" go run main.go
```

## 4. 从C调用Go函数

CGO也支持将Go函数导出给C代码使用。这需要满足两个条件：
1.  在Go函数前加上`//export MyGoFunction`的注释。
2.  Go函数必须是可导出的（首字母大写）。

**示例:**
`main.go`:
```go
package main

// #include <stdio.h>
//
// // 声明将要从Go导入的函数
// void MyGoFunction();
//
// static inline void callGoFunc() {
//     printf("C is about to call Go.\n");
//     MyGoFunction(); // 调用Go函数
// }
import "C"
import "fmt"

//export MyGoFunction
func MyGoFunction() {
    fmt.Println("Go function called by C.")
}

func main() {
    C.callGoFunc()
}
```
- `//export MyGoFunction`指令将`MyGoFunction`导出为C可以链接的符号。
- C代码部分需要有一个对应的函数声明。

## 5. 性能与注意事项

- **调用开销**: 每次Go和C之间的调用都有固定的性能开销，因为它涉及上下文切换（从Go的goroutine栈切换到C的系统线程栈）。因此，应避免在循环中进行高频的CGO调用。最好是传递一个大的数据块进行一次性处理，而不是分小块多次调用。
- **构建复杂性**: CGO依赖于C编译器（如GCC或Clang），这使得构建环境变得复杂。
- **跨平台编译**: `go build`的跨平台能力在CGO面前会失效。如果想交叉编译一个使用CGO的项目，你需要一个目标平台的C交叉编译器。
- **并发与线程**: Go的并发模型（goroutines）和C的线程模型不同。从C调用的Go函数将在一个新的goroutine中执行。需要小心处理线程安全问题。
- **Go GC与C内存**: Go的垃圾回收器无法管理C代码中分配的内存（如`malloc`）。**谁分配，谁释放**是使用CGO时必须遵守的黄金法则。 