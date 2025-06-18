# C 语言：文件操作 (File I/O)

文件操作是任何编程语言都不可或缺的功能，它允许程序读取外部文件中的数据，并将数据永久地存储到文件中。在 C 语言中，文件操作主要通过标准 I/O 库 `<stdio.h>` 中定义的一系列函数和 `FILE` 类型来完成。

## 1. `FILE` 结构体

在 C 语言中，文件被看作是一个**流 (stream)**。当你打开一个文件时，操作系统会返回一个指向 `FILE` 结构体的指针。这个 `FILE` 结构体包含了管理该文件流所需的所有信息，如文件位置指示器、缓冲区等。我们不需要知道 `FILE` 结构体的内部细节，只需要通过这个指针来操作文件即可。

`FILE* p_file;`

## 2. 打开和关闭文件

### `fopen()` - 打开文件

`fopen()` 函数用于打开一个文件，并返回一个指向该文件的 `FILE` 指针。

**原型:**
`FILE* fopen(const char* filename, const char* mode);`

- **`filename`**: 要打开的文件的路径字符串。
- **`mode`**: 文件打开模式，决定了你可以对文件进行哪些操作。
- **返回值**:
    - 如果成功，返回一个有效的 `FILE*` 指针。
    - 如果失败（例如，文件不存在或没有权限），返回 `NULL`。

**常用的文件打开模式:**

| 模式 | 描述 | 如果文件不存在 | 如果文件存在 |
| :--- | :--- | :--- | :--- |
| `"r"`| **读 (Read)**：打开一个文本文件用于读取。 | 返回 `NULL` | 从文件开头读取 |
| `"w"`| **写 (Write)**：打开一个文本文件用于写入。 | 创建新文件 | **清空**文件内容后写入 |
| `"a"`| **追加 (Append)**：打开一个文本文件用于在末尾追加内容。| 创建新文件 | 从文件末尾写入 |
| `"r+"`| 读写：打开一个文本文件用于读写。| 返回 `NULL` | 从文件开头读写 |
| `"w+"`| 读写：打开一个文本文件用于读写。| 创建新文件 | **清空**文件内容后读写 |
| `"a+"`| 读写：打开一个文本文件用于读写追加。| 创建新文件 | 从文件末尾读写追加 |

在模式字符串后添加 `b`（如 `"rb"`, `"wb"`）可以按**二进制模式**操作文件。

### `fclose()` - 关闭文件

`fclose()` 函数用于关闭一个已打开的文件流，并将缓冲区中剩余的数据写入文件。

**原型:**
`int fclose(FILE* stream);`

- **返回值**: 如果成功关闭，返回 `0`；如果发生错误，返回 `EOF`。

**重要性**:
- **数据完整性**: `fclose` 会刷新缓冲区，确保所有写入操作都已完成。
- **资源释放**: 每个进程能打开的文件数量是有限的。关闭不再使用的文件可以释放系统资源。
- **养成习惯**: 打开文件后，应立即考虑在何处关闭它，通常在文件操作完成后进行。一个推荐的模式是，在检查 `fopen` 成功后，立即在文件末尾写下 `fclose`。

**基本操作流程:**
```c
#include <stdio.h>

int main() {
    FILE* p_file = NULL;
    const char* filename = "example.txt";

    p_file = fopen(filename, "w");

    // 必须检查 fopen 是否成功
    if (p_file == NULL) {
        printf("无法打开文件 %s\n", filename);
        return 1;
    }

    // ... 在这里进行文件操作 ...
    fprintf(p_file, "Hello, World!\n");

    // 关闭文件
    fclose(p_file);
    p_file = NULL; // 好习惯

    return 0;
}
```

## 3. 文件读写函数

### 格式化 I/O: `fprintf()` 和 `fscanf()`

这两个函数与 `printf` 和 `scanf` 非常相似，只是第一个参数是一个 `FILE` 指针。

- `int fprintf(FILE* stream, const char* format, ...);`
  - 将格式化的数据**写入**到文件中。
- `int fscanf(FILE* stream, const char* format, ...);`
  - 从文件中**读取**格式化的数据。

**示例：**
```c
// 写入
fprintf(p_file, "Name: %s, Age: %d\n", "Alice", 25);

// 读取
char name[50];
int age;
fscanf(p_file, "Name: %s, Age: %d\n", name, &age);
```

### 字符 I/O: `fgetc()` 和 `fputc()`

- `int fgetc(FILE* stream);`
  - 从文件中读取一个字符，并返回其整数表示。如果到达文件末尾或发生错误，返回 `EOF`。
- `int fputc(int character, FILE* stream);`
  - 将一个字符写入到文件中。

**示例：复制文件**
```c
FILE* src = fopen("source.txt", "r");
FILE* dest = fopen("destination.txt", "w");
// ... 检查文件打开是否成功 ...

int ch;
while ((ch = fgetc(src)) != EOF) {
    fputc(ch, dest);
}

fclose(src);
fclose(dest);
```

### 字符串 I/O: `fgets()` 和 `fputs()`

- `char* fgets(char* str, int n, FILE* stream);`
  - 从文件中读取一行（最多 `n-1` 个字符），并将其存储到 `str` 指向的字符数组中。它会自动在末尾添加 `\0`。如果读取成功，返回 `str`；如果到达文件末尾或出错，返回 `NULL`。
  - `fgets` 会读取换行符 `\n`。
- `int fputs(const char* str, FILE* stream);`
  - 将一个字符串写入到文件中。它**不会**自动添加换行符。

**示例：逐行读取文件**
```c
char line_buffer[256];
while (fgets(line_buffer, sizeof(line_buffer), p_file) != NULL) {
    printf("%s", line_buffer);
}
```

---

文件操作是程序与外部世界持久交互的桥梁。掌握它，你的程序就能处理配置文件、日志、用户数据等。接下来，我们将了解 C 语言编译过程中的一个重要阶段：[预处理器](c-preprocessor.md)。 