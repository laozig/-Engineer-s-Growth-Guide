# Java IO 流

Java 的 I/O (输入/输出) 操作基于"流" (Stream) 的概念。流是一个有序的数据序列，可以作为数据的来源（输入流）或目的地（输出流）。Java IO 库 (`java.io`) 提供了丰富的类来处理各种类型的输入输出。

## 1. 流的分类

Java 的 IO 流可以从不同维度进行分类：

1.  **按数据流向**:
    *   **输入流 (Input Stream)**: 从数据源（如文件、网络）读取数据。
    *   **输出流 (Output Stream)**: 向目的地（如文件、网络）写入数据。

2.  **按处理单元**:
    *   **字节流 (Byte Stream)**: 以字节（8-bit）为单位处理数据。可以处理任何类型的数据（如图片、视频、文本文件）。所有字节流类都以 `InputStream` 或 `OutputStream` 结尾。
    *   **字符流 (Character Stream)**: 以字符（16-bit Unicode）为单位处理数据。专门用于处理文本数据，能自动处理字符编码。所有字符流类都以 `Reader` 或 `Writer` 结尾。

3.  **按功能角色**:
    *   **节点流 (Node Stream)**: 直接与数据源或目的地连接的流，如 `FileInputStream`、`FileWriter`。它们是底层流。
    *   **处理流 (Processing Stream)** / **包装流 (Wrapper Stream)**: "包装"在已存在的流（节点流或其他处理流）之上，为其提供额外的功能，如缓冲 (`BufferedInputStream`)、对象序列化 (`ObjectOutputStream`)。

```mermaid
graph TD
    subgraph "按数据流向"
        A[输入流]
        B[输出流]
    end
    subgraph "按处理单元"
        C[字节流]
        D[字符流]
    end
    subgraph "按功能角色"
        E[节点流]
        F[处理流]
    end
```

---

## 2. 核心字节流

### `InputStream` (抽象基类)
-   `int read()`: 读取下一个字节，返回 0-255 之间的整数，如果到达流末尾则返回 -1。
-   `int read(byte[] b)`: 读取多个字节到字节数组 `b` 中。

### `OutputStream` (抽象基类)
-   `void write(int b)`: 写入一个字节。
-   `void write(byte[] b)`: 写入一个字节数组。

**常用实现：`FileInputStream` 和 `FileOutputStream`**

```java
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class ByteStreamExample {
    public static void main(String[] args) {
        String inputFile = "source.txt";
        String outputFile = "destination.txt";

        // 使用 try-with-resources 自动关闭流
        try (FileInputStream in = new FileInputStream(inputFile);
             FileOutputStream out = new FileOutputStream(outputFile)) {
            
            int c;
            // 循环读取和写入
            while ((c = in.read()) != -1) {
                out.write(c);
            }
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

---

## 3. 核心字符流

### `Reader` (抽象基类)
-   `int read()`: 读取下一个字符，如果到达流末尾则返回 -1。

### `Writer` (抽象基类)
-   `void write(int c)`: 写入一个字符。

**常用实现：`FileReader` 和 `FileWriter`**

`FileReader` 和 `FileWriter` 专门用于读写文本文件。它们在内部使用 `FileInputStream` 和 `FileOutputStream`，并处理字节到字符的转换。

```java
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

public class CharacterStreamExample {
    public static void main(String[] args) {
        String inputFile = "source.txt";
        String outputFile = "destination_char.txt";

        try (FileReader reader = new FileReader(inputFile);
             FileWriter writer = new FileWriter(outputFile)) {

            int c;
            while ((c = reader.read()) != -1) {
                writer.write(c);
            }
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

---

## 4. 强大的处理流（包装流）

处理流的构造方法接收另一个流对象作为参数，它们提供了更强大、更方便的读写功能。

### 4.1. 缓冲流: `Buffered...`

-   `BufferedInputStream` / `BufferedOutputStream` (字节)
-   `BufferedReader` / `BufferedWriter` (字符)

**作用**: 增加一个内部缓冲区，减少对底层物理设备（如硬盘）的实际读写次数，从而 **极大地提高 I/O 性能**。

`BufferedReader` 还提供了一个非常有用的方法 `readLine()`，可以一次读取一行文本。

```java
// 使用缓冲流高效读写文本文件
try (BufferedReader br = new BufferedReader(new FileReader("input.txt"));
     BufferedWriter bw = new BufferedWriter(new FileWriter("output.txt"))) {
    
    String line;
    while ((line = br.readLine()) != null) {
        bw.write(line);
        bw.newLine(); // 写入一个平台无关的换行符
    }
    
} catch (IOException e) {
    e.printStackTrace();
}
```
**实践中，总是推荐使用缓冲流来包装节点流。**

### 4.2. 转换流: `InputStreamReader` / `OutputStreamWriter`

**作用**: 作为一座"桥梁"，将 **字节流** 转换为 **字符流**。这在处理需要指定字符编码（如 "UTF-8", "GBK"）的场景中至关重要。

```java
// 从网络套接字读取UTF-8编码的文本
// socket.getInputStream() 返回的是一个字节流
try (BufferedReader reader = new BufferedReader(
                                new InputStreamReader(socket.getInputStream(), "UTF-8"))) {
    String line;
    while ((line = reader.readLine()) != null) {
        // ... process line ...
    }
}
```

### 4.3. 对象流: `ObjectInputStream` / `ObjectOutputStream`

**作用**: 用于直接将 Java 对象写入流中（**序列化**），以及从流中读回对象（**反序列化**）。

-   **序列化 (Serialization)**: 将对象的状态信息转换为可以存储或传输的形式（如字节序列）的过程。
-   **反序列化 (Deserialization)**: 从序列化的形式中重新创建对象。

要被序列化的类必须实现 `java.io.Serializable` 标记接口。

```java
// User.java
public class User implements java.io.Serializable {
    private String name;
    private int age;
    // ... 构造器, getter/setter ...
}

// 序列化
try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("user.dat"))) {
    User user = new User("Alice", 30);
    oos.writeObject(user);
}

// 反序列化
try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream("user.dat"))) {
    User user = (User) ois.readObject();
    System.out.println(user.getName());
} catch (ClassNotFoundException e) {
    // ...
}
```

---

## 5. Java NIO (New I/O)

Java 1.4 引入了 `java.nio` 包，称为 New I/O 或 NIO。它提供了与标准 I/O 不同的 I/O 工作方式。

**NIO 的三大核心组件**:
1.  **Channels (通道)**: 类似于流，但通道是双向的。可以同时进行读写操作。
2.  **Buffers (缓冲区)**: 数据读写的中转站。数据总是先被读入缓冲区，然后再从缓冲区写入通道。
3.  **Selectors (选择器)**: 允许单个线程监控多个通道的 I/O 事件（如连接就绪、数据到达等），是实现高性能非阻塞 I/O 的关键。

NIO 的模型更适合于需要管理成千上万个并发连接的 I/O 密集型应用，例如网络服务器。对于简单的文件读写，传统 IO 更为简单直观。
