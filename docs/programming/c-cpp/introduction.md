# C/C++ 简介

C 和 C++ 是计算机科学史上最重要、最有影响力的两门编程语言。它们以其高性能、对硬件的底层控制能力以及广泛的应用领域而闻名。本指南将带你踏上学习这两门强大语言的旅程。

## 1. C 语言：现代语言的基石

C 语言由丹尼斯·里奇（Dennis Ritchie）于 1972 年在贝尔实验室开发出来，其主要目的是为了编写 UNIX 操作系统。

### C 的设计哲学

- **相信程序员**：C 语言赋予程序员极大的权力，允许直接操作内存地址、进行位运算等。它假设程序员清楚地知道自己在做什么。
- **小巧、快速、可移植**：C 的核心语言特性非常少，它依赖于一个标准库来提供大部分功能。这使得 C 的编译器易于实现，并且可以轻松地移植到各种不同的计算机架构上。
- **面向过程**：C 语言是一种过程式语言，它将程序看作是一系列函数的集合。代码的组织和结构围绕函数展开。

### C 语言的影响

C 语言是软件世界的基石。
- **操作系统**: 几乎所有的主流操作系统内核，包括 Windows、Linux、macOS、iOS 和 Android，其核心部分都是用 C 语言编写的。
- **嵌入式系统**: 从微波炉、汽车到航空航天设备，C 语言无处不在，是嵌入式系统开发的首选。
- **编程语言之母**: C++、Java、C#、Python、JavaScript、Go 等无数现代编程语言在语法或设计思想上都深受 C 语言的影响。

## 2. C++ 语言：C 的演进与扩展

C++ 由本贾尼·斯特劳斯特卢普（Bjarne Stroustrup）于 20 世纪 80 年代初在贝尔实验室开发，最初被称为"带类的C"（C with Classes）。

### C++ 的设计哲学

- **C 的超集**：C++ 的一个核心设计目标是与 C 语言保持高度兼容。基本上，所有合法的 C 代码也都是合法的 C++ 代码。这使得 C 程序员可以平滑地过渡到 C++。
- **支持多种编程范式**：C++ 不仅仅是面向对象的。它是一门多范式语言，同时支持过程式编程、面向对象编程 (OOP)、泛型编程和函数式编程。
- **零成本抽象**（Zero-Overhead Abstraction）：C++ 致力于提供高级的抽象机制（如类、模板、Lambda），同时不给程序带来额外的性能开销。你不需要为你没有使用的特性付出任何代价。

### C++ 的应用领域

C++ 在 C 语言强大的基础上，通过其高级抽象能力，扩展到了更多对性能和复杂度要求极高的领域：
- **游戏开发**: 顶级游戏引擎，如 Unreal Engine 和 Unity 的核心部分，都是用 C++ 构建的。
- **高性能计算 (HPC)**: 在科学计算、金融建模、物理模拟等领域，C++ 是标准工具。
- **桌面应用程序**: 许多大型桌面应用，如 Adobe Photoshop、Google Chrome 和 Microsoft Office，都大量使用了 C++。
- **后端服务**: 在需要处理高并发、低延迟的服务器端应用中，如搜索引擎和金融交易系统，C++ 仍然是关键技术。

## 3. C vs. C++: 我应该学习哪个？

**答案通常是：两者都学，从 C 开始。**

- **从 C 开始**：学习 C 语言能让你牢固地掌握编程的基本功，特别是内存管理、指针和计算机的工作原理。这是理解 C++ 更高级特性的坚实基础。
- **过渡到 C++**：在掌握了 C 之后，学习 C++ 会变得更加自然。你将学习如何使用类来组织代码，如何利用 STL (标准模板库) 来提高开发效率，以及如何运用现代 C++ 的特性来编写更安全、更简洁的代码。

本指南将遵循这一路径，首先带你深入 C 语言的核心，然后平滑地过渡到 C++ 的强大世界。

---

了解了 C/C++ 的背景后，下一步是[搭建你的开发环境](environment-setup.md)。 