# Rust 嵌入式开发

嵌入式系统开发是 Rust 发挥其独特优势的另一个关键领域。传统上，嵌入式开发由 C 和 C++ 主导，但这些语言在内存安全方面存在固有的挑战。Rust 带来了现代语言的特性、强大的类型系统和编译时安全保证，使其成为编写可靠、高效的嵌入式固件的理想选择。

## 1. 为什么选择 Rust 进行嵌入式开发？

- **可靠性**: Rust 的内存安全和线程安全保证在编译时就消除了许多可能导致系统崩溃的常见错误，这对于需要长时间稳定运行的嵌入式设备至关重要。
- **性能**: 作为一门编译型语言，Rust 提供了与 C/C++ 相媲美的运行时性能和对硬件的底层控制能力，没有垃圾回收带来的不可预测的延迟。
- **`#[no_std]` 环境**: Rust 可以不依赖标准库 (`std`) 进行开发，仅使用核心库 (`core`)。这使得 Rust 程序可以运行在没有操作系统的裸机（bare-metal）环境中。
- **零成本抽象**: 你可以放心地使用 Rust 的高级抽象（如迭代器、闭包、泛型），而不用担心会产生额外的运行时开销。
- **并发性**: Rust 的并发模型使得在多核微控制器上编写安全的多任务固件变得更加容易。
- **活跃的社区**: Rust 嵌入式社区非常活跃，提供了大量的工具、库和硬件抽象层（HAL）来简化开发。

## 2. 核心概念

### 2.1. `#[no_std]` 和 `core` 库

- 在嵌入式开发中，通常使用 `#[no_std]` 属性来告诉编译器不要链接标准库 `std`。
- 你可以依赖 `core` 库，它提供了独立于平台的原始类型、基本特质和宏。
- 对于需要动态内存分配的场景，可以使用 `alloc` crate，并提供一个全局分配器的实现。

### 2.2. 硬件抽象层 (HAL)

硬件抽象层（HAL）是嵌入式 Rust 生态系统的基石。HAL 是一个 Rust crate，它为特定微控制器（MCU）家族的外设（如 GPIO, UART, SPI, I2C 等）提供了安全、高级的 API。

- **`embedded-hal`**: 这是一个定义了一系列通用特质的 crate，这些特质描述了与硬件交互的通用操作（例如，数字引脚的 `InputPin`, `OutputPin`）。
- **芯片级 HAL (`e.g., stm32f4xx-hal`, `nrf52840-hal`)**:
  - 这些 crate 为特定的芯片实现了 `embedded-hal` 的特质。
  - 它们处理了所有与寄存器操作相关的底层、不安全的细节，并向上层提供了安全的接口。
- **板级支持包 (BSP - Board Support Package)**:
  - BSP 位于 HAL 之上，为特定的开发板（如 STM32 Nucleo, Raspberry Pi Pico）提供了更高级的抽象，例如将特定引脚映射到板载的 LED 或按钮。

### 2.3. 并发模型

在嵌入式系统中，通常需要同时处理多个任务（例如，读取传感器数据、更新显示、响应用户输入）。

- **中断驱动**:
  - 这是最基本的并发形式。你可以为硬件中断（如定时器中断、引脚电平变化中断）注册处理函数。
  - 在中断服务程序（ISR）中执行代码需要特别小心，因为它们会打断主程序的执行。

- **RTIC (Real-Time For the Masses)**:
  - RTIC 是一个流行的嵌入式并发框架，它利用 Rust 的静态分析能力在编译时就保证任务之间的数据共享是无数据竞争的。
  - 它基于任务和资源模型，调度开销极低，非常适合硬实时应用。

```rust,ignore
// RTIC 应用示例
#[rtic::app(device = pac::PERIPHERALS, dispatchers = [USART1])]
mod app {
    #[shared]
    struct Shared {
        // ... 共享资源
    }

    #[local]
    struct Local {
        // ... 本地资源
    }

    #[init]
    fn init(cx: init::Context) -> (Shared, Local, init::Monotonics) {
        // ... 初始化代码
    }

    #[task(binds = TIM2, local = [led], shared = [shared_res])]
    fn timer_task(cx: timer_task::Context) {
        // ... 定时任务
    }
}
```

- **嵌入式操作系统/运行时**:
  - 对于更复杂的应用，可以使用像 `Embassy` 或 `Tock` 这样的异步运行时或嵌入式操作系统。
  - `Embassy` 是一个现代的异步嵌入式框架，将 `async`/`.await` 引入嵌入式开发，使得编写复杂的、非阻塞的逻辑变得非常简单。

### 2.4. 工具链

- **交叉编译**: 你需要在你的开发机（通常是 x86_64）上为目标嵌入式平台（如 ARM Cortex-M）进行交叉编译。使用 `rustup target add <target-triple>` 可以轻松安装目标工具链。
- **`probe-rs` / `cargo-embed`**:
  - `probe-rs` 是一个用于与调试探针（如 J-Link, ST-Link）交互的工具集。
  - `cargo-embed` 是一个基于 `probe-rs` 的 Cargo 子命令，它将编译、烧写固件和启动调试会话（包括 GDB 和 RTT 日志输出）等步骤集成到一个命令中，极大地简化了开发流程。

## 3. 开发流程示例 (以 Raspberry Pi Pico 为例)

1.  **安装模板和工具**:
    ```bash
    # 安装交叉编译目标
    rustup target add thumbv6m-none-eabi
    # 安装烧写和调试工具
    cargo install cargo-embed
    # 从模板创建项目
    cargo generate --git https://github.com/rp-rs/rp2040-project-template
    ```

2.  **编写 "Blinky" 程序**:
    - 在生成的项目中，`src/main.rs` 会包含一个闪烁板载 LED 的示例代码。
    - 代码会使用 `rp2040-hal` 来获取对外设的控制权，并配置一个 GPIO 引脚为输出模式，然后在循环中切换其电平。

3.  **编译和烧写**:
    - 将你的 Raspberry Pi Pico 通过 USB 连接到电脑。
    - 在项目目录下运行：
      ```bash
      cargo embed --release
      ```
    - `cargo-embed` 会自动编译你的代码，找到连接的调试探针，并将固件烧写到芯片上。

## 总结

Rust 正在迅速成为嵌入式系统开发的一个强大选择。
- 它通过**编译时安全检查**和**零成本抽象**解决了传统嵌入式开发的许多痛点。
- **硬件抽象层 (HAL)** 和 **`embedded-hal`** 提供了一个统一、可移植的硬件访问接口。
- **RTIC** 和 **Embassy** 等并发框架使得构建复杂的、可靠的实时应用成为可能。
- **现代化的工具链** (`cargo-embed`, `probe-rs`) 提供了流畅的开发体验。

对于寻求更高可靠性、安全性和开发效率的嵌入式工程师来说，学习和采用 Rust 是一项非常有价值的投资。 