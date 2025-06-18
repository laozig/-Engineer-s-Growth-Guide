# 现代 C++: RAII 与智能指针

C++11 及后续标准引入了大量强大的特性，旨在让 C++ 编程更安全、更高效、更富有表现力。其中，**智能指针**（Smart Pointers）是现代 C++ 资源管理的核心，它们是 **RAII**（Resource Acquisition Is Initialization，资源获取即初始化）设计模式的完美体现。

## 1. RAII 设计模式

RAII 是 C++ 语言中最重要的编程范式之一。它的核心思想是：

> 将资源的生命周期与一个对象的生命周期绑定。资源在对象创建时被获取（例如，在构造函数中分配内存、打开文件、加锁），在对象销毁时被自动释放（例如，在析构函数中释放内存、关闭文件、解锁）。

这样做的好处是，开发者无需手动调用 `delete`、`fclose` 等释放函数。只要对象被正确地销毁（例如，当它离开作用域时），其管理的资源就会被**自动**、**确定性**地释放，即使在发生异常的情况下也能保证。这极大地减少了资源泄漏的风险，使得代码更健壮。

## 2. 智能指针：RAII 的实践者

智能指针是行为类似于原生指针（如 `int*`）的类模板，但它们能自动管理所指向的对象的生命周期。当智能指针本身被销毁时，它会自动释放所指向的对象。

现代 C++ 在 `<memory>` 头文件中主要提供了三种智能指针：

- `std::unique_ptr`: 独占所有权的智能指针。
- `std::shared_ptr`: 共享所有权的智能指针。
- `std::weak_ptr`: `shared_ptr` 的观察者，不影响对象生命周期。

---

### a. `std::unique_ptr`

`unique_ptr` 对其管理的资源拥有**独占所有权**。这意味着在任何时刻，只有一个 `unique_ptr` 可以指向给定的对象。

**核心特点**:
- **独占性**: 不可复制（`copy`），只可移动（`move`）。这在编译期就保证了所有权的唯一性。
- **轻量级**: 与原生指针大小相同，无额外的性能开销。
- **自动释放**: 当 `unique_ptr` 离开作用域时，它会自动调用 `delete` 释放其指向的对象。

**使用场景**:
- 当你明确知道一个对象只需要一个所有者时，`unique_ptr` 是默认的最佳选择。
- 作为工厂函数的返回值。
- 在类中管理只属于该类实例的资源。

```cpp
#include <iostream>
#include <memory>

class MyResource {
public:
    MyResource() { std::cout << "Resource Acquired\n"; }
    ~MyResource() { std::cout << "Resource Released\n"; }
    void do_work() { std::cout << "Doing work...\n"; }
};

void process_resource(std::unique_ptr<MyResource> res) {
    if (res) {
        res->do_work();
    }
    // 当函数结束时，res 离开作用域，自动释放资源
}

int main() {
    // 推荐使用 std::make_unique 创建 unique_ptr (C++14+)
    // 它可以避免某些异常安全问题
    auto ptr1 = std::make_unique<MyResource>();

    // ptr1->do_work(); // 可以像普通指针一样使用

    // 所有权从 ptr1 转移到 process_resource 函数的参数 res
    process_resource(std::move(ptr1));

    // 此时 ptr1 为 nullptr，因为它已不再拥有资源
    if (!ptr1) {
        std::cout << "ptr1 is now empty.\n";
    }

    return 0; // 程序结束
}
// 输出:
// Resource Acquired
// Doing work...
// Resource Released
// ptr1 is now empty.
```

---

### b. `std::shared_ptr`

`shared_ptr` 实现了**共享所有权**。多个 `shared_ptr` 可以指向同一个对象。它内部维护一个"引用计数"，记录有多少个 `shared_ptr` 共同指向该对象。

**核心特点**:
- **共享性**: 可以被自由地复制，每次复制都会导致引用计数增加。
- **自动释放**: 当最后一个指向对象的 `shared_ptr` 被销毁或重置时（引用计数变为 0），它会自动释放所管理的对象。
- **开销**: 比 `unique_ptr` 稍大，因为它需要额外存储一个控制块（Control Block）来管理引用计数等信息。

**使用场景**:
- 当你不确定一个对象的生命周期，或者需要多个指针共同管理同一个资源时。
- 在数据结构中（如图、树）的节点间共享数据。
- 作为回调函数的参数，以确保回调执行时对象仍然有效。

```cpp
#include <iostream>
#include <memory>
#include <vector>

class SharedData {
public:
    SharedData() { std::cout << "SharedData Acquired\n"; }
    ~SharedData() { std::cout << "SharedData Released\n"; }
};

int main() {
    std::shared_ptr<SharedData> p1;
    {
        // 推荐使用 std::make_shared
        auto p2 = std::make_shared<SharedData>();
        std::cout << "Use count: " << p2.use_count() << std::endl; // 输出 1

        p1 = p2; // p1 和 p2 共享所有权
        std::cout << "Use count: " << p1.use_count() << std::endl; // 输出 2
    } // p2 离开作用域，被销毁，引用计数减 1

    std::cout << "After inner scope, use count: " << p1.use_count() << std::endl; // 输出 1

    return 0; // p1 离开作用域，引用计数变为 0，资源被释放
}
// 输出:
// SharedData Acquired
// Use count: 1
// Use count: 2
// After inner scope, use count: 1
// SharedData Released
```

---

### c. `std::weak_ptr`

`weak_ptr` 是 `shared_ptr` 的一个"助手"。它是一种非拥有（non-owning）的智能指针，它指向由 `shared_ptr` 管理的对象，但**不会增加引用计数**。

**核心特点**:
- **观察者**: 它只观察对象，不参与对象的生命周期管理。
- **打破循环引用**: `weak_ptr` 的主要用途是解决 `shared_ptr` 可能导致的循环引用（Cyclic Dependency）问题。
- **安全性**: 在访问其指向的对象之前，必须先将其转换为一个 `shared_ptr`（通过调用 `lock()` 方法）。如果对象已被销毁，`lock()` 会返回一个空的 `shared_ptr`，从而避免了悬挂指针问题。

**使用场景**:
- 解决 `shared_ptr` 的循环引用，例如在双向链表或父子节点相互引用的场景中。
- 实现缓存系统，缓存项可以用 `weak_ptr` 指向，当对象在别处被销毁后，缓存可以安全地检测到。

```cpp
#include <iostream>
#include <memory>

struct Node {
    std::shared_ptr<Node> next;
    std::weak_ptr<Node> prev; // 使用 weak_ptr 打破循环
    ~Node() { std::cout << "Node destroyed\n"; }
};

int main() {
    auto node1 = std::make_shared<Node>();
    auto node2 = std::make_shared<Node>();

    node1->next = node2;
    node2->prev = node1; // 如果这里用 shared_ptr，会产生循环引用

    // 两个节点都能被正确销毁，因为 prev 不增加引用计数
    return 0;
}
// 输出:
// Node destroyed
// Node destroyed
```
如果没有 `weak_ptr`，`node1` 和 `node2` 的引用计数永远不会降为 0，从而导致内存泄漏。

## 总结

- **优先使用 `std::unique_ptr`**: 它最轻量，且所有权模型最清晰。
- **当需要共享所有权时，使用 `std::shared_ptr`**。
- **使用 `std::weak_ptr` 来打破 `std::shared_ptr` 的循环引用**。
- **总是优先使用 `std::make_unique` 和 `std::make_shared`**，而不是直接使用 `new`。

智能指针是现代 C++ 管理资源的首选方式，它们是编写安全、无泄漏代码的基石。 