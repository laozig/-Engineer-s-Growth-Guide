# Lambda 表达式与 Stream API

Java 8 是 Java 发展史上的一个里程碑版本，它引入了函数式编程的两个核心元素：Lambda 表达式和 Stream API。这极大地简化了集合的处理，让代码更简洁、更易读。

## 1. Lambda 表达式

Lambda 表达式可以被理解为一种简洁的、可传递的匿名函数。它允许你将函数作为方法的参数，或者将代码作为数据对待。

### 1.1. 语法

Lambda 表达式的基本语法是 `(parameters) -> expression` 或 `(parameters) -> { statements; }`。

-   `(int a, int b) -> a + b`
-   `(String s) -> System.out.println(s)`
-   `() -> 42` (无参数)
-   `(a, b) -> { int sum = a + b; return sum; }` (代码块)

### 1.2. 函数式接口 (Functional Interface)

Lambda 表达式的类型是一个 **函数式接口**。函数式接口是 **只包含一个抽象方法** 的接口。`@FunctionalInterface` 注解用于强制编译器检查一个接口是否满足此条件。

Java 内置了许多函数式接口，位于 `java.util.function` 包中，最核心的四个是：

-   `Predicate<T>`: 接收一个 `T` 类型的参数，返回一个 `boolean` 值。(`test` 方法)
-   `Function<T, R>`: 接收一个 `T` 类型的参数，返回一个 `R` 类型的结果。(`apply` 方法)
-   `Consumer<T>`: 接收一个 `T` 类型的参数，没有返回值 (消费数据)。(`accept` 方法)
-   `Supplier<T>`: 不接收参数，返回一个 `T` 类型的结果 (生产数据)。(`get` 方法)

**示例：**
```java
// 使用 Predicate 筛选偶数
Predicate<Integer> isEven = (n) -> n % 2 == 0;
System.out.println(isEven.test(4)); // true
System.out.println(isEven.test(5)); // false

// 使用 Function 将字符串转换为长度
Function<String, Integer> lengthFunc = (s) -> s.length();
System.out.println(lengthFunc.apply("hello")); // 5
```

---

## 2. Stream API

Stream API 是对集合 (Collection) 功能的巨大增强，它提供了一种声明式的方式来处理数据。Stream 不是数据结构，它不存储数据，而是像一个传送带，数据在上面流过并被处理。

### 2.1. Stream 的特点

-   **非破坏性**: Stream 操作不会修改源集合。它们会返回一个新的 Stream。
-   **惰性求值 (Lazy Evaluation)**: 中间操作（如 `filter`, `map`）不会立即执行，只有当遇到一个终端操作（如 `forEach`, `collect`）时，整个操作链才会触发。
-   **只能消费一次**: 一个 Stream 只能被"消费"（执行终端操作）一次。如果你需要再次遍历，必须从源数据重新创建一个新的 Stream。

### 2.2. Stream 的创建

-   从集合创建: `collection.stream()` 或 `collection.parallelStream()` (并行流)
-   从数组创建: `Arrays.stream(array)`
-   从值创建: `Stream.of("a", "b", "c")`
-   创建无限流: `Stream.iterate(0, n -> n + 2)` 或 `Stream.generate(Math::random)`

### 2.3. Stream 操作

Stream 操作分为两类：

1.  **中间操作 (Intermediate Operations)**:
    -   返回一个新的 Stream，可以链接多个中间操作。
    -   **`filter(Predicate<T> p)`**: 过滤元素。
    -   **`map(Function<T, R> f)`**: 转换元素（一对一映射）。
    -   **`flatMap(Function<T, Stream<R>> f)`**: 扁平化映射（一对多映射，将多个子 Stream 合并成一个）。
    -   **`sorted()`**: 自然排序。
    -   **`distinct()`**: 去除重复元素。
    -   **`limit(long n)`**: 截断流，使其元素不超过给定数量。
    -   **`skip(long n)`**: 跳过前 n 个元素。

2.  **终端操作 (Terminal Operations)**:
    -   触发计算并产生一个最终结果或副作用。
    -   **`forEach(Consumer<T> c)`**: 遍历每个元素。
    -   **`collect(Collector c)`**: 将 Stream 转换为其他形式，如 `List`, `Set`, `Map`。这是最常用的终端操作之一。
    -   **`count()`**: 返回元素总数。
    -   **`reduce(...)`**: 将流中的元素组合起来，得到一个单一的值。
    -   **`anyMatch(Predicate p)`**: 是否有任何一个元素匹配。
    -   **`allMatch(Predicate p)`**: 是否所有元素都匹配。
    -   **`findFirst()`**: 返回第一个元素 (`Optional`)。
    -   **`findAny()`**: 返回任意一个元素 (`Optional`)。

### 2.4. 综合示例

**需求**: 从一个包含用户对象的列表中，找出所有来自 "USA" 的用户，按年龄排序，并返回他们的名字列表。

```java
class User {
    String name;
    int age;
    String country;
    // constructor, getters...
}

List<User> users = // ... 初始化用户列表

// 传统写法
List<String> names = new ArrayList<>();
List<User> filteredUsers = new ArrayList<>();
for (User user : users) {
    if ("USA".equals(user.getCountry())) {
        filteredUsers.add(user);
    }
}
Collections.sort(filteredUsers, new Comparator<User>() {
    public int compare(User u1, User u2) {
        return Integer.compare(u1.getAge(), u2.getAge());
    }
});
for (User user : filteredUsers) {
    names.add(user.getName());
}

// Stream API 写法
List<String> streamNames = users.stream() // 1. 创建流
    .filter(user -> "USA".equals(user.getCountry())) // 2. 过滤
    .sorted(Comparator.comparingInt(User::getAge)) // 3. 排序
    .map(User::getName) // 4. 映射为名字
    .collect(Collectors.toList()); // 5. 收集为 List
```

可以看到，Stream API 的代码像一条流水线，清晰地描述了"做什么"，而不是"怎么做"，代码意图一目了然。

---

## 3. `Optional` 类

`Optional` 是 Java 8 引入的一个容器类，用于表示一个值可能存在或不存在。它旨在解决 `NullPointerException` 这个臭名昭著的问题。

Stream 的一些终端操作（如 `findFirst`, `reduce`）会返回 `Optional` 对象。

**常用方法**:
-   `isPresent()`: 判断值是否存在。
-   `get()`: 获取值（如果不存在会抛出 `NoSuchElementException`）。
-   `orElse(T other)`: 如果值存在则返回，否则返回 `other`。
-   `orElseGet(Supplier<? extends T> other)`: 如果值存在则返回，否则执行 `Supplier` 来生成一个默认值。
-   `ifPresent(Consumer<? super T> consumer)`: 如果值存在，则对其执行 `Consumer` 操作。

```java
Optional<String> found = users.stream()
                              .filter(u -> u.getName().equals("NonExistent"))
                              .map(User::getCountry)
                              .findFirst();

// 安全地处理可能不存在的值
String country = found.orElse("Unknown"); 
System.out.println(country); // 输出 "Unknown"
```
`Optional` 鼓励你显式地处理"可能没有值"的情况，从而编写出更健壮的代码。
