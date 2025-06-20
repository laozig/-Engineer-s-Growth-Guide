# 测试: JUnit 5, Mockito, 集成测试, TDD

在软件开发中，测试是保证代码质量、功能正确性和系统稳定性的基石。一个没有测试覆盖的项目是脆弱且难以维护的。Spring Boot 通过 `spring-boot-starter-test` 提供了强大的测试支持，它默认集成了 JUnit 5, Mockito, AssertJ, Spring Test 等一流的测试框架。

---

## 1. 测试金字塔

测试金字塔是一个描述不同类型测试数量和成本的模型：

-   **单元测试 (Unit Tests)** (金字塔底层):
    -   **目标**: 测试最小的可测试单元（如一个方法或一个类），隔离地进行。
    -   **特点**: 运行速度快，数量最多，编写成本低。
    -   **工具**: JUnit 5, Mockito。
-   **集成测试 (Integration Tests)** (金字塔中层):
    -   **目标**: 测试多个组件（类、服务）如何协同工作。例如，测试 Controller -> Service -> Repository 的整个调用链路。
    -   **特点**: 运行速度比单元测试慢，数量适中。
-   **端到端测试 (End-to-End Tests)** (金字塔顶层):
    -   **目标**: 模拟真实用户场景，测试整个应用的完整流程（从 UI 到数据库）。
    -   **特点**: 运行最慢，最脆弱，数量最少，编写和维护成本最高。
    -   **工具**: Selenium, Cypress。

本章主要关注单元测试和集成测试。

---

## 2. 单元测试

### 2.1. JUnit 5

JUnit 5 是 Java 单元测试的最新标准。
**常用注解**:
-   `@Test`: 标记一个方法为测试方法。
-   `@BeforeEach`: 在每个 `@Test` 方法运行 **前** 执行。
-   `@AfterEach`: 在每个 `@Test` 方法运行 **后** 执行。
-   `@BeforeAll`: 在所有测试方法运行 **前** 执行一次（必须是静态方法）。
-   `@AfterAll`: 在所有测试方法运行 **后** 执行一次（必须是静态方法）。
-   `@DisplayName`: 为测试类或方法提供一个更具可读性的名称。
-   `@Disabled`: 禁用一个测试。

**断言 (Assertions)**: 使用 `org.junit.jupiter.api.Assertions` 类或更流畅的 AssertJ 来验证结果。
```java
import static org.junit.jupiter.api.Assertions.*;
import static org.assertj.core.api.Assertions.*; // AssertJ

@DisplayName("Calculator Unit Tests")
class CalculatorTest {
    @Test
    @DisplayName("1 + 1 = 2")
    void addsTwoNumbers() {
        Calculator calculator = new Calculator();
        // JUnit 5 assertion
        assertEquals(2, calculator.add(1, 1), "1 + 1 should equal 2");
        // AssertJ assertion (更推荐，提供流畅的API和更丰富的断言)
        assertThat(calculator.add(1, 1)).isEqualTo(2);
    }
}
```

### 2.2. Mockito: 模拟对象

在单元测试中，我们希望 **隔离** 被测试的类。如果 `UserService` 依赖于 `UserRepository`，我们不希望在测试 `UserService` 时真正地去调用数据库。这时就需要 **模拟 (Mock)** `UserRepository`。

Mockito 是一个流行的模拟框架。

-   **`@Mock`**: 创建一个模拟对象。
-   **`@InjectMocks`**: 创建一个类的实例，并将使用 `@Mock` 创建的模拟对象注入到其中。
-   **`when(...).thenReturn(...)`**: 定义当模拟对象的某个方法被调用时，应该返回什么。
-   **`verify(...)`**: 验证模拟对象的某个方法是否被以期望的方式调用过。

**示例：测试 `UserService`**
```java
// UserService.java
public class UserService {
    private final UserRepository userRepository;
    public UserService(UserRepository userRepository) { this.userRepository = userRepository; }

    public User findUserById(Long id) {
        return userRepository.findById(id).orElse(null);
    }
}

// UserServiceTest.java
@ExtendWith(MockitoExtension.class) // JUnit 5 整合 Mockito
class UserServiceTest {

    @Mock
    private UserRepository userRepository; // 1. 模拟依赖

    @InjectMocks
    private UserService userService; // 2. 创建被测试对象并注入模拟依赖

    @Test
    @DisplayName("Should return user when user is found")
    void findUserById_whenUserExists() {
        // 3. 准备 (Arrange / Given)
        User user = new User(1L, "John Doe");
        // 当 userRepository.findById(1L) 被调用时，返回 Optional.of(user)
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));

        // 4. 执行 (Act / When)
        User foundUser = userService.findUserById(1L);

        // 5. 验证 (Assert / Then)
        assertThat(foundUser).isNotNull();
        assertThat(foundUser.getName()).isEqualTo("John Doe");

        // 验证 userRepository.findById(1L) 被调用了且仅调用了一次
        verify(userRepository, times(1)).findById(1L);
    }
}
```

---

## 3. 集成测试

在 Spring Boot 中，集成测试通常需要启动一个完整的或部分的 Spring 应用上下文 (Application Context)。

-   `@SpringBootTest`: 标记这是一个 Spring Boot 集成测试。它会加载完整的应用上下文。
-   `@AutoConfigureMockMvc`: 自动配置一个 `MockMvc` 对象，用于对 Controller 层进行测试，而无需启动一个真正的 HTTP 服务器。
-   `@DataJpaTest`: 只测试 JPA 相关的部分。它会配置一个内存数据库（如 H2），并只加载与 JPA 相关的 Bean (Entities, Repositories)。
-   `@WebMvcTest`: 只测试 Web 层 (Controller)。它不会加载 Service 或 Repository 层的 Bean。

### 示例：测试 Controller 层
```java
@WebMvcTest(UserController.class) // 只测试 UserController
@AutoConfigureMockMvc
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc; // 用于模拟 HTTP 请求

    @MockBean // 使用 Mockito 的模拟 Bean 替代真实的 UserService
    private UserService userService;

    @Test
    void whenGetUserById_thenReturnUser() throws Exception {
        // Given
        User user = new User(1L, "API User");
        when(userService.getUserById(1L)).thenReturn(Optional.of(user));

        // When & Then
        mockMvc.perform(get("/api/users/1") // 模拟 GET 请求
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk()) // 期望状态码 200
                .andExpect(jsonPath("$.name", is("API User"))); // 期望返回的 JSON 中 name 字段是 "API User"
    }
}
```

---

## 4. 测试驱动开发 (Test-Driven Development, TDD)

TDD 是一种软件开发过程，它要求开发者在编写任何功能代码之前，先编写一个失败的自动化测试用例。

**TDD 的节奏：红-绿-重构 (Red-Green-Refactor)**
1.  **红 (Red)**: 写一个测试，它描述了你想要实现的功能。运行它，它会因为功能尚未实现而失败（变红）。
2.  **绿 (Green)**: 编写 **最简单** 的代码来让测试通过（变绿）。此时不追求代码质量，只求快速通过测试。
3.  **重构 (Refactor)**: 在测试通过的保护下，改进和重构刚刚编写的代码，使其更清晰、更高效，同时确保测试仍然通过。

TDD 的好处在于，它强迫你在一开始就清晰地思考需求和设计，并且最终产出的代码都自带一套完整的测试用例，这极大地增强了代码的健壮性和可维护性。
