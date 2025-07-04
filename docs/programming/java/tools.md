# 附录：开发工具与资源

工欲善其事，必先利其器。拥有高效的工具和优质的学习资源，可以极大地提升 Java 开发的效率和体验。

---

## 1. 集成开发环境 (IDE)

-   **IntelliJ IDEA (强烈推荐)**:
    -   由 JetBrains 公司开发，被广泛认为是 Java 开发的 **最佳 IDE**。
    -   **Ultimate (旗舰版)**: 功能最全，付费。提供强大的 Spring, Java EE, 数据库等支持。学生和开源项目可免费申请。
    -   **Community (社区版)**: 免费。支持 Java, Kotlin, Groovy, Scala, Android 开发，对 Maven/Gradle 支持良好。对于纯粹的 Spring Boot 开发也足够使用。
-   **Visual Studio Code (VS Code)**:
    -   一个轻量级但功能强大的代码编辑器。通过安装 **Extension Pack for Java**，可以获得包括代码补全、调试、测试、Maven/Gradle 支持等在内的完整 Java 开发体验。
    -   启动速度快，占用资源少，适合快速编辑和小型项目。
-   **Eclipse**:
    -   一个历史悠久、完全开源的 IDE。功能强大，拥有庞大的插件生态系统。
    -   对于 Spring 开发，可以下载 **Spring Tools 4 for Eclipse**。

---

## 2. 构建与依赖管理

-   **Maven**: 成熟、稳定，基于 XML 配置。拥有庞大的社区和插件库，是许多企业项目的标准。
-   **Gradle**: 灵活、现代，使用 Groovy/Kotlin DSL。构建速度通常比 Maven 更快，是 Android 官方的构建工具。

---

## 3. API 测试与调试

-   **Postman**:
    -   一个功能强大的 API 开发协作平台。可以轻松地发送 HTTP 请求（GET, POST, PUT, DELETE 等），测试和调试 RESTful API。
    -   支持环境变量、集合、自动化测试脚本。
-   **Insomnia**:
    -   一个设计简洁、开源的 API 测试工具，是 Postman 的一个有力竞争者。
-   **curl / httpie**:
    -   命令行工具，适合在终端中进行快速的 API 测试。httpie 提供了更友好、更易读的语法和输出格式。

---

## 4. 数据库工具

-   **DBeaver**:
    -   一个免费、开源的通用数据库管理工具。支持几乎所有主流的关系型和非关系型数据库。
-   **DataGrip**:
    -   由 JetBrains 开发的专业数据库 IDE（付费）。与 IntelliJ IDEA 无缝集成，提供强大的 SQL 编辑、查询和数据库管理功能。
-   **Navicat / Sequel Pro (macOS)**: 其他流行的图形化数据库客户端。

---

## 5. 容器化与虚拟机

-   **Docker Desktop**: 在 Windows 和 macOS 上运行和管理 Docker 容器的最简单方式。
-   **JDK 管理**:
    -   **SDKMAN! (Linux/macOS)**: 一个强大的软件开发工具包管理器，可以轻松地安装、切换和管理多个版本的 JDK。
    -   **jEnv (Linux/macOS)**: 一个专注于管理 Java 环境的工具。

---

## 6. 在线学习资源

-   **官方文档**:
    -   **Spring.io**: Spring 官方网站，所有 Spring 项目的权威文档和指南。
    -   **Baeldung**: 一个非常优秀的第三方 Spring 和 Java 教程网站。
    -   **Oracle Java Documentation**: Java 官方的 API 文档。
-   **在线课程**: Coursera, edX, Udemy 等平台上有大量高质量的 Java 和 Spring 课程。
-   **社区**:
    -   **Stack Overflow**: 程序员的问答社区。
    -   **GitHub**: 探索优秀的开源项目，学习最佳实践。
-   **书籍**:
    -   《Effective Java》 (Joshua Bloch)
    -   《Spring in Action》 (Craig Walls)
    -   《Designing Data-Intensive Applications》 (Martin Kleppmann)

选择并熟练掌握一套适合自己的工具，将使你的开发之旅事半功倍。
