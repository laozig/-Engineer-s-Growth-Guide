# 构建工具：Maven 与 Gradle

在现代 Java 开发中，构建工具是不可或缺的一环。它们自动化了项目的构建过程，包括依赖管理、编译、测试、打包和部署。Maven 和 Gradle 是 Java 世界中最主流的两大构建工具。

---

## 1. Maven

Maven 是一个成熟、稳定的项目管理和整合工具。它基于 **项目对象模型 (Project Object Model, POM)** 的概念，使用一个名为 `pom.xml` 的文件来管理项目的构建、报告和文档。

### 1.1. 核心概念

-   **POM (Project Object Model)**: `pom.xml` 文件是 Maven 的核心。它定义了项目的所有配置，包括项目坐标、依赖、插件、目标等。
-   **坐标 (Coordinates)**: 在 Maven 的世界里，任何一个依赖、插件或项目本身都需要由一组坐标来唯一标识。
    -   `groupId`: 项目组ID，通常是公司或组织的逆向域名 (e.g., `com.google.guava`)。
    -   `artifactId`: 项目ID，通常是项目的名称 (e.g., `guava`)。
    -   `version`: 版本号 (e.g., `31.1-jre`)。
-   **依赖管理 (Dependency Management)**: Maven 会自动下载项目所需的依赖库（JARs）并管理它们的版本。它还支持 **传递性依赖**，即自动管理依赖的依赖。
-   **仓库 (Repository)**: 用于存储所有项目依赖的地方。
    -   **本地仓库**: 位于开发者本机 (`~/.m2/repository`)。
    -   **中央仓库**: Maven 官方提供的全球性仓库。
    -   **远程仓库 (私服)**: 公司或组织内部搭建的仓库。
-   **生命周期与插件 (Lifecycle & Plugins)**: Maven 定义了标准的构建生命周期（如 `clean`, `validate`, `compile`, `test`, `package`, `install`, `deploy`）。构建的实际工作由插件（Plugins）完成，插件的目标（Goals）可以绑定到生命周期的特定阶段（Phase）。

### 1.2. `pom.xml` 示例

```xml
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">

    <!-- 1. 项目坐标 -->
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>my-app</artifactId>
    <version>1.0-SNAPSHOT</version>

    <!-- 2. 项目属性 -->
    <properties>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <maven.compiler.source>1.8</maven.compiler.source>
        <maven.compiler.target>1.8</maven.compiler.target>
    </properties>

    <!-- 3. 依赖管理 -->
    <dependencies>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope> <!-- scope定义了依赖的作用范围 -->
        </dependency>
        <dependency>
            <groupId>com.google.guava</groupId>
            <artifactId>guava</artifactId>
            <version>31.1-jre</version>
        </dependency>
    </dependencies>

    <!-- 4. 构建配置 -->
    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-shade-plugin</artifactId>
                <version>3.2.4</version>
                <executions>
                    <execution>
                        <phase>package</phase>
                        <goals>
                            <goal>shade</goal>
                        </goals>
                        <configuration>
                            <transformers>
                                <transformer implementation="org.apache.maven.plugins.shade.resource.ManifestResourceTransformer">
                                    <mainClass>com.example.my-app.App</mainClass>
                                </transformer>
                            </transformers>
                        </configuration>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>
</project>
```

---

## 2. Gradle

Gradle 是一个更现代、更灵活的构建工具。它借鉴了 Maven 的优点（如生命周期、依赖管理），但使用基于 **Groovy** 或 **Kotlin** 的 **DSL (Domain-Specific Language)** 来编写构建脚本，而不是 XML。

### 2.1. 核心优势

-   **灵活性与可编程性**: 构建脚本是代码，不是配置文件。你可以使用 Groovy/Kotlin 的全部功能来编写复杂的构建逻辑。
-   **性能**: Gradle 通过 **增量构建 (Incremental Build)** 和 **构建缓存 (Build Cache)** 等技术，显著提升了构建性能。对于已经执行过的任务，如果其输入输出没有变化，Gradle 会跳过该任务。
-   **DSL**: 基于 Groovy/Kotlin 的 DSL 语法比 XML 更简洁、更具可读性。
-   **依赖管理**: 提供了更精细的依赖配置（如 `implementation` vs `api`），可以更好地控制依赖的传递范围。

### 2.2. `build.gradle` (Groovy DSL) 示例

```groovy
// 1. 插件
plugins {
    id 'java' // 应用 Java 插件
    id 'application'
}

// 2. 项目坐标
group 'com.example'
version '1.0-SNAPSHOT'

// 3. 仓库
repositories {
    mavenCentral() // 使用 Maven 中央仓库
}

// 4. 依赖
dependencies {
    // 'implementation' 是一种依赖配置，表示这是内部实现细节
    implementation 'com.google.guava:guava:31.1-jre'

    // 'testImplementation' 表示这只在测试时需要
    testImplementation 'org.junit.jupiter:junit-jupiter-api:5.8.1'
    testRuntimeOnly 'org.junit.jupiter:junit-jupiter-engine:5.8.1'
}

// 5. 应用配置
application {
    mainClass = 'com.example.my-app.App'
}

// 6. 测试配置
test {
    useJUnitPlatform()
}
```

---

## 3. Maven vs. Gradle

| 特性 | Maven | Gradle |
| :--- | :--- | :--- |
| **配置文件** | `pom.xml` (XML) | `build.gradle` (Groovy/Kotlin DSL) |
| **灵活性** | 较低，基于固定的生命周期和插件 | 非常高，构建即代码 |
| **性能** | 较慢，缺少高级缓存和增量构建机制 | 非常快，支持增量构建、构建缓存和守护进程 |
| **简洁性** | 冗长，XML 模板化严重 | 简洁，DSL 更易读写 |
| **社区与生态**| 非常成熟，插件丰富，社区庞大 | 快速发展，被 Android 官方采用，社区活跃 |
| **学习曲线** | 较低，易于上手 | 较高，需要理解 Groovy/Kotlin 和其 DSL |

**如何选择？**
-   对于传统的、结构相对固定的 Java EE 或 Spring Boot 项目，**Maven** 是一个非常可靠、稳妥的选择。
-   对于需要复杂构建逻辑、追求极致构建性能的项目，或者多模块、多语言混合的项目（如 Android），**Gradle** 提供了无与伦比的灵活性和性能。

在现代 Java 开发中，Gradle 的受欢迎程度正在稳步上升，尤其是在新项目和拥抱 DevOps 文化的团队中。
