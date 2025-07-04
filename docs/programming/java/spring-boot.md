# Spring Boot 全家桶

Spring Boot 是由 Pivotal 团队提供的全新框架，其设计目的是用来简化新 Spring 应用的初始搭建以及开发过程。它基于 Spring 框架，但通过 **"约定优于配置" (Convention over Configuration)** 的理念，极大地减少了配置工作，让开发者可以快速启动和运行一个独立的、生产级的 Spring 应用。

## 1. 核心特性

-   **自动配置 (Auto-Configuration)**: Spring Boot 的杀手级特性。它会根据你添加的依赖（JARs）来自动配置你的 Spring 应用。例如，如果 `spring-boot-starter-web` 在类路径上，它会自动配置 Tomcat 和 Spring MVC。
-   **起步依赖 (Starter Dependencies)**: Spring Boot 提供了一系列"起步依赖" (`starter`)，它们是预先配置好的依赖描述符集合。例如，`spring-boot-starter-data-jpa` 不仅包含了 Spring Data JPA，还包含了 Hibernate 和其他相关的依赖。这让你无需手动寻找和配置单个依赖。
-   **内嵌服务器 (Embedded Servers)**: 无需将应用打包成 WAR 文件部署到外部服务器。Spring Boot 应用内置了 Tomcat, Jetty 或 Undertow，可以直接通过 `main` 方法启动，打包成一个可执行的 JAR 文件。
-   **生产就绪特性 (Production-ready Features)**: 提供了诸如度量 (metrics)、健康检查 (health checks) 和外部化配置等生产环境中需要的功能。

---

## 2. Spring Boot 基础

### 2.1. 创建一个 Spring Boot 应用

最快的方式是使用 **Spring Initializr** ([start.spring.io](https://start.spring.io/))。这是一个 Web 工具，可以让你选择项目元数据、构建工具（Maven/Gradle）和所需的起步依赖，然后生成一个完整的项目骨架。

### 2.2. 主启动类

一个典型的 Spring Boot 应用主类如下：
```java
package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication // 这是一个组合注解
public class DemoApplication {

    public static void main(String[] args) {
        // 启动 Spring Boot 应用
        SpringApplication.run(DemoApplication.class, args);
    }

}
```
`@SpringBootApplication` 是一个组合注解，它包含了：
-   `@Configuration`: 标记该类为应用的配置类。
-   `@EnableAutoConfiguration`: 启用 Spring Boot 的自动配置机制。
-   `@ComponentScan`: 在当前包及其子包下扫描组件（如 `@Component`, `@Service`, `@Repository`, `@Controller`）。

### 2.3. Web 开发：构建一个 RESTful API

1.  **添加依赖**: 在 `pom.xml` 或 `build.gradle` 中添加 `spring-boot-starter-web`。
2.  **创建控制器 (Controller)**:
    ```java
    package com.example.demo.controller;

    import org.springframework.web.bind.annotation.GetMapping;
    import org.springframework.web.bind.annotation.RequestParam;
    import org.springframework.web.bind.annotation.RestController;

    @RestController // 组合了 @Controller 和 @ResponseBody
    public class HelloController {

        @GetMapping("/hello") // 映射 HTTP GET 请求到 /hello 路径
        public String sayHello(@RequestParam(value = "name", defaultValue = "World") String name) {
            return String.format("Hello, %s!", name);
        }
    }
    ```
    -   `@RestController`: 表明这个类中的所有方法返回的都是领域对象或 JSON/XML 等数据，而不是视图名。
    -   `@GetMapping`: 是 `@RequestMapping(method = RequestMethod.GET)` 的简写。

现在，运行主启动类，访问 `http://localhost:8080/hello?name=SpringBoot` 就可以看到结果。

---

## 3. 核心概念深入

### 3.1. 外部化配置

Spring Boot 允许你将配置从代码中分离出来，以便在不同环境中可以轻松切换。配置可以来源于多种地方，并遵循一个优先级顺序。

**常用配置源 (优先级从高到低)**:
1.  命令行参数
2.  `application.properties` 或 `application.yml` 文件中 `spring.config.activate.on-profile` 指定的文档
3.  `application-{profile}.properties` 或 `application-{profile}.yml` (如 `application-dev.yml`)
4.  `application.properties` 或 `application.yml`

**`application.yml` 示例**:
```yaml
server:
  port: 8081 # 设置服务器端口

spring:
  application:
    name: my-app # 设置应用名称
  profiles:
    active: dev # 激活开发环境配置

--- # 使用三个短横线分隔不同 profile 的配置
spring:
  config:
    activate:
      on-profile: dev # 开发环境配置
  datasource:
    url: jdbc:mysql://localhost:3306/devdb
    username: devuser
    password: devpassword

---
spring:
  config:
    activate:
      on-profile: prod # 生产环境配置
  datasource:
    url: jdbc:mysql://prod-server:3306/proddb
    username: produser
    password: ${DB_PASSWORD} #可以引用环境变量
```
使用 `@Value` 注解可以将配置值注入到 bean 中：
```java
@Value("${server.port}")
private int port;
```

### 3.2. Spring Boot Starters

Starters 是 Spring Boot 的核心，它们是一系列方便的依赖描述符。一些常用的 Starters：
-   `spring-boot-starter-web`: 用于构建 Web 应用，包括 RESTful API，使用 Spring MVC。
-   `spring-boot-starter-data-jpa`: 用于使用 Spring Data JPA 和 Hibernate 进行数据库持久化。
-   `spring-boot-starter-security`: 用于使用 Spring Security 进行身份验证和授权。
-   `spring-boot-starter-test`: 用于测试 Spring Boot 应用，包含 JUnit, Mockito, Spring Test 等。
-   `spring-boot-starter-actuator`: 提供生产就绪特性，如监控和度量。

### 3.3. Actuator: 应用监控与管理

添加 `spring-boot-starter-actuator` 依赖后，Spring Boot 会自动暴露一系列用于监控和管理应用的端点 (endpoints)。

**常用端点**:
-   `/actuator/health`: 显示应用的健康状况。
-   `/actuator/info`: 显示任意的应用信息。
-   `/actuator/metrics`: 显示应用的度量信息（如内存、CPU使用率、HTTP请求统计）。
-   `/actuator/env`: 显示当前环境的所有配置属性。
-   `/actuator/beans`: 显示应用中所有 Spring bean 的完整列表。

这些端点对于应用的运维和故障排查至关重要。

Spring Boot 极大地提升了 Java 开发者的生产力，已成为构建微服务和现代 Web 应用的事实标准。
