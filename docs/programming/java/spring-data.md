# 数据持久化：Spring Data JPA, Hibernate, MyBatis

数据持久化是将内存中的数据模型（如对象）转换为可永久存储的形式（如数据库记录）的过程。在 Java 企业级应用中，与数据库交互是核心功能之一。本章将介绍 Spring Boot 中最常用的三种数据持久化技术：Spring Data JPA (及其底层实现 Hibernate) 和 MyBatis。

---

## 1. ORM 与 Spring Data JPA

**ORM (Object-Relational Mapping, 对象关系映射)** 是一种编程技术，它在关系型数据库和面向对象的编程语言之间建立起一座桥梁。开发者可以操作对象，而 ORM 框架会自动将其转换为相应的 SQL 语句来操作数据库。

-   **JPA (Java Persistence API)**: JPA 是 Java EE 的一个 **规范**，它定义了一系列用于 ORM 的 API 和注解。它只是一套标准，不是具体实现。
-   **Hibernate**: Hibernate 是 JPA 规范 **最著名、最强大的实现**。它是一个功能齐全的 ORM 框架。
-   **Spring Data JPA**: Spring Data JPA 是 Spring Data 项目的一部分，它在 JPA 规范之上又做了一层 **抽象和封装**。它极大地简化了数据访问层的开发，让你无需编写 DAO/Repository 的实现代码。

当你使用 `spring-boot-starter-data-jpa` 时，你实际上同时引入了 Spring Data JPA、JPA 规范 API 和 Hibernate。

### 1.1. 核心组件

1.  **实体 (Entity)**:
    -   一个映射到数据库表的普通 Java 对象 (POJO)。
    -   必须使用 `@Entity` 注解。
    -   必须有一个主键，使用 `@Id` 注解。

    ```java
    package com.example.demo.model;

    import javax.persistence.Entity;
    import javax.persistence.GeneratedValue;
    import javax.persistence.GenerationType;
    import javax.persistence.Id;

    @Entity
    public class User {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;
        private String name;
        private String email;
        // ... getters and setters
    }
    ```

2.  **仓库 (Repository)**:
    -   一个接口，用于定义数据访问的方法。
    -   通过继承 `JpaRepository`，你可以 **自动获得** 一整套 CRUD (Create, Read, Update, Delete) 以及分页和排序的方法，**无需任何实现**。

    ```java
    package com.example.demo.repository;

    import com.example.demo.model.User;
    import org.springframework.data.jpa.repository.JpaRepository;
    import java.util.List;

    public interface UserRepository extends JpaRepository<User, Long> {
        // Spring Data JPA 的魔力：根据方法名自动生成查询
        User findByName(String name);
        List<User> findByEmailContaining(String keyword);
    }
    ```

### 1.2. 配置与使用

-   **配置 `application.yml`**:
    ```yaml
    spring:
      datasource:
        url: jdbc:mysql://localhost:3306/mydatabase
        username: root
        password: password
      jpa:
        hibernate:
          ddl-auto: update # (create, update, validate, none) 自动更新表结构
        show-sql: true # 在控制台显示执行的 SQL
    ```
-   **在 Service 中使用 Repository**:
    ```java
    @Service
    public class UserService {
        @Autowired
        private UserRepository userRepository;

        public User createUser(User user) {
            return userRepository.save(user); // save 方法兼具新增和更新功能
        }

        public List<User> getAllUsers() {
            return userRepository.findAll();
        }
    }
    ```

---

## 2. MyBatis：SQL 映射框架

MyBatis 是另一个流行的持久化框架。与 ORM 不同，MyBatis 是一种 **SQL 映射 (SQL Mapper)** 框架。

**核心思想**: 将繁琐的 JDBC 代码（如创建连接、`PreparedStatement`、处理 `ResultSet`）封装起来，但将 **SQL 语句的完全控制权交还给开发者**。开发者在 XML 文件或注解中编写 SQL，MyBatis 负责将 SQL 的输入参数和输出结果映射到 Java 对象。

### 2.1. 核心组件

1.  **Mapper 接口**: 类似于 JPA 的 Repository，定义数据访问方法。
    ```java
    @Mapper // 标记为 MyBatis 的 Mapper 接口
    public interface UserMapper {
        User findById(Long id);
        List<User> findAll();
        void insert(User user);
    }
    ```
2.  **Mapper XML 文件**: 编写与接口方法对应的 SQL 语句。
    ```xml
    <!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
            "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
    <mapper namespace="com.example.demo.mapper.UserMapper">
        <select id="findById" resultType="com.example.demo.model.User">
            SELECT * FROM user WHERE id = #{id}
        </select>

        <select id="findAll" resultType="com.example.demo.model.User">
            SELECT * FROM user
        </select>

        <insert id="insert" useGeneratedKeys="true" keyProperty="id">
            INSERT INTO user(name, email) VALUES(#{name}, #{email})
        </insert>
    </mapper>
    ```

### 2.2. 配置与使用

-   **添加依赖**: `mybatis-spring-boot-starter`
-   **配置 `application.yml`**:
    ```yaml
    mybatis:
      mapper-locations: classpath:mappers/*.xml # 指定 XML 文件位置
      configuration:
        map-underscore-to-camel-case: true # 开启驼峰命名自动转换
    ```

---

## 3. Spring Data JPA vs. MyBatis

| 特性 | Spring Data JPA (Hibernate) | MyBatis |
| :--- | :--- | :--- |
| **抽象级别** | **高** (ORM)。开发者面向对象编程，屏蔽了 SQL。 | **中** (SQL Mapper)。开发者仍需编写和优化 SQL。 |
| **开发效率** | **非常高**。简单的 CRUD 无需写任何 SQL 和实现代码。 | **较高**。免去了 JDBC 的繁琐模板代码。 |
| **SQL 控制力** | **弱**。SQL 由框架自动生成，难以进行深度优化。 | **强**。完全控制 SQL，可以轻松实现复杂的查询和优化。 |
| **可移植性** | **强**。由于屏蔽了 SQL 方言，理论上可以轻松切换数据库。| **弱**。SQL 是针对特定数据库编写的。 |
| **学习曲线** | 概念较多（实体状态、缓存、事务等），上手有一定门槛。 | 简单直观，有 SQL 基础即可快速上手。 |
| **适用场景** | 业务逻辑相对简单、CRUD 操作频繁的系统（如后台管理系统）。 | 业务逻辑复杂、对 SQL 性能要求极高、需要大量复杂报表的系统（如互联网应用）。 |

**总结**:
-   选择 **Spring Data JPA**，如果你想快速开发，不关心具体的 SQL 实现，并且希望代码有良好的数据库可移植性。
-   选择 **MyBatis**，如果你是 SQL 专家，希望对数据库有完全的控制权，并且需要应对复杂的、高性能的查询场景。

在实际项目中，两者也可以结合使用，发挥各自的优势。
