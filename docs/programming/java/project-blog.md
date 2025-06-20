# 实战项目案例一：开发一个功能完备的博客系统

本项目旨在引导你从零开始，利用前面所学的 Java 和 Spring Boot 技术栈，构建一个功能完备、现代化的博客系统。通过这个项目，你将把理论知识融会贯通，应用到真实的开发场景中。

---

## 1. 项目概述与技术选型

### 1.1. 核心功能

-   **用户模块**: 用户注册、登录 (JWT 认证)、个人信息修改。
-   **文章模块**:
    -   文章的发布、编辑、删除 (CRUD)。
    -   支持 Markdown 编辑器。
    -   文章列表展示（分页）、按分类/标签筛选。
    -   文章详情页展示。
-   **评论模块**: 用户可以对文章进行评论、回复。
-   **分类与标签**: 管理员可以创建和管理文章分类；用户发布文章时可以打上标签。
-   **简单的后台管理**: 管理员可以管理所有用户、文章和评论。

### 1.2. 技术选型

-   **后端**:
    -   **核心框架**: Spring Boot
    -   **安全认证**: Spring Security + JWT
    -   **数据持久化**: Spring Data JPA + Hibernate
    -   **数据库**: MySQL (或 H2 用于快速测试)
    -   **数据校验**: Spring Validation
    -   **构建工具**: Maven
-   **前端 (可选，可使用 Postman 进行 API 测试)**:
    -   **框架**: Vue.js / React
    -   **UI 组件库**: Element UI / Ant Design
    -   **HTTP 客户端**: Axios
-   **部署**: Docker + Docker Compose

---

## 2. 数据库设计 (E-R 图)

设计清晰的数据库模型是项目成功的关键。

-   **User (用户表)**
    -   `id` (PK), `username`, `password` (加密存储), `email`, `role` (e.g., 'ROLE_USER', 'ROLE_ADMIN'), `created_at`
-   **Post (文章表)**
    -   `id` (PK), `title`, `content` (Markdown 格式), `summary`, `status` ('PUBLISHED', 'DRAFT'), `created_at`, `updated_at`
    -   `user_id` (FK to User)
    -   `category_id` (FK to Category)
-   **Comment (评论表)**
    -   `id` (PK), `content`, `created_at`
    -   `post_id` (FK to Post)
    -   `user_id` (FK to User)
    -   `parent_id` (FK to Comment, for replies)
-   **Category (分类表)**
    -   `id` (PK), `name`, `description`
-   **Tag (标签表)**
    -   `id` (PK), `name`
-   **post_tags (文章-标签关联表)** - 多对多关系
    -   `post_id` (FK to Post)
    -   `tag_id` (FK to Tag)

---

## 3. API 设计 (RESTful)

设计一套清晰、一致的 RESTful API。

-   **认证 API**
    -   `POST /api/auth/register`: 用户注册
    -   `POST /api/auth/login`: 用户登录，返回 JWT
-   **文章 API**
    -   `POST /api/posts`: 创建新文章
    -   `GET /api/posts`: 获取文章列表（支持分页、分类、标签过滤）
    -   `GET /api/posts/{id}`: 获取单篇文章详情
    -   `PUT /api/posts/{id}`: 更新文章
    -   `DELETE /api/posts/{id}`: 删除文章
-   **评论 API**
    -   `POST /api/posts/{postId}/comments`: 为文章添加评论
    -   `GET /api/posts/{postId}/comments`: 获取文章的评论列表
-   **分类 API (管理员)**
    -   `POST /api/categories`, `GET /api/categories`, `PUT /api/categories/{id}`, `DELETE /api/categories/{id}`
-   **标签 API**
    -   `GET /api/tags`: 获取所有标签

---

## 4. 开发步骤建议

1.  **项目初始化**: 使用 Spring Initializr 创建项目骨架，勾选所需依赖 (Web, JPA, Security, MySQL, Validation)。
2.  **配置与模型**:
    -   配置 `application.yml` (数据库连接、JPA 设置)。
    -   根据数据库设计，创建所有实体类 (`@Entity`)。
3.  **数据访问层**: 为每个实体创建对应的 Spring Data JPA Repository 接口。
4.  **安全框架搭建**:
    -   配置 Spring Security (`SecurityConfig`)，实现 `UserDetailsService`。
    -   实现密码加密 `PasswordEncoder`。
    -   创建认证 API (`/api/auth/**`)，用于注册和登录（签发 JWT）。
    -   创建 JWT 工具类和过滤器，并集成到 `SecurityConfig` 中。
5.  **业务逻辑层 (Service)**:
    -   为每个模块（用户、文章、评论）创建 Service 类。
    -   在 Service 中注入 Repository，实现核心业务逻辑。
    -   使用 DTO (Data Transfer Object) 在 Controller 和 Service 之间传递数据，避免直接暴露实体。
6.  **API 接口层 (Controller)**:
    -   创建 Controller 类，设计 RESTful API 端点。
    -   注入 Service，处理 HTTP 请求。
    -   使用 `@Valid` 和 DTO 进行数据校验。
    -   实现全局异常处理 (`@ControllerAdvice`)，返回统一的错误响应格式。
7.  **测试**:
    -   为 Service 层编写单元测试 (JUnit + Mockito)。
    -   为 Controller 层编写集成测试 (`@WebMvcTest` + `MockMvc`)。
8.  **容器化与部署**:
    -   编写 `Dockerfile` 将应用打包成镜像。
    -   (可选) 编写 `docker-compose.yml`，一键启动应用和 MySQL 数据库。
9.  **(可选) 前端开发**:
    -   使用前端框架（如 Vue.js）调用后端 API，构建用户界面。

这个项目将全面检验你对 Spring Boot 生态系统的掌握程度，并让你获得宝贵的项目实战经验。
