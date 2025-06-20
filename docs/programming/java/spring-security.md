# 安全框架: Spring Security

Spring Security 是一个功能强大且高度可定制的身份验证和访问控制框架。它是保护基于 Spring 的应用程序的 **事实标准**。Spring Security 能够处理 **认证 (Authentication)** 和 **授权 (Authorization)**。

-   **认证 (Authentication)**: 你是谁？验证用户的身份，通常是通过用户名和密码。
-   **授权 (Authorization)**: 你能做什么？在用户成功认证后，决定他们是否有权限访问某些资源。

---

## 1. Spring Security 核心概念

Spring Security 的核心是一系列 **Servlet 过滤器链 (Servlet Filter Chain)**。当一个请求到达时，它会经过这条链，链上的每个过滤器都会对请求进行处理（例如，检查 CSRF token，验证 Session，检查授权等）。

### 1.1. 关键组件

-   **`SecurityFilterChain`**: 这是 Spring Security 的核心配置，定义了哪些请求需要被保护，以及如何保护它们。在现代的 Spring Security (5.4+) 中，这通常通过一个 `@Bean` 方法来配置。
-   **`UserDetailsService`**: 一个用于从持久化存储（如数据库）中加载特定用户信息的接口。你需要提供它的实现，告诉 Spring Security 如何根据用户名查找用户及其密码和角色。
-   **`PasswordEncoder`**: 一个用于密码编码的接口。**绝不允许以明文形式存储密码**。Spring Security 推荐使用 `BCryptPasswordEncoder`。
-   **`AuthenticationManager`**: 处理认证请求的主要接口。

### 1.2. 基础配置：基于表单的登录

1.  **添加依赖**: `spring-boot-starter-security`
2.  **创建 `SecurityConfig` 类**:
    ```java
    @Configuration
    @EnableWebSecurity
    public class SecurityConfig {

        @Bean
        public UserDetailsService userDetailsService(DataSource dataSource) {
            // 这里为了简化，使用JDBC从数据库加载用户
            // 你也可以自定义实现，从任何地方加载用户
            JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);
            // ... 你需要定义 usersByUsernameQuery 和 authoritiesByUsernameQuery
            return users;
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
            // 使用 BCrypt 算法对密码进行加密
            return new BCryptPasswordEncoder();
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            http
                .authorizeHttpRequests(authorize -> authorize
                    .antMatchers("/css/**", "/js/**", "/login").permitAll() // 允许所有人访问静态资源和登录页面
                    .antMatchers("/api/admin/**").hasRole("ADMIN") // /api/admin/** 路径需要 ADMIN 角色
                    .anyRequest().authenticated() // 其他所有请求都需要认证
                )
                .formLogin(formLogin -> formLogin
                    .loginPage("/login") // 自定义登录页面
                    .defaultSuccessUrl("/home", true) // 登录成功后跳转的页面
                    .permitAll()
                )
                .logout(logout -> logout
                    .logoutUrl("/logout")
                    .logoutSuccessUrl("/login?logout")
                    .permitAll()
                );
            return http.build();
        }
    }
    ```

---

## 2. 无状态认证与 JWT

在现代的 RESTful API 和微服务架构中，通常采用 **无状态认证 (Stateless Authentication)**，而不是传统的基于 Session 的认证。这意味着服务器不存储任何关于用户登录状态的信息。每个请求都必须包含能证明其身份的凭证。

**JSON Web Token (JWT)** 是实现无状态认证最流行的方式。

### 2.1. JWT 是什么？

JWT 是一个紧凑且自包含的字符串，格式为 `header.payload.signature`。

-   **Header**: 包含了 token 的类型 (JWT) 和使用的签名算法 (如 HMAC SHA256 或 RSA)。
-   **Payload**: 包含了 **声明 (Claims)**。声明是关于实体（通常是用户）和附加元数据的陈述。常见的声明有 `sub` (主题, a.k.a 用户ID), `iss` (签发者), `exp` (过期时间), 以及自定义的角色、权限等信息。
-   **Signature**: 用于验证消息在传递过程中没有被篡改。它是通过对编码后的 header 和 payload，加上一个秘钥，使用指定的算法进行签名生成的。

### 2.2. JWT 工作流程

1.  **用户登录**: 用户使用用户名和密码向认证服务器（如 `/api/authenticate` 端点）发起请求。
2.  **服务器认证**: 服务器验证用户的凭证。
3.  **签发 Token**: 如果凭证有效，服务器会创建一个 JWT（包含用户ID、角色等信息），用自己的秘钥对其签名，然后将其返回给客户端。
4.  **客户端存储 Token**: 客户端（如浏览器）通常将 JWT 存储在 `localStorage` 或 `Authorization` 请求头的 `Bearer` 模式中。
5.  **后续请求**: 对于需要认证的后续请求，客户端会在 `Authorization` 头中携带 JWT。
    ```
    Authorization: Bearer <token>
    ```
6.  **服务器验证 Token**: 服务器收到请求后，会解析 `Authorization` 头，获取 JWT。它会验证 token 的签名（确保未被篡改）和有效期。如果验证通过，服务器就信任 token 中的信息（如用户ID和角色），并处理该请求。

### 2.3. 在 Spring Security 中集成 JWT

集成 JWT 比基础表单登录要复杂一些，主要步骤如下：

1.  **添加 JWT 库依赖**: 如 `io.jsonwebtoken:jjwt-api`, `jjwt-impl`, `jjwt-jackson`。
2.  **创建 `JwtUtil` 类**: 一个工具类，负责生成、解析和验证 JWT。它将包含签名用的秘钥。
3.  **创建认证端点**: 创建一个控制器（如 `/api/authenticate`），接收用户名和密码，验证后调用 `JwtUtil` 生成 token 并返回。
4.  **创建 JWT 过滤器**: 创建一个自定义的 Servlet 过滤器 (`JwtRequestFilter`)，它继承自 `OncePerRequestFilter`。
    -   这个过滤器的作用是在每个请求到达时，检查 `Authorization` 头。
    -   如果存在 `Bearer` token，就使用 `JwtUtil` 解析并验证它。
    -   如果 token 有效，就从中提取用户信息（如用户名和权限），创建一个 `UsernamePasswordAuthenticationToken`，并将其设置到 `SecurityContextHolder` 的上下文中。这相当于**手动**告诉 Spring Security 当前请求的用户是谁。
5.  **配置 `SecurityFilterChain`**:
    -   禁用 CSRF（因为是无状态的）。
    -   配置 session 管理策略为 `STATELESS`。
    -   允许对认证端点 (`/api/authenticate`) 的匿名访问。
    -   将自定义的 `JwtRequestFilter` 添加到过滤器链中的 `UsernamePasswordAuthenticationFilter` 之前。

---

## 3. OAuth 2.0

OAuth 2.0 是一个 **授权框架**，它允许第三方应用在获得用户授权的情况下，访问用户在某个服务上的特定资源，而无需获取用户的用户名和密码。

例如，当你使用"通过 Google/GitHub 登录"功能时，你正在使用的就是 OAuth 2.0。你授权该网站访问你在 Google/GitHub 的基本信息（如用户名和邮箱），但该网站永远不会知道你的 Google/GitHub 密码。

Spring Security 提供了对 OAuth 2.0 的全面支持，包括实现 **认证服务器 (Authorization Server)** 和 **资源服务器 (Resource Server)**，以及与第三方 OAuth 2.0 提供商（如 Google, Facebook, GitHub）集成的客户端支持。这部分内容较为复杂，通常作为高级主题进行深入学习。
