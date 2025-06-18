# PHP 安全最佳实践

构建安全的Web应用程序至关重要。PHP应用程序是网络上常见的攻击目标，因此了解并实施安全最佳实践是每个PHP开发者的责任。本指南概述了最关键的安全主题。

## 1. 防止SQL注入

**威胁**: 攻击者通过Web表单或URL参数注入恶意的SQL代码，可能导致数据泄露、篡改或删除。

**解决方案**: **始终使用预处理语句 (Prepared Statements)**。不要将用户输入直接拼接到SQL查询中。

**错误的做法 (易受攻击):**
```php
// 极度不安全！
$id = $_GET['id'];
$pdo->query("SELECT * FROM users WHERE id = $id"); 
```

**正确的做法 (使用PDO预处理):**
```php
<?php
// ... $pdo 连接 ...
$id = $_GET['id'];

$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $id]);
$user = $stmt->fetch();
?>
```
通过使用预处理语句，用户输入的数据 (`$id`) 永远被当作数据处理，而不是可执行的SQL代码，从而完全消除了SQL注入的风险。

## 2. 防止跨站脚本 (XSS)

**威胁**: 攻击者向你的网站注入恶意的客户端脚本（通常是JavaScript）。当其他用户浏览该页面时，脚本会在他们的浏览器中执行，可能用于窃取Session、篡改页面内容等。

**解决方案**: 在将任何用户输入的数据输出到HTML页面之前，**始终对其进行转义**。

**正确的做法 (使用 `htmlspecialchars`):**
```php
<?php
// 假设 $comment 是从数据库中获取的用户评论
$comment = '<script>alert("XSS Attack!");</script>';

// 在输出到HTML时进行转义
echo htmlspecialchars($comment, ENT_QUOTES, 'UTF-8');
// 输出: &lt;script&gt;alert(&quot;XSS Attack!&quot;);&lt;/script&gt;
// 浏览器会将其显示为纯文本，而不会执行脚本。
?>
```
`ENT_QUOTES`标志确保单引号和双引号都被转换。指定`UTF-8`可以防止某些字符编码相关的攻击。

## 3. 防止跨站请求伪造 (CSRF)

**威胁**: 攻击者诱导已登录的用户在不知情的情况下，从他们自己的浏览器向你的应用发送一个恶意的请求（例如，修改邮箱、转账等）。

**解决方案**: 使用**同步器令牌 (Synchronizer Token)** 模式。
1.  当向用户显示一个执行敏感操作的表单时（如修改密码表单），生成一个随机的、唯一的令牌，并将其存储在用户的Session中，同时将其作为隐藏字段放入表单。
2.  当用户提交表单时，比较提交的隐藏令牌和Session中存储的令牌。
3.  如果两者匹配，则处理该请求。如果不匹配，则拒绝该请求。

**生成表单时的代码:**
```php
<?php
session_start();
// 如果session中没有令牌，则创建一个
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];
?>

<form action="/update-profile" method="post">
    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
    <!-- 其他表单字段 -->
    <button type="submit">更新个人资料</button>
</form>
```

**处理表单时的代码:**
```php
<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        // 令牌不匹配，拒绝请求
        die('CSRF token validation failed.');
    }
    // 令牌匹配，继续处理请求...
}
?>
```
使用`hash_equals()`进行比较可以防止[时序攻击](https://en.wikipedia.org/wiki/Timing_attack)。

## 4. 密码安全

**威胁**: 如果数据库泄露，以明文或弱加密方式存储的密码将直接暴露给攻击者。

**解决方案**: **始终对密码进行哈希处理**。绝不存储明文密码。使用PHP内置的强大密码哈希API。

**正确的做法:**
-   **`password_hash()`**: 创建一个安全的密码哈希值。它会自动处理加盐 (salting)。
-   **`password_verify()`**: 验证一个给定的密码是否与一个哈希值匹配。

**注册时哈希密码:**
```php
<?php
$plain_password = 'my-super-secret-password';
// PASSWORD_BCRYPT 或 PASSWORD_DEFAULT 是推荐的算法
$hashed_password = password_hash($plain_password, PASSWORD_DEFAULT);

// 将 $hashed_password 存储到数据库中
?>
```

**登录时验证密码:**
```php
<?php
$submitted_password = $_POST['password'];
// $db_hashed_password 是从数据库中取出的哈希值
$db_hashed_password = '...'; 

if (password_verify($submitted_password, $db_hashed_password)) {
    echo '密码正确!';
    // 用户登录成功
} else {
    echo '密码错误。';
}
?>
```

## 5. 文件上传安全

**威胁**: 用户可能上传恶意的PHP脚本、超大文件或伪装成图片的可执行文件，从而导致服务器被控制或资源耗尽。

**解决方案**:
-   **验证文件类型**: 不要相信用户提供的MIME类型 (`$_FILES['userfile']['type']`)。最好使用 `finfo_file` (Fileinfo扩展) 来从文件内容中判断其真实的MIME类型。
-   **验证文件大小**: 检查`$_FILES['userfile']['size']`是否在允许的范围内。
-   **使用随机文件名**: 为上传的文件生成一个新的、随机的文件名，以防止目录遍历等攻击。
-   **存储在Web根目录之外**: 将上传的文件存储在一个非Web可访问的目录中。如果需要提供访问，通过一个PHP脚本来代理，该脚本在提供文件前会进行权限检查。

## 6. 会话安全

**威胁**: 攻击者可能窃取用户的会话ID（会话劫持），从而冒充该用户。

**解决方案**:
-   **`session_regenerate_id(true)`**: 在用户权限级别发生变化的任何时候（例如，登录或登出），都应调用此函数。它会生成一个新的会话ID，并删除旧的会话文件，使旧ID失效。
-   **使用HTTPS**: 始终在整个网站上使用HTTPS (SSL/TLS) 来加密客户端和服务器之间的所有通信，防止会话ID在传输过程中被窃听。
-   **配置安全的Cookie参数**: 在`session_set_cookie_params()`或`php.ini`中设置`session.cookie_httponly = 1`和`session.cookie_secure = 1`。

## 其他重要建议

-   **关闭生产环境的错误显示**: 在`php.ini`中设置`display_errors = Off`，并将错误记录到文件中 (`log_errors = On`)。错误信息可能暴露敏感的服务器信息。
-   **保持软件最新**: 定期更新你的PHP版本、Web服务器、数据库以及所有使用的库（使用`composer update`）。软件更新通常包含重要的安全补丁。
-   **遵循最小权限原则**: 数据库用户应只拥有其完成任务所必需的最小权限。Web服务器进程也应以一个低权限用户运行。
-   **过滤所有输入，转义所有输出**: 这是Web安全的基本原则。 