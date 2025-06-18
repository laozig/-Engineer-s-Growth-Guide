# PHP 处理Web表单

Web表单是网站与用户交互的核心部分。PHP提供了简单而强大的方法来接收和处理用户通过HTML表单提交的数据。

## 创建一个HTML表单

一个基本的HTML表单包含一些输入字段和一个提交按钮。`<form>`标签的两个重要属性是：
-   **`action`**: 指定当表单被提交时，数据应被发送到哪个URL进行处理。
-   **`method`**: 指定用于发送数据的HTTP方法，通常是 `GET` 或 `POST`。

**`simple_form.html`:**
```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <title>简单表单</title>
</head>
<body>

<form action="welcome.php" method="post">
    <label for="name">名字:</label><br>
    <input type="text" id="name" name="name"><br>
    
    <label for="email">邮箱:</label><br>
    <input type="text" id="email" name="email"><br><br>
    
    <input type="submit" value="提交">
</form> 

</body>
</html>
```

## `GET` vs `POST`

-   **`GET`**: 
    -   表单数据会附加在URL的查询字符串中。
    -   对发送的数据量有限制（约2000字符）。
    -   数据在URL中可见，不应用于发送敏感信息（如密码）。
    -   提交的页面可以被收藏为书签。
    -   适用于搜索、过滤等非修改性操作。

-   **`POST`**:
    -   表单数据包含在HTTP请求的主体中。
    -   对发送的数据量没有限制。
    -   数据不在URL中显示，更安全。
    -   提交的页面不能被收藏为书签。
    -   适用于注册、登录、修改数据等操作。

## 接收表单数据

PHP使用超全局变量 `$_GET` 和 `$_POST` 来分别收集 `method="get"` 和 `method="post"` 的表单数据。

**`welcome.php` (处理上述表单):**
```php
<?php
// 检查请求方法是否为POST
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // 从 $_POST 数组中收集值
    $name = $_POST['name'];
    $email = $_POST['email'];
    
    if (empty($name) || empty($email)) {
        echo "名字和邮箱字段都不能为空。";
    } else {
        echo "欢迎, " . $name . "!<br>";
        echo "你的邮箱是: " . $email;
    }
} else {
    echo "无效的请求方法。";
}
?>
```

## 数据验证与清理

**永远不要相信用户的输入！** 在处理任何用户提交的数据之前，必须进行严格的验证和清理，以防止安全漏洞。

### 1. 验证 (Validation)

验证是确保用户输入符合预期规则的过程（例如，邮箱格式是否正确，年龄是否为数字等）。

-   **检查空值**: `empty()`
-   **检查格式**: 使用正则表达式 `preg_match()` 或内置的过滤器 `filter_var()`。

### 2. 清理 (Sanitization)

清理是移除用户输入中任何非法或不安全字符的过程。这对于防止 **跨站脚本攻击 (Cross-Site Scripting, XSS)** 至关重要。

-   **`htmlspecialchars()`**: 将特殊字符转换为HTML实体。这是防止XSS的最基本、最重要的函数。
    -   `&` 变成 `&amp;`
    -   `"` 变成 `&quot;`
    -   `'` 变成 `&#039;`
    -   `<` 变成 `&lt;`
    -   `>` 变成 `&gt;`

## 完整的表单处理示例

这个示例将验证、清理和"粘性表单"（在提交后保留用户输入）结合在一起。所有逻辑都在一个PHP文件中。

**`contact_form.php`:**
```php
<?php
// 定义变量并设置为空值
$nameErr = $emailErr = $genderErr = $websiteErr = "";
$name = $email = $gender = $comment = $website = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // 验证名字
    if (empty($_POST["name"])) {
        $nameErr = "名字是必填的";
    } else {
        $name = sanitize_input($_POST["name"]);
        // 检查名字是否只包含字母和空格
        if (!preg_match("/^[a-zA-Z-' ]*$/", $name)) {
            $nameErr = "只允许字母和空格";
        }
    }

    // 验证邮箱
    if (empty($_POST["email"])) {
        $emailErr = "邮箱是必填的";
    } else {
        $email = sanitize_input($_POST["email"]);
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $emailErr = "无效的邮箱格式";
        }
    }

    // 验证URL (可选)
    if (!empty($_POST["website"])) {
        $website = sanitize_input($_POST["website"]);
        if (!filter_var($website, FILTER_VALIDATE_URL)) {
            $websiteErr = "无效的URL";
        }
    }

    // 处理评论和性别 (简单清理)
    $comment = sanitize_input($_POST["comment"]);
    $gender = sanitize_input($_POST["gender"]);
}

// 数据清理函数
function sanitize_input($data) {
    $data = trim($data); // 移除两侧多余的空格、tab、换行
    $data = stripslashes($data); // 移除反斜杠
    $data = htmlspecialchars($data); // 转换特殊字符
    return $data;
}
?>

<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <title>完整表单示例</title>
    <style>.error { color: #FF0000; }</style>
</head>
<body>

<h2>PHP 表单验证示例</h2>
<p><span class="error">* 必填字段</span></p>
<form method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]);?>">
    名字: <input type="text" name="name" value="<?php echo $name;?>">
    <span class="error">* <?php echo $nameErr;?></span>
    <br><br>

    邮箱: <input type="text" name="email" value="<?php echo $email;?>">
    <span class="error">* <?php echo $emailErr;?></span>
    <br><br>

    网址: <input type="text" name="website" value="<?php echo $website;?>">
    <span class="error"><?php echo $websiteErr;?></span>
    <br><br>

    评论: <textarea name="comment" rows="5" cols="40"><?php echo $comment;?></textarea>
    <br><br>

    性别:
    <input type="radio" name="gender" <?php if (isset($gender) && $gender=="female") echo "checked";?> value="female">女性
    <input type="radio" name="gender" <?php if (isset($gender) && $gender=="male") echo "checked";?> value="male">男性
    <input type="radio" name="gender" <?php if (isset($gender) && $gender=="other") echo "checked";?> value="other">其他
    <span class="error">* <?php echo $genderErr;?></span>
    <br><br>

    <input type="submit" name="submit" value="提交">
</form>

<?php
echo "<h2>你的输入:</h2>";
echo $name;
echo "<br>";
echo $email;
echo "<br>";
echo $website;
echo "<br>";
echo $comment;
echo "<br>";
echo $gender;
?>

</body>
</html>
```
### 代码解释:
1.  **`$_SERVER["PHP_SELF"]`**: 是一个超全局变量，它返回当前执行脚本的文件名。将其用作表单的`action`属性，可以确保表单数据被提交回当前页面进行处理。
2.  **`htmlspecialchars()`**: 我们对 `$_SERVER["PHP_SELF"]` 使用此函数。这是一个安全措施，可以防止XSS攻击。如果用户试图在URL中注入恶意脚本，`htmlspecialchars()`会将其转换为无害的HTML实体。
3.  **粘性表单**: 在每个输入字段的`value`属性中，我们输出了对应的PHP变量（如`value="<?php echo $name;?>"`）。这样，即使用户提交的表单有误，他们之前输入的数据也会被保留在表单中，提升了用户体验。
4.  **显示错误**: 在每个必填字段旁边，我们都输出了对应的错误信息变量（如`<?php echo $nameErr;?>`）。 