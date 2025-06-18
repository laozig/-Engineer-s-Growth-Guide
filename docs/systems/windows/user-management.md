# 4. 用户与组管理

在 Windows 中，所有的安全性和资源访问都基于**用户账户 (User Accounts)** 和**组 (Groups)**。正确地管理它们是确保系统安全和资源隔离的核心任务。本章将探讨本地用户和组的管理。

---

### 4.1 用户账户类型

Windows 中主要有两种类型的用户账户：

-   **本地用户账户 (Local User Accounts)**:
    -   账户信息存储在**本地计算机**的安全账户管理器 (Security Account Manager, SAM) 数据库中。
    -   只能用于登录和访问创建它的那台计算机上的资源。
    -   适用于独立的工作站或不属于域的服务器环境。

-   **域用户账户 (Domain User Accounts)**:
    -   账户信息集中存储在**域控制器 (Domain Controller)** 的 Active Directory 数据库中。
    -   可以使用该账户登录到域内的任何一台计算机（需权限允许）。
    -   是企业网络环境中的标准，便于集中管理。本章重点是本地账户，域账户将在后续章节讨论。

#### 内置账户

Windows 系统自带一些内置账户，各自有特殊用途：

-   **Administrator**:
    -   本地计算机上权限最高的账户。
    -   默认情况下，在现代 Windows 版本中处于**禁用**状态，以提高安全性。
    -   最佳实践是保持禁用，并使用另一个普通管理员账户进行管理，只在必要时启用它。

-   **Guest**:
    -   为临时用户提供有限的访问权限。
    -   默认处于**禁用**状态，且强烈建议保持禁用。

-   **DefaultAccount/WDAGUtilityAccount**:
    -   系统管理和虚拟化（如 Windows Defender Application Guard）使用的账户，通常不需要用户干预。

---

### 4.2 使用 GUI 管理本地用户和组

管理本地用户和组最直观的工具是"计算机管理"中的 `lusrmgr.msc` 管理单元。

**访问方式**:
1.  按 `Win + R`，输入 `lusrmgr.msc` 并回车。
2.  或通过 `计算机管理 -> 本地用户和组`。

> **注意**: `lusrmgr.msc` 在 **Windows 家庭版**中不可用，这是专业版及以上版本的功能。

#### 创建一个新用户

1.  在 `本地用户和组` 中，右键点击 `用户` 文件夹，选择 `新用户`。
2.  **用户名**: 用户的登录名（例如 `jdoe`）。
3.  **全名/描述**: 可选，提供更多用户信息。
4.  **密码**: 设置一个**强密码**。强密码通常包含大小写字母、数字和符号，且长度足够。
5.  **密码选项**:
    -   `用户下次登录时须更改密码`: 强制用户在首次登录后设置自己的密码，非常推荐。
    -   `用户不能更改密码`: 限制用户修改密码，适用于服务账户等特殊场景。
    -   `密码永不过期`: 覆盖系统的密码策略，不推荐用于普通用户账户。
    -   `帐户已禁用`: 创建一个暂时不启用的账户。

#### 管理用户属性

双击一个用户账户，可以修改其属性：

-   **常规**: 修改全名、描述和密码选项。
-   **隶属于 (Member Of)**: **这是最重要的标签页**。它决定了该用户所属的组，从而决定了其权限。默认情况下，新用户只属于 `Users` 组。

---

### 4.3 使用 GUI 管理组

组是权限的集合。将用户添加到组中，该用户就会继承该组的所有权限。这样可以简化权限管理：我们给组分配权限，而不是给单个用户。

#### 内置组

Windows 包含许多具有预定义权限的内置组：

-   **Administrators (管理员组)**:
    -   该组的成员拥有对计算机的**完全控制权**。
    -   可以安装软件、修改系统设置、管理所有文件和用户。
    -   `Administrator` 账户是该组的默认成员。

-   **Users (普通用户组)**:
    -   该组的成员拥有标准的、受限的权限。
    -   可以运行已安装的程序、管理自己的文件。
    -   **不能**安装软件、修改系统设置或访问其他用户的文件。
    -   这是最安全的日常工作权限级别。

-   **Backup Operators**: 允许成员备份和还原文件，即使用户对这些文件没有直接的访问权限。
-   **Remote Desktop Users**: 允许成员通过远程桌面登录到该计算机。
-   **Power Users**: (为兼容旧版软件而保留，权限与 Users 组基本相同)。

#### 将用户添加到组

1.  在 `隶属于` 标签页中，点击 `添加`。
2.  输入你想要添加的组的名称（例如 `Administrators`），点击 `检查名称`，然后确定。
3.  或者，在 `组` 文件夹中双击一个组（如 `Administrators`），点击 `添加` 来将用户加入该组。

---

### 4.4 使用 PowerShell 管理本地用户和组

对于自动化和批量操作，PowerShell 是更高效的选择。需要**以管理员身份运行 PowerShell**。

#### 用户管理

-   **创建新用户**:
    ```powershell
    # 创建一个需要密码重置的新用户
    $Password = Read-Host -AsSecureString # 提示安全输入密码
    New-LocalUser -Name "bsmith" -Password $Password -FullName "Bob Smith" -UserMayNotChangePassword $false -PasswordNeverExpires $false
    ```

-   **查看用户信息**:
    ```powershell
    Get-LocalUser -Name "bsmith"
    ```

-   **禁用/启用用户**:
    ```powershell
    Disable-LocalUser -Name "bsmith"
    Enable-LocalUser -Name "bsmith"
    ```

-   **删除用户**:
    ```powershell
    Remove-LocalUser -Name "bsmith"
    ```

#### 组管理

-   **将用户添加到组**:
    ```powershell
    # 将用户 bsmith 添加到 Administrators 组
    Add-LocalGroupMember -Group "Administrators" -Member "bsmith"
    ```

-   **查看组成员**:
    ```powershell
    Get-LocalGroupMember -Group "Administrators"
    ```

-   **从组中移除用户**:
    ```powershell
    Remove-LocalGroupMember -Group "Administrators" -Member "bsmith"
    ```

---

### 4.5 最佳实践

-   **最小权限原则 (Principle of Least Privilege)**:
    -   日常工作应使用**标准用户账户 (Users 组)**，而不是管理员账户。
    -   仅在需要执行管理任务时，通过"以管理员身份运行"或用户账户控制 (UAC) 提示来提升权限。

-   **账户管理**:
    -   为每个用户创建独立的账户，不要共享。
    -   当员工离职时，应立即**禁用**其账户，而不是删除。这样可以保留其文件所有权和 SID (安全标识符) 以供审计，确认无误后再择机删除。

-   **密码策略**:
    -   强制使用强密码，并定期更换。这些可以通过本地安全策略或组策略 (GPO) 来强制执行。 