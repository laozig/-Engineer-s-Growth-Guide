# 12. 文件与打印服务

文件和打印服务是任何企业网络中最基本、最常用的服务之一。Windows Server 提供了强大而灵活的功能来集中管理文件共享和网络打印机。

---

### 12.1 文件服务 (File Services)

文件服务允许多个用户通过网络访问存储在服务器上的文件。这需要两个层面的权限设置：**共享权限**和 **NTFS 权限**。

#### 共享权限 vs. NTFS 权限

这是一个非常重要的概念：

-   **共享权限 (Share Permissions)**:
    -   在**文件夹共享**级别设置。
    -   控制用户通过**网络**访问该共享文件夹时的权限。
    -   权限级别很简单：`完全控制`、`更改`、`读取`。
    -   它们是用户进入共享大门的"第一道防线"。

-   **NTFS 权限 (NTFS Permissions)**:
    -   在**文件系统**级别设置（我们在第 5 章已学习过）。
    -   控制用户对文件和文件夹的**实际**访问权限，无论用户是**本地登录**还是**通过网络访问**。
    -   权限级别更精细：完全控制、修改、读取和执行等。
    -   它们是用户通过大门后的"第二道、也是最终的防线"。

**最终有效权限**: 当用户通过网络访问时，系统会取**共享权限**和 **NTFS 权限**中**限制更严格 (the most restrictive)** 的那个作为最终的有效权限。

**最佳实践**:
-   将**共享权限**设置为一个非常宽松的级别，例如 `Authenticated Users` (所有通过验证的用户) 拥有 `更改` 或 `完全控制` 权限。
-   然后，使用**更精细的 NTFS 权限**来严格控制对文件夹和文件的实际访问。
-   **一句话总结：用共享权限"开大门"，用 NTFS 权限"管房间"。**

#### 创建文件共享

**方法一：简单共享 (不推荐用于服务器)**
-   在文件资源管理器中右键点击文件夹 -> `授予访问权限`。这是一种快速的共享方式，但控制粒度很粗。

**方法二：高级共享 (Advanced Sharing - 推荐)**
1.  右键点击要共享的文件夹 -> `属性` -> `共享` 选项卡 -> `高级共享...`。
2.  勾选 `共享此文件夹`。
3.  **共享名**: 设置网络访问时使用的名称（可以不同于文件夹名）。`$` 后缀（如 `Data$`）可以创建**隐藏共享**，用户无法在网络邻居中浏览到，必须知道确切路径 (`\\server\Data$`) 才能访问。
4.  **权限 (Permissions)** 按钮:
    -   点击进入，设置**共享权限**。
    -   默认只有 `Everyone` 的读取权限。通常建议移除 `Everyone`，添加 `Authenticated Users` 并给予 `更改` 或 `完全控制` 权限。
5.  **缓存 (Caching)** 按钮: 配置脱机文件，允许用户在断开网络时访问文件的缓存版本。

配置完共享后，不要忘记去 `安全` 选项卡配置 **NTFS 权限**！

---

### 12.2 打印服务 (Print Services)

Windows Server 的打印服务器角色允许你集中管理网络中的所有打印机。用户只需连接到打印服务器，就可以使用所有已发布的打印机，而无需在每台电脑上单独安装驱动程序。

#### 安装打印服务器角色

1.  **服务器管理器** -> `添加角色和功能`。
2.  在**服务器角色**列表中，勾选 `打印和文件服务 (Print and Document Services)`。
3.  在角色服务中，确保 `打印服务器 (Print Server)` 被选中。
4.  完成安装。

#### 添加和共享打印机

1.  **打开打印管理器**:
    -   `服务器管理器` -> `工具` -> `打印管理`。

2.  **安装打印机驱动程序**:
    -   在 `打印服务器` -> `你的服务器` -> `驱动程序` 上右键，选择 `添加驱动程序`。
    -   最好同时安装 **x64** 和 **x86** (32位) 版本的驱动程序，以兼容所有客户端。

3.  **添加打印机**:
    -   在 `打印机` 上右键，选择 `添加打印机...`。
    -   根据向导，选择打印机的连接方式（最常见的是 `使用 TCP/IP 地址或主机名添加打印机`）。
    -   输入打印机的 IP 地址，安装正确的驱动程序。

4.  **共享打印机**:
    -   添加完成后，在打印机上右键 -> `属性` -> `共享` 选项卡。
    -   勾选 `共享这台打印机`，并设置一个共享名。
    -   勾选 `在目录中列出` 会将打印机发布到 Active Directory 中，使用户可以更轻松地搜索和找到它。

#### 客户端连接

-   在客户端电脑上，打开文件资源管理器，在地址栏输入 `\\YourPrintServerName`。
-   你会看到所有共享的打印机列表。
-   双击要连接的打印机，Windows 会自动从服务器下载并安装驱动程序，然后完成连接。

---

### 12.3 分布式文件系统 (DFS)

DFS 是 Windows Server 提供的一项高级文件服务技术，包含两个主要组件：

-   **DFS 命名空间 (DFS Namespace)**:
    -   它允许你将位于**不同服务器**上的多个共享文件夹，聚合到一个**统一的、逻辑的**文件夹结构下。
    -   用户只需访问一个路径（如 `\\yourdomain\Public`），而无需关心 `Public` 文件夹下的数据实际存储在哪台服务器上。
    -   极大地简化了用户访问和后台数据迁移。

-   **DFS 复制 (DFS Replication)**:
    -   一个多主复制引擎，可以保持多个服务器上文件夹内容的同步。
    -   常与 DFS 命名空间结合使用，为共享文件提供**高可用性**和**容错能力**。如果一台文件服务器宕机，用户可以无缝地被重定向到另一台持有相同数据副本的服务器上。

DFS 是构建大规模、高可用文件服务的核心技术。 