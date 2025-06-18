# 1.1 环境搭建：从零到一的 Java 开发环境配置

欢迎来到 Java 的世界！在编写任何代码之前，我们需要一个稳定、高效的开发环境。本章是您 Java 学习之旅的第一步，将手把手指导您完成从 JDK 安装到 IDE 配置的全过程。

## 核心组件

我们的 Java 开发环境主要由以下三部分组成：
1.  **JDK (Java Development Kit)**: Java 开发工具包，我们编程所需的一切工具的核心。
2.  **构建工具 (Build Tool)**: 如 Maven 或 Gradle，用于自动化管理项目依赖和构建过程。
3.  **IDE (Integrated Development Environment)**: 集成开发环境，如 IntelliJ IDEA，我们编写、调试和运行代码的地方。

---

## 第一部分：安装与配置 JDK

JDK 是 Java 的心脏，包含了 Java 编译器 (`javac`)、Java 运行时环境 (JRE) 和核心类库。我们强烈推荐安装 **长期支持 (LTS) 版本**，例如 Java 11, 17 或 21，因为它们提供了更长的维护和安全更新周期。

### 在 Windows 上安装 JDK

1.  **选择并下载 JDK**:
    *   **推荐**: 访问 [Adoptium Temurin](https://adoptium.net/temurin/releases/)，这是一个由 Eclipse 基金会支持的高质量 OpenJDK 发行版。
    *   **备选**: [Oracle JDK](https://www.oracle.com/java/technologies/downloads/)。
    *   在下载页面，选择适合您系统的 LTS 版本（如 17 或 21）和 Windows x64 的 `.msi` 安装程序。

2.  **运行安装程序**:
    *   双击下载的 `.msi` 文件。
    *   遵循安装向导的指示。建议保持默认安装路径（通常是 `C:\Program Files\Eclipse Adoptium\jdk-17.0.x.x`），并确保勾选 "Add to PATH" 和 "Set `JAVA_HOME` variable" 选项。这会让安装程序自动为您配置环境变量。

3.  **手动配置环境变量 (如果安装程序未自动配置)**:
    *   在 Windows 搜索中输入 "环境变量"，然后选择 "编辑系统环境变量"。
    *   在弹出的"系统属性"窗口中，点击"环境变量..."。
    *   在"系统变量"部分：
        *   **新建 `JAVA_HOME`**: 点击"新建"，变量名输入 `JAVA_HOME`，变量值输入您的 JDK 安装目录（例如 `C:\Program Files\Java\jdk-17.0.2`）。
        *   **编辑 `Path`**: 找到并双击 `Path` 变量，在列表中点击"新建"，然后输入 `%JAVA_HOME%\bin`。确保将此条目移动到列表顶部，以保证其优先被系统找到。
    *   点击所有"确定"按钮以保存更改。

4.  **验证安装**:
    *   **重要**: 打开一个 **新的** 命令提示符 (CMD) 或 PowerShell 窗口。
    *   分别输入以下两个命令并回车：
        ```sh
        java -version
        javac -version
        ```
    *   如果系统能正确显示出您安装的 JDK 版本号，恭喜您，JDK 已成功安装！

### 在 macOS 上安装 JDK

macOS 用户可以利用 [Homebrew](https://brew.sh/)（一个流行的包管理器）来简化安装过程。

1.  **安装 Homebrew (如果尚未安装)**:
    ```sh
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    ```

2.  **使用 Homebrew 安装 JDK**:
    ```sh
    brew install openjdk@17
    ```

3.  **验证安装**:
    *   Homebrew 会自动处理环境变量的配置。打开新终端，直接运行验证命令：
        ```sh
        java -version
        ```

### 在 Linux (Ubuntu/Debian) 上安装 JDK

1.  **更新包列表**:
    ```sh
    sudo apt update
    ```
2.  **安装 OpenJDK**:
    ```sh
    sudo apt install openjdk-17-jdk
    ```
3.  **验证安装**:
    ```sh
    java -version
    ```

---

## 第二部分：设置构建工具

企业级 Java 项目几乎都使用构建工具来管理复杂的依赖库和构建流程。

### Maven

1.  **下载**: 访问 [Maven 官网](https://maven.apache.org/download.cgi)，下载最新的 `bin.zip` 或 `bin.tar.gz` 文件。
2.  **解压**: 将文件解压到一个纯英文、无空格的路径，例如 `D:\dev\apache-maven-3.9.6`。
3.  **配置环境变量**:
    *   新建 `MAVEN_HOME` 系统变量，指向您的 Maven 解压目录。
    *   在 `Path` 变量中，添加 `%MAVEN_HOME%\bin`。
4.  **配置国内镜像 (强烈推荐)**:
    *   为了闪电般地下载依赖，需要替换默认的中央仓库。打开 Maven 目录下的 `conf/settings.xml` 文件。
    *   找到 `<mirrors>` 标签，在其中添加以下阿里云的镜像配置：
        ```xml
        <mirror>
          <id>aliyunmaven</id>
          <mirrorOf>*</mirrorOf>
          <name>Aliyun Maven</name>
          <url>https://maven.aliyun.com/repository/public</url>
        </mirror>
        ```
5.  **验证**: 打开新终端，运行 `mvn -v`。

---

## 第三部分：配置 IDE - IntelliJ IDEA

IntelliJ IDEA 是 Java 开发的行业标准，其强大的功能可以极大地提升您的开发效率。

1.  **下载与安装**:
    *   访问 [JetBrains 官网](https://www.jetbrains.com/idea/download/) 下载 **Community (社区版)**。社区版对个人和开源项目完全免费，足以满足核心 Java 的学习需求。
    *   运行安装程序，根据向导完成安装。

2.  **首次启动与配置**:
    *   **项目 SDK**: 当您创建第一个项目时，IDEA 会要求您指定 Project SDK。在这里选择您之前安装的 JDK 即可。IDEA 通常能自动检测到。
    *   **Maven 配置**:
        *   打开设置 `File > Settings` (或 `Ctrl+Alt+S`)。
        *   导航到 `Build, Execution, Deployment > Build Tools > Maven`。
        *   在 `Maven home path` 中，选择您自己安装的 Maven 目录。
        *   在 `User settings file` 中，勾选 `Override` 并指向您刚刚修改过的 `conf/settings.xml` 文件。这能确保 IDEA 使用您的国内镜像配置。

3.  **必备插件推荐**:
    *   `Chinese (Simplified) Language Pack`: 官方中文语言包。
    *   `SonarLint`: 实时发现代码中的质量和安全问题。
    *   `Key Promoter X`: 帮助您记忆快捷键，快速成为高效开发者。

---

至此，您的机器已经拥有了一个专业级的 Java 开发环境。您可以开始创建您的第一个 Java 项目了！ 