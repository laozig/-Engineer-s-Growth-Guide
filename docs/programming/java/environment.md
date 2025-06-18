# 1. 环境搭建

在开始 Java 企业级开发之前，搭建一个稳定、高效的开发环境至关重要。本章将指导你完成 JDK 的安装、构建工具（Maven 和 Gradle）的配置以及主流集成开发环境（IDE）的设置。

## 1.1. 安装与配置 JDK

Java Development Kit (JDK) 是 Java 开发的核心，包含了 Java 编译器、运行时环境（JRE）和核心类库。我们推荐安装长期支持（LTS）版本，如 Java 11、Java 17 或最新的 Java 21。

### Windows 系统

1.  **下载 JDK**:
    -   访问 [Oracle Java SE Downloads](https://www.oracle.com/java/technologies/downloads/) 或 [OpenJDK](https://jdk.java.net/) (如 Adoptium Temurin)。
    -   选择对应的 Windows x64 安装包（`.msi` 或 `.zip`）。

2.  **安装**:
    -   如果下载的是 `.msi` 文件，双击运行并按照向导完成安装。默认安装路径通常在 `C:\Program Files\Java\jdk-xx`。
    -   如果下载的是 `.zip` 文件，解压到你选择的目录，如 `D:\dev\jdk-17`。

3.  **配置环境变量**:
    -   在 Windows 搜索框中输入"环境变量"，选择"编辑系统环境变量"。
    -   在"系统属性"窗口中，点击"环境变量"按钮。
    -   在"系统变量"下，点击"新建"：
        -   **变量名**: `JAVA_HOME`
        -   **变量值**: `C:\Program Files\Java\jdk-17.0.2` (你的 JDK 安装路径)
    -   找到并编辑 `Path` 变量，在列表顶部添加一个新的条目：
        -   `%JAVA_HOME%\bin`
    -   点击"确定"保存所有设置。

4.  **验证安装**:
    -   打开新的命令提示符（CMD）或 PowerShell，输入以下命令：
    ```bash
    java -version
    javac -version
    ```
    -   如果能正确显示 Java 和 Javac 的版本号，则表示安装成功。

### macOS / Linux 系统

1.  **安装 JDK**:
    -   **macOS**: 可以使用 [Homebrew](https://brew.sh/) 进行安装：
        ```bash
        brew install openjdk@17
        ```
    -   **Linux (Ubuntu/Debian)**:
        ```bash
        sudo apt update
        sudo apt install openjdk-17-jdk
        ```
    -   **Linux (CentOS/Fedora)**:
        ```bash
        sudo dnf install java-17-openjdk-devel
        ```

2.  **配置环境变量**:
    -   编辑 `~/.bashrc`, `~/.zshrc` 或 `~/.profile` 文件：
    ```bash
    export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64  # 根据实际安装路径修改
    export PATH=$JAVA_HOME/bin:$PATH
    ```
    -   保存文件后，执行 `source ~/.bashrc` (或对应的配置文件) 使其生效。

3.  **验证安装**:
    -   打开新的终端，执行 `java -version` 和 `javac -version`。

## 1.2. 设置构建工具

Maven 和 Gradle 是 Java 世界最流行的项目构建和依赖管理工具。

### Maven

Maven 使用 XML 格式的 `pom.xml` 文件来管理项目。

1.  **下载**: 从 [Maven 官网](https://maven.apache.org/download.cgi) 下载二进制 `zip` 压缩包。
2.  **安装**: 解压到指定目录，如 `D:\dev\apache-maven-3.8.4`。
3.  **配置环境变量**:
    -   新建系统变量 `MAVEN_HOME`，值为你的 Maven 安装路径。
    -   在 `Path` 变量中添加 `%MAVEN_HOME%\bin`。
4.  **验证**: 打开新终端，运行 `mvn -v`。
5.  **(可选) 配置国内镜像源**:
    -   编辑 Maven 安装目录下的 `conf/settings.xml` 文件。
    -   在 `<mirrors>` 标签内添加阿里云镜像配置，可以极大提升依赖下载速度：
    ```xml
    <mirror>
      <id>aliyunmaven</id>
      <mirrorOf>*</mirrorOf>
      <name>Aliyun Maven</name>
      <url>https://maven.aliyun.com/repository/public</url>
    </mirror>
    ```

### Gradle

Gradle 使用 Groovy 或 Kotlin DSL (`build.gradle`)，提供了更灵活和高效的构建方式。

1.  **安装**:
    -   可以使用包管理器安装，如 `sdkman` (`sdk install gradle`) 或 `brew install gradle`。
    -   也可以从 [Gradle 官网](https://gradle.org/releases/) 手动下载并配置环境变量（类似 Maven）。
2.  **验证**: 打开新终端，运行 `gradle -v`。

## 1.3. IDE 配置

一个好的 IDE 能显著提升开发效率。IntelliJ IDEA 是目前 Java 开发者的首选。

### IntelliJ IDEA

1.  **下载安装**:
    -   从 [JetBrains 官网](https://www.jetbrains.com/idea/download/) 下载。社区版（Community）免费，但功能有限；旗舰版（Ultimate）功能强大，支持所有企业级开发框架，推荐使用（可申请学生免费授权或试用）。
2.  **配置 JDK**:
    -   首次启动或在 `File > Project Structure > SDKs` 中，可以添加已安装的 JDK。IDEA 通常会自动检测系统中的 `JAVA_HOME`。
3.  **配置构建工具**:
    -   在 `File > Settings > Build, Execution, Deployment > Build Tools > Maven` 中，可以指定自己安装的 Maven 路径和 `settings.xml` 文件，以使用国内镜像。
    -   Gradle 配置类似。
4.  **重要插件推荐**:
    -   `.env files support`: 支持 `.env` 文件。
    -   `Lombok`: 简化 JavaBean 开发（需要项目中引入对应依赖）。
    -   `SonarLint`: 实时代码质量检查。
    -   `Docker`: 提供 Docker 支持。

### Visual Studio Code

VS Code 通过扩展包也能很好地支持 Java 开发，适合轻量级项目。

1.  **安装**: 从 [VS Code 官网](https://code.visualstudio.com/) 下载。
2.  **安装扩展包**:
    -   在扩展市场搜索并安装 "Extension Pack for Java"。这个扩展包会自动安装 Debugger for Java, Test Runner for Java, Maven for Java 等核心插件。
3.  **配置 JDK**:
    -   打开设置 (Ctrl+,)，搜索 `java.jdt.ls.java.home`，将其设置为你的 JDK 安装路径。

---

环境搭建完成后，你的系统就已经具备了进行现代 Java 企业级开发的全部条件。接下来，我们将回顾一些核心的 Java 概念。 