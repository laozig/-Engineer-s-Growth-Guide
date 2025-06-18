# 4. 编写 Dockerfile

到目前为止，我们使用的都是别人已经构建好的镜像。而 Docker 的真正威力在于能够通过一个名为 `Dockerfile` 的文件，来精确、可重复地构建我们自己的应用程序镜像。`Dockerfile` 是实现"基础设施即代码"的基石。

## Dockerfile 是什么？

`Dockerfile` 是一个纯文本文件，它包含了一系列用户可以执行的指令，用于自动地从一个基础镜像开始，一步步构建出一个新的、自定义的镜像。

`docker build` 命令会读取这个文件，并根据其中的指令来执行构建过程。

## 基本结构与常用指令

一个 `Dockerfile` 通常遵循以下结构：

```Dockerfile
# 注释：指定基础镜像
FROM ubuntu:22.04

# 注释：添加元数据，如作者信息
LABEL maintainer="your-name@example.com"

# 注释：设置环境变量
ENV APP_HOME /app

# 注释：设置工作目录
WORKDIR $APP_HOME

# 注释：复制文件到镜像中
COPY . .

# 注释：在构建过程中运行命令，例如安装依赖
RUN apt-get update && apt-get install -y python3

# 注释：声明容器运行时监听的端口
EXPOSE 5000

# 注释：定义容器启动时执行的命令
CMD ["python3", "app.py"]
```

让我们来详细了解每一个常用指令。

-   **`FROM <image>[:tag]`**
    -   必须是 `Dockerfile` 中的第一个非注释指令。
    -   指定了你的镜像将要基于哪个**基础镜像**来构建。

-   **`LABEL <key>=<value>`**
    -   为生成的镜像添加元数据，如作者、版本、描述等。这是一个很好的实践。

-   **`WORKDIR /path/to/workdir`**
    -   为后续的 `RUN`, `CMD`, `ENTRYPOINT`, `COPY`, `ADD` 指令设置工作目录。
    -   如果目录不存在，它会自动被创建。推荐使用绝对路径。

-   **`COPY <src> <dest>`**
    -   将本地**构建上下文**中的文件或目录复制到镜像内的指定路径。
    -   `src` 路径必须是相对于构建上下文的路径。
    -   推荐优先使用 `COPY`，因为它比 `ADD` 更透明、更直接。

-   **`ADD <src> <dest>`**
    -   功能与 `COPY` 类似，但有两个额外功能：
        1.  如果 `<src>` 是一个 URL，它会下载文件。
        2.  如果 `<src>` 是一个本地的 `tar` 压缩文件，它会自动解压到 `<dest>`。
    -   由于其"魔法"行为，除非你明确需要上述特殊功能，否则应始终优先使用 `COPY`。

-   **`RUN <command>`**
    -   在镜像**构建过程**中，在当前镜像层之上执行指定的命令，并将结果提交为新的一层。
    -   常用于安装软件包、编译代码等。可以链式调用 (`RUN command1 && command2`) 以减少镜像层数。

-   **`EXPOSE <port>`**
    -   向 Docker 声明容器在运行时会监听的特定网络端口。
    -   这**不会**自动发布端口。它只是一个元数据，起到文档的作用，并且在使用 `-P` (大写) 运行容器时，会自动发布这些声明的端口。

-   **`ENV <key>=<value>`**
    -   设置持久的环境变量。这个环境变量在镜像构建过程 (`RUN`) 和容器运行过程 (`CMD`, `ENTRYPOINT`) 中都可用。

### `CMD` vs. `ENTRYPOINT`

这两个指令都用于定义容器启动时执行的命令，但它们的行为和交互方式是初学者最容易混淆的地方。

-   **`CMD ["executable","param1","param2"]`** (exec 格式, 推荐)
    -   **目的**: 为正在执行的容器**提供默认的执行命令**。
    -   **特点**:
        -   一个 Dockerfile 中只能有一个 `CMD` 指令生效。
        -   `docker run` 命令如果带有参数，会**覆盖** `CMD` 的内容。
    -   **示例**: `CMD ["python", "app.py"]`. 如果用户运行 `docker run my-image ls -l`，则 `CMD` 会被忽略，容器会执行 `ls -l`。

-   **`ENTRYPOINT ["executable", "param1", "param2"]`** (exec 格式, 推荐)
    -   **目的**: 将容器配置为像一个**可执行文件**一样运行。
    -   **特点**:
        -   `docker run` 命令的参数会**追加**到 `ENTRYPOINT` 指令之后。
        -   不会被 `docker run` 的参数轻易覆盖（需要使用 `--entrypoint` 标志）。
    -   **示例**: `ENTRYPOINT ["redis-server"]`. 如果用户运行 `docker run my-image --port 6380`，则容器会执行 `redis-server --port 6380`。

-   **组合使用 `ENTRYPOINT` 和 `CMD`**:
    -   这是最常见的最佳实践。`ENTRYPOINT` 定义主命令，`CMD` 为主命令提供**默认参数**。
    -   **示例**:
        ```Dockerfile
        ENTRYPOINT ["/usr/bin/git"]
        CMD ["--help"]
        ```
        -   运行 `docker run my-git-image` -> 执行 `/usr/bin/git --help`
        -   运行 `docker run my-git-image status` -> 执行 `/usr/bin/git status`

## 构建上下文 (Build Context)

当你运行 `docker build .` 时，最后的 `.` 非常重要。它告诉 Docker，**构建上下文**是当前目录。

构建上下文是指本地文件系统中所有文件和目录的集合，Docker 守护进程在构建镜像时可以访问这些文件。`COPY` 或 `ADD` 指令的源路径都必须在此上下文中。

## 层缓存 (Layer Caching)

Docker 在构建镜像时，会缓存每一条指令成功执行后产生的结果（即一个镜像层）。
-   当再次构建时，如果某条指令及其引用的文件没有发生任何变化，Docker 就会直接使用缓存中的层，而不是重新执行该指令。
-   这大大加快了镜像的构建速度。
-   **最佳实践**: 将不经常变化的指令（如安装系统依赖的 `RUN`）放在前面，将经常变化的指令（如 `COPY . .`）放在后面，可以最大化地利用缓存。

## `.dockerignore` 文件

为了减小构建上下文的大小，从而加快构建速度并减小最终镜像的体积，你应该在构建上下文的根目录创建一个 `.dockerignore` 文件。
它的语法类似于 `.gitignore`，用于排除不需要复制到镜像中的文件和目录。

**示例 (`.dockerignore`)**:
```
.git
node_modules
*.log
Dockerfile
```

## 完整示例 (Node.js Web 应用)

**目录结构**:
```
.
├── .dockerignore
├── Dockerfile
├── node_modules/
├── package.json
└── server.js
```

**`Dockerfile`**:
```Dockerfile
# 1. 使用官方的 Node.js 18 的轻量级版本作为基础镜像
FROM node:18-alpine

# 2. 设置工作目录
WORKDIR /usr/src/app

# 3. 复制 package.json 和 package-lock.json
#    将这一步分开，可以利用层缓存。只有在这些文件变化时，才会重新安装依赖。
COPY package*.json ./

# 4. 安装应用依赖
RUN npm install

# 5. 将应用的其余源代码复制到镜像中
COPY . .

# 6. 声明应用监听的端口
EXPOSE 3000

# 7. 定义容器启动时运行的命令
CMD [ "node", "server.js" ]
```

**构建镜像**:
```bash
docker build -t my-node-app .
```
这个过程清晰、高效且可重复，这就是 Dockerfile 的强大之处。 