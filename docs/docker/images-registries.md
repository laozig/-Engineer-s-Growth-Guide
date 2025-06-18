# 5. 镜像与仓库

镜像是 Docker 的核心构建块，而仓库则是分发和管理这些镜像的中心。本章我们将深入探讨镜像的内部结构，以及如何有效地管理和共享它们。

## 深入理解镜像：分层结构

我们在前面的章节中提到，Docker 镜像是分层的。每一个 `Dockerfile` 中的指令（主要是 `RUN`, `COPY`, `ADD`）都会创建一个新的**层 (Layer)**。

-   **层是只读的**: 镜像的每一层都是只读的。当你从一个镜像启动一个容器时，Docker 会在镜像的最顶层添加一个**可写的容器层**。你在容器内做的所有修改（创建、修改、删除文件）都发生在这个可写层。
-   **层是可复用的**: 这是 Docker 高效的关键。如果多个镜像共享相同的基础层（例如，都基于 `ubuntu:22.04`），那么在宿主机上，这个基础层只需要存储一次。
-   **写时复制 (Copy-on-Write)**: 当容器需要修改一个来自下层只读层的文件时，Docker 会使用写时复制策略。它会将该文件从只读层复制到顶部的可写容器层，然后对副本进行修改。原始文件保持不变。

![Layered Filesystem](https://i.imgur.com/your-layers-image.png) <!-- 你需要替换成真实的图片链接 -->

这种分层结构使得镜像的构建、存储和分发都极其高效。

## 管理本地镜像

我们已经接触过一些镜像管理命令，这里我们做更深入的探讨。

-   **`docker history <image>`**: 查看一个镜像的构建历史。这会显示构成镜像的每一层，以及创建它们的指令。这对于理解镜像是如何构建的以及诊断问题非常有用。
    ```bash
    docker history nginx:latest
    ```

-   **悬空镜像 (Dangling Images)**:
    当你重新构建一个已存在的镜像时（例如，`docker build -t my-app .`），旧的镜像并不会被自动删除，它的标签会被新镜像占用，导致旧镜像变成一个没有标签、ID 为 `<none>:<none>` 的镜像。这种镜像被称为"悬空镜像"。
    它们会占用磁盘空间，应该定期清理。
    ```bash
    # 列出所有悬空镜像
    docker images -f "dangling=true"

    # 清理所有悬空镜像
    docker image prune
    ```
    更简单的方法是使用我们之前学过的 `docker system prune`。

## 镜像仓库 (Registry) 详解

镜像仓库是用于存储和分发 Docker 镜像的服务。

### 1. 公共仓库: Docker Hub

[Docker Hub](https://hub.docker.com/) 是由 Docker 公司维护的、默认的、也是最大的公共镜像仓库。
-   **官方镜像 (Official Images)**: 由 Docker 公司审查和维护的精选镜像（如 `ubuntu`, `nginx`, `redis`）。它们是安全、遵循最佳实践的，通常是你构建自定义镜像时的首选基础镜像。
-   **社区镜像 (Community Images)**: 由个人或其他组织发布和维护的镜像。它们数量庞大，涵盖了几乎所有你能想到的应用。在使用社区镜像时，你应该检查其 Dockerfile 和受欢迎程度（星标数、拉取次数）来判断其质量和安全性。

### 2. 私有仓库 (Private Registries)

虽然 Docker Hub 很方便，但在企业和团队协作中，通常需要使用私有仓库。
**为什么需要私有仓库？**
-   **安全性**: 你不希望将包含专有代码的应用程序镜像公开给全世界。
-   **速度**: 将仓库部署在离你的服务器更近的网络中，可以大大加快镜像的拉取速度。
-   **控制权**: 完全控制镜像的存储、访问和版本管理策略。

**常见的私有仓库解决方案**:
-   **Docker Official Registry**: Docker 官方提供了一个开源的镜像仓库应用，你可以非常轻松地以一个 Docker 容器的形式在自己的服务器上部署一个基础的私有仓库。
    ```bash
    docker run -d -p 5000:5000 --name registry registry:2
    ```
-   **云厂商提供的仓库**:
    -   Amazon Elastic Container Registry (ECR)
    -   Google Artifact Registry (GAR)
    -   Azure Container Registry (ACR)
    这些服务是全托管的，提供了高可用性、安全扫描和与各自云生态系统的深度集成。
-   **第三方解决方案**:
    -   **Harbor**: 一个 CNCF 的毕业项目，提供了企业级的特性，如基于角色的访问控制 (RBAC)、漏洞扫描、垃圾回收等。
    -   **Nexus Repository**: 一个支持多种格式（包括 Docker）的通用仓库管理器。
    -   **JFrog Artifactory**: 另一个功能强大的通用仓库管理器。

## 推送与拉取工作流

与远程仓库交互遵循一个标准的工作流程：

**1. `docker login`**: 登录到一个镜像仓库。对于 Docker Hub，你只需要运行 `docker login`。对于私有仓库，你需要提供仓库的主机名。
```bash
# 登录到 Docker Hub
docker login

# 登录到本地运行在 5000 端口的私有仓库
docker login localhost:5000
```

**2. `docker tag`**: 在推送前，你需要将本地镜像标记成符合远程仓库命名规范的格式。
**格式**: `<registry-host>/<username_or_project>/<image_name>:<tag>`

-   **Docker Hub**: `your-username/my-app:1.0`
-   **私有仓库**: `localhost:5000/my-app:1.0`
-   **云厂商**: 通常会有更长的格式，如 `123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:1.0`

**示例**:
```bash
# 假设我们有一个名为 my-app:latest 的本地镜像
# 将其标记以便推送到本地私有仓库
docker tag my-app:latest localhost:5000/my-app:1.0
```

**3. `docker push`**: 将标记好的镜像推送到仓库。
```bash
docker push localhost:5000/my-app:1.0
```

**4. `docker pull`**: 从其他机器上拉取这个镜像。
```bash
docker pull localhost:5000/my-app:1.0
```

**5. `docker logout`**: 登出仓库。
```bash
docker logout localhost:5000
```

理解并熟练运用镜像和仓库，是实现高效、可扩展的容器化应用交付流程的基础。 