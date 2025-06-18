# 16. 容器化 (Docker, Podman)

容器化是一种轻量级的虚拟化技术，它允许你将应用程序及其所有依赖（库、配置文件、运行时等）打包到一个标准化的、可移植的单元中，即**容器**。这个容器可以在任何支持容器化的 Linux 系统上运行，表现完全一致。

## 容器 vs. 虚拟机 (VM)

理解容器与传统虚拟机的区别至关重要：

- **虚拟机 (Virtual Machine)**:
  - 在物理硬件（Host OS）之上运行一个完整的客户操作系统（Guest OS），包括其自身的内核。
  - 每个 VM 都需要GB级别的存储空间和内存。
  - 启动慢，资源开销大。
  - 提供了完全的隔离。

- **容器 (Container)**:
  - **共享宿主机的内核**。容器内只包含应用程序及其依赖，不包含操作系统内核。
  - 容器是轻量级的，通常只有MB级别。
  - 启动速度极快，接近原生应用。
  - 资源占用少，可以在一台机器上运行数百个容器。
  - 隔离性不如 VM，但对于大多数应用来说已经足够。

![Container vs VM](https://i.imgur.com/your-container-vm-image.png) <!-- 你需要替换成真实的图片链接 -->

## 1. Docker

Docker 是目前最流行和使用最广泛的容器化平台。它极大地简化了容器的创建、管理和分发。

### Docker 核心概念
- **镜像 (Image)**: 一个只读的模板，包含了创建容器所需的一切：代码、运行时、库、环境变量和配置文件。镜像是分层构建的。
- **容器 (Container)**: 镜像的一个可运行实例。你可以从同一个镜像创建任意多个容器。容器是可写的，你在容器内做的任何修改都只存在于该容器中。
- **Dockerfile**: 一个纯文本文件，定义了如何一步步构建一个 Docker 镜像。这是实现"基础设施即代码"的关键。
- **仓库 (Registry)**: 存储和分发 Docker 镜像的地方。Docker Hub 是官方的公共仓库。

### 安装 Docker (以 Ubuntu 为例)
```bash
# 卸载旧版本
sudo apt-get remove docker docker-engine docker.io containerd runc

# 设置 Docker 的 apt 仓库
sudo apt-get update
sudo apt-get install ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# 安装 Docker Engine
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# 将当前用户添加到 docker 组以避免每次都输入 sudo (需要重新登录后生效)
sudo usermod -aG docker $USER
```

### 常用 Docker 命令
- **`docker run`**: 从镜像创建并启动一个新容器。
  ```bash
  # 运行一个 nginx 容器，将容器的80端口映射到宿主机的8080端口，并在后台运行
  docker run --name my-nginx -d -p 8080:80 nginx

  # 运行一个 ubuntu 容器，并进入其交互式 shell
  docker run -it ubuntu /bin/bash
  ```
- **`docker ps`**: 列出正在运行的容器。
  - `docker ps -a`: 列出所有容器（包括已停止的）。
- **`docker images`**: 列出本地存储的所有镜像。
- **`docker stop <container_id_or_name>`**: 停止一个正在运行的容器。
- **`docker start <container_id_or_name>`**: 启动一个已停止的容器。
- **`docker rm <container_id_or_name>`**: 删除一个容器。
  - `docker rm $(docker ps -aq)`: 删除所有已停止的容器。
- **`docker rmi <image_id_or_name>`**: 删除一个镜像。
- **`docker logs <container_id_or_name>`**: 查看容器的日志。
  - `docker logs -f <container_id>`: 实时跟踪日志。
- **`docker exec -it <container_id> <command>`**: 在一个正在运行的容器内执行一个命令。
  ```bash
  docker exec -it my-nginx /bin/bash
  ```
- **`docker build -t <image_name:tag> .`**: 从当前目录的 Dockerfile 构建一个镜像。

### 编写一个简单的 Dockerfile
```Dockerfile
# 使用官方的 Python 3.9 slim 版本作为基础镜像
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 将当前目录下的 requirements.txt 复制到容器的 /app/ 目录
COPY requirements.txt .

# 在容器内运行 pip 命令来安装依赖
RUN pip install --no-cache-dir -r requirements.txt

# 将当前目录下的所有文件复制到容器的 /app/ 目录
COPY . .

# 暴露端口 5000
EXPOSE 5000

# 定义容器启动时要执行的命令
CMD ["python", "app.py"]
```

## 2. Podman

Podman 是一个由 Red Hat 开发的容器引擎，旨在成为 Docker 的直接替代品。它的主要特点是：

- **无守护进程 (Daemonless)**: Docker 依赖一个长时间运行的后台守护进程 (`dockerd`)。而 Podman 直接与容器运行时 (如 `runc`) 交互，减少了系统的复杂性和潜在的安全风险。
- **无根模式 (Rootless)**: Podman 可以在普通用户权限下运行，无需 `root`。这极大地提高了安全性。
- **命令兼容**: Podman 的命令与 Docker 的命令几乎完全相同。你可以直接用 `podman` 替换 `docker`。
  ```bash
  alias docker=podman
  ```

### 安装 Podman (以 Fedora 为例)
```bash
sudo dnf install podman
```

### 使用 Podman
由于命令兼容，你可以参考上面的 Docker 命令列表，将 `docker` 替换为 `podman` 即可。

```bash
# 运行 nginx
podman run --name my-nginx -d -p 8080:80 nginx

# 列出正在运行的容器
podman ps
```

## 总结
容器化技术彻底改变了软件的开发、分发和部署方式。
- **Docker** 是当前的事实标准，拥有最庞大的社区和生态系统。
- **Podman** 提供了一个更安全、更现代的替代方案，特别是在注重安全性的企业环境中越来越受欢迎。

掌握容器化技术对于现代 Linux 系统管理员和开发者来说是一项必备技能。 