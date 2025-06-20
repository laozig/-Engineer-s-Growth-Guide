# 容器化技术

## 容器技术简介

容器是一种轻量级的虚拟化技术，它将应用程序及其依赖打包在一个独立的单元中。与传统虚拟机不同，容器共享主机的操作系统内核，因此启动更快、资源消耗更少。

### 容器 vs 虚拟机

| 特性 | 容器 | 虚拟机 |
|------|------|--------|
| 隔离级别 | 进程级隔离 | 完全隔离 |
| 资源开销 | 轻量级 | 较重 |
| 启动时间 | 秒级 | 分钟级 |
| 存储空间 | MB 级别 | GB 级别 |
| 操作系统 | 共享宿主 OS 内核 | 包含完整 OS |

### 容器技术的优势

- **一致的环境**：从开发到测试到生产，保持一致的运行环境
- **快速部署**：容器可以在几秒内启动
- **高效利用资源**：多个容器共享操作系统资源
- **隔离性**：容器之间相互隔离，不会相互影响
- **可移植性**：可以在任何支持容器技术的平台上运行

## Docker

Docker 是目前最流行的容器平台，它简化了容器的创建、部署和运行过程。

### 核心概念

- **镜像 (Image)**：容器的只读模板，包含运行容器所需的所有文件和配置
- **容器 (Container)**：镜像的运行实例，可以被启动、停止、删除
- **仓库 (Repository)**：存储和分发 Docker 镜像的地方，如 Docker Hub

### 安装 Docker

```bash
# Ubuntu
sudo apt update
sudo apt install docker.io
sudo systemctl enable --now docker

# CentOS
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo yum install docker-ce docker-ce-cli containerd.io
sudo systemctl start docker
sudo systemctl enable docker
```

### 基本命令

```bash
# 查看 Docker 版本
docker --version

# 拉取镜像
docker pull ubuntu:20.04

# 列出本地镜像
docker images

# 运行容器
docker run -it --name my-ubuntu ubuntu:20.04 bash

# 列出正在运行的容器
docker ps

# 列出所有容器（包括已停止的）
docker ps -a

# 启动/停止容器
docker start my-ubuntu
docker stop my-ubuntu

# 删除容器
docker rm my-ubuntu

# 删除镜像
docker rmi ubuntu:20.04
```

### 创建自定义镜像

Dockerfile 是构建 Docker 镜像的脚本：

```dockerfile
# 基于 Ubuntu 20.04
FROM ubuntu:20.04

# 安装依赖
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip

# 设置工作目录
WORKDIR /app

# 复制应用程序到容器中
COPY . /app

# 安装 Python 依赖
RUN pip3 install -r requirements.txt

# 容器启动时运行的命令
CMD ["python3", "app.py"]
```

构建镜像：
```bash
docker build -t myapp:1.0 .
```

## Docker Compose

Docker Compose 是一个用于定义和运行多容器 Docker 应用程序的工具。通过一个 YAML 文件配置应用的服务，然后用一个命令创建并启动所有服务。

### 安装 Docker Compose

```bash
# Linux
sudo curl -L "https://github.com/docker/compose/releases/download/v2.18.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### docker-compose.yml 示例

```yaml
version: '3'
services:
  web:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - .:/app
    depends_on:
      - db
  db:
    image: postgres:13
    volumes:
      - postgres_data:/var/lib/postgresql/data
    environment:
      - POSTGRES_PASSWORD=password
      - POSTGRES_USER=user
      - POSTGRES_DB=mydb

volumes:
  postgres_data:
```

### 基本命令

```bash
# 启动服务
docker-compose up

# 后台启动服务
docker-compose up -d

# 停止服务
docker-compose down

# 查看服务状态
docker-compose ps
```

## Podman

Podman 是一个无守护进程的容器引擎，旨在作为 Docker 的替代品，特别适用于安全性要求高的环境。

### Podman 的特点

- **无守护进程**：不需要像 Docker 那样运行持久的守护进程
- **无 root 权限**：可以以普通用户身份运行容器
- **与 Docker 兼容**：命令和镜像格式与 Docker 兼容
- **支持 Kubernetes**：生成 Kubernetes YAML 文件

### 安装 Podman

```bash
# Ubuntu
sudo apt-get update
sudo apt-get -y install podman

# CentOS
sudo yum -y install podman
```

### 基本命令

Podman 的命令与 Docker 几乎完全相同：

```bash
# 拉取镜像
podman pull ubuntu:20.04

# 运行容器
podman run -it --name my-ubuntu ubuntu:20.04 bash

# 列出正在运行的容器
podman ps

# 构建镜像
podman build -t myapp:1.0 .
```

## 容器最佳实践

1. **保持镜像小巧**：使用轻量级基础镜像，如 Alpine Linux
2. **使用多阶段构建**：减少最终镜像大小
3. **不在容器内存储数据**：使用卷（volumes）持久化数据
4. **一个容器一个进程**：每个容器只运行一个应用或服务
5. **使用非 root 用户**：避免容器内使用 root 权限
6. **定期更新基础镜像**：保持安全更新
7. **使用 .dockerignore 文件**：排除不必要的文件

## 参考资源

- [Docker 官方文档](https://docs.docker.com/)
- [Podman 官方文档](https://podman.io/docs)
- [Docker Compose 文档](https://docs.docker.com/compose/) 