# 19. 自动化 (Ansible, Bash)

随着管理的服务器数量从几台增长到数十、数百甚至数千台，手动执行任务变得效率低下、容易出错且不可持续。自动化是现代系统管理的核心，它能确保配置的一致性、提高部署速度并减少人为错误。

本章将介绍两种主要的自动化方法：使用我们已经熟悉的 Bash 脚本，以及更强大、更专业的配置管理工具——Ansible。

## 1. 使用 Bash 脚本进行自动化

通过编写 Bash 脚本，我们可以将一系列命令组合起来，实现简单的自动化。这对于快速执行临时性或小规模的任务非常有效。

**场景**: 在三台 Web 服务器 (`web1`, `web2`, `web3`) 上更新 Nginx 配置文件并重新加载服务。

**前提**: 你已经配置了 SSH 免密登录到这些服务器。

```bash
#!/bin/bash

# 定义服务器列表
SERVERS=("web1" "web2" "web3")

# 定义本地和远程配置文件的路径
LOCAL_CONFIG="nginx.conf.new"
REMOTE_CONFIG="/etc/nginx/nginx.conf"

# 检查新的配置文件是否存在
if [ ! -f "$LOCAL_CONFIG" ]; then
    echo "错误: 新的配置文件 $LOCAL_CONFIG 不存在！"
    exit 1
fi

# 循环遍历所有服务器
for server in "${SERVERS[@]}"; do
    echo "--- 正在处理服务器: $server ---"

    # 1. 复制新的配置文件到服务器
    echo "正在复制配置文件..."
    scp "$LOCAL_CONFIG" "${server}:${REMOTE_CONFIG}"
    if [ $? -ne 0 ]; then
        echo "错误: 无法将配置文件复制到 $server"
        continue # 跳到下一个服务器
    fi

    # 2. 在服务器上测试 Nginx 配置
    echo "正在测试 Nginx 配置..."
    ssh "$server" "sudo nginx -t"
    if [ $? -ne 0 ]; then
        echo "错误: $server 上的 Nginx 配置测试失败！请手动检查。"
        continue
    fi

    # 3. 重新加载 Nginx 服务
    echo "正在重新加载 Nginx..."
    ssh "$server" "sudo systemctl reload nginx"
    if [ $? -ne 0 ]; then
        echo "错误: 无法在 $server 上重新加载 Nginx。"
    else
        echo "$server 处理完成。"
    fi
done

echo "--- 所有服务器处理完毕 ---"
```
这种方法的**优点**是简单直接，不需额外工具。**缺点**是缺乏幂等性（重复运行可能会产生副作用），错误处理和状态管理比较复杂，扩展性差。

## 2. Ansible 入门

Ansible 是一个极其流行的开源自动化工具。它可以用来配置系统、部署软件和编排更高级的任务，如持续部署或零停机滚动更新。

### Ansible 核心概念
- **无代理 (Agentless)**: Ansible 不需要再受管节点上安装任何客户端软件或代理。它通过 SSH（默认）或 PowerShell (Windows) 工作，这极大地简化了部署和管理。
- **控制节点 (Control Node)**: 安装了 Ansible 并从中运行命令和剧本的机器。
- **受管节点 (Managed Node)**: 被 Ansible 管理的服务器。
- **YAML**: Ansible 使用 YAML (YAML Ain't Markup Language) 来编写**剧本 (Playbooks)**，这是一种可读性非常高的数据序列化语言。

### 安装 Ansible (在控制节点上)
```bash
# 以 Ubuntu 为例
sudo apt update
sudo apt install software-properties-common
sudo add-apt-repository --yes --update ppa:ansible/ansible
sudo apt install ansible
```

### 核心组件
- **清单 (Inventory)**: 一个定义了受管节点列表的文件（默认为 `/etc/ansible/hosts`）。你可以将服务器分组。
  **示例 (`hosts.ini`)**:
  ```ini
  [webservers]
  web1.example.com
  web2.example.com
  web3.example.com

  [dbservers]
  db1.example.com
  ```
- **模块 (Module)**: Ansible 的工作单元。每个模块都有一个特定的功能，例如 `apt` 模块用于管理软件包，`service` 模块用于管理服务，`copy` 模块用于复制文件。Ansible 拥有数千个内置模块。
- **任务 (Task)**: 一个将模块和其参数结合起来的动作。
- **剧本 (Playbook)**: 一个或多个**任务**的有序列表，作用于清单中定义的主机组。Playbook 是 Ansible 的配置、部署和编排语言。

### 第一个 Playbook
**场景**: 在 `webservers` 组中的所有服务器上，确保 Nginx 已经安装并正在运行。

**1. 创建清单文件 `hosts.ini`** (内容如上)

**2. 创建 Playbook 文件 `nginx.yml`**:
```yaml
---
- name: 配置 Web 服务器
  hosts: webservers  # 应用于清单中定义的 webservers 组
  become: yes        # 以 root 权限执行任务 (相当于 sudo)

  tasks:
    - name: 1. 确保 nginx 已经安装
      apt:
        name: nginx
        state: present   # 状态为"存在" (如果不存在则安装)
        update_cache: yes

    - name: 2. 确保 nginx 服务正在运行并已启用
      service:
        name: nginx
        state: started   # 状态为"已启动"
        enabled: yes     # 确保开机自启
```

**3. 运行 Playbook**:
```bash
# -i 指定清单文件
ansible-playbook -i hosts.ini nginx.yml
```

### Ansible 的优势
- **幂等性 (Idempotency)**: 这是 Ansible 的核心优势。一个操作的多次执行所产生的影响均与一次执行的影响相同。如果你运行上面的 Playbook 十次，只有在第一次运行时会发生改变（如果 Nginx 未安装），后续九次运行 Ansible 会检查状态，发现 Nginx 已经安装并运行，于是不会做任何改变。这使得自动化任务变得安全和可预测。
- **声明性**: 你只需要在 Playbook 中**声明**你想要的**最终状态**（例如，"Nginx 必须存在并运行"），而不需要关心如何达到这个状态的具体命令（是 `apt-get install` 还是 `dnf install`？服务是否已经启动？）。Ansible 会自己处理这些细节。
- **可扩展性**: 拥有庞大的模块库和社区支持，可以轻松管理从简单到复杂的各种任务。

对于任何需要管理超过少数几台服务器的场景，学习并使用像 Ansible 这样的专业自动化工具都是一项非常有价值的投资。 