# 9. 使用 Compose 编排应用

在上一章中，我们了解了 Docker Compose 的基础知识。现在，让我们通过一个更真实、更复杂的例子，来学习如何使用 Compose 编排一个由多个服务组成的完整应用。

## 场景描述：一个简单的投票应用

我们将构建一个包含两个服务的简单投票应用：
1.  **`vote`**: 一个用 Python Flask 编写的 Web 应用，它提供一个前端界面让用户投票。
2.  **`redis`**: 一个 Redis 数据库，用于持久化地存储投票结果。

`vote` 服务需要能够连接到 `redis` 服务来读取和写入数据。

## 项目结构

```
.
├── docker-compose.yml
└── vote/
    ├── Dockerfile
    ├── requirements.txt
    └── app.py
```
-   `docker-compose.yml`: 我们的核心编排文件。
-   `vote/`: 包含 Python 应用的所有源代码和其 `Dockerfile`。

## 编写应用 (`vote` 服务)

### `vote/app.py`
一个简单的 Flask 应用，连接到 Redis 并处理投票。
```python
from flask import Flask, render_template_string, request, redirect, url_for
import redis
import os

app = Flask(__name__)

# 从环境变量获取 Redis 主机名，如果不存在则默认为 'redis'
# 这是 Compose 服务发现的关键！
redis_host = os.environ.get('REDIS_HOST', 'redis')
# 连接到 Redis
db = redis.Redis(host=redis_host, port=6379, db=0, decode_responses=True)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        option = request.form['option']
        db.hincrby('votes', option, 1)
        return redirect(url_for('index'))
    
    votes = db.hgetall('votes')
    
    # 为了简单起见，我们直接在 Python 代码中写 HTML 模板
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Docker Vote</title>
    </head>
    <body>
        <h1>Vote for your favorite technology:</h1>
        <form method="POST">
            <button name="option" value="Docker">Docker</button>
            <button name="option" value="Kubernetes">Kubernetes</button>
        </form>
        <hr>
        <h2>Results:</h2>
        <ul>
            {% for tech, count in votes.items() %}
            <li>{{ tech }}: {{ count }}</li>
            {% endfor %}
        </ul>
    </body>
    </html>
    """
    return render_template_string(html_template, votes=votes)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

### `vote/requirements.txt`
```
flask
redis
```

### `vote/Dockerfile`
```Dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["flask", "run", "--host=0.0.0.0"]
```
*注意：在 Flask 2.x 之后，`flask run` 是启动开发服务器的标准方式。*

## 编排一切：`docker-compose.yml` 详解

现在，我们来编写核心的 `docker-compose.yml` 文件。

```yaml
version: '3.8'

services:
  # 1. 投票应用服务
  vote:
    # build 指令告诉 Compose 在 'vote' 目录中查找 Dockerfile 并构建镜像
    # 而不是从仓库拉取
    build: ./vote
    # 端口映射
    ports:
      - "5000:5000"
    # 设置环境变量，将 Redis 的主机名传递给应用
    environment:
      - REDIS_HOST=redis
      # Flask 需要这个来找到 app.py
      - FLASK_APP=app
    # 使用 depends_on 来确保 redis 服务先于 vote 服务启动
    # 这只保证了启动顺序，不保证 redis 完全可用
    depends_on:
      - redis
    # 将此服务连接到我们定义的 'app-network' 网络
    networks:
      - app-network

  # 2. Redis 数据库服务
  redis:
    # 直接使用官方镜像
    image: redis:6.2-alpine
    # 将此服务也连接到 'app-network'
    networks:
      - app-network
    # 使用命名卷来持久化 Redis 的数据
    volumes:
      - redis-data:/data

# 顶层 networks 键，用于定义网络
networks:
  app-network:
    # 使用默认的 bridge 驱动
    driver: bridge

# 顶层 volumes 键，用于定义命名卷
volumes:
  redis-data:
    # 使用默认的 local 驱动
    driver: local
```

### 关键配置项详解

-   **`build: ./vote`**: Compose 会进入 `./vote` 目录，使用那里的 `Dockerfile` 构建一个名为 `projectname_vote` 的镜像。
-   **`environment`**: 这是向容器内部传递配置信息的标准方式。我们的 Python 应用会读取 `REDIS_HOST` 来找到数据库。
-   **`depends_on`**: 控制服务的启动顺序。这在服务间有明确依赖关系时非常有用。
-   **`networks`**: 我们明确地创建了一个名为 `app-network` 的网络，并将两个服务都连接上去。这是一个比使用默认网络更好的实践。
-   **`volumes: - redis-data:/data`**: 我们将一个名为 `redis-data` 的**命名卷**挂载到 Redis 容器的 `/data` 目录，这是 Redis 默认存储其数据文件的地方。这确保了即使 `redis` 容器被删除和重建，投票数据也不会丢失。

## 启动与测试

1.  **一键启动**:
    在项目根目录运行：
    ```bash
    docker-compose up -d
    ```
    Compose 会：
    -   构建 `vote` 服务的镜像。
    -   拉取 `redis` 镜像。
    -   创建 `app-network` 网络和 `redis-data` 卷。
    -   按顺序启动 `redis` 和 `vote` 容器。

2.  **测试应用**:
    打开浏览器，访问 `http://localhost:5000`。你应该能看到投票界面。尝试投票，刷新页面，你会看到结果被正确地记录和显示。

3.  **验证持久化**:
    ```bash
    # 停止并移除所有容器
    docker-compose down

    # 再次启动
    docker-compose up -d
    ```
    再次访问 `http://localhost:5000`，你会发现之前的投票数据依然存在！这是因为数据被保存在了 `redis-data` 卷中，而 `docker-compose down` 默认不会删除卷。

4.  **彻底清理**:
    如果你想连同数据卷一起删除，使用 `-v` 标志。
    ```bash
    docker-compose down -v
    ```

## 扩展服务 (Scaling)

假设我们的投票应用变得非常流行，单个 `vote` 容器无法处理所有流量。我们可以轻松地水平扩展它：
```bash
# 将 vote 服务的容器数量扩展到 3 个
docker-compose up -d --scale vote=3
```
Compose 会创建 3 个 `vote` 容器实例，并自动在它们之间进行负载均衡（对于端口映射）。注意，这只适用于无状态的服务，对于像数据库这样的有状态服务，扩展要复杂得多。

通过这个例子，你可以看到 Docker Compose 如何将一个多服务应用的定义、配置、连接和持久化管理得井井有条，极大地提升了开发和测试的效率。 