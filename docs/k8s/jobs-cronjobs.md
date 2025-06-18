# 16. Jobs & CronJobs：处理批处理任务

到目前为止，我们接触的所有工作负载（`Deployment`, `StatefulSet`, `DaemonSet`）都是为**持续运行的服务**（long-running services）设计的。它们的目标是确保 Pod 一直活着。但还有另一大类任务：**批处理任务 (batch jobs)**，它们只需要运行一次，直到成功完成，然后就应该停止。

例如：
-   执行一次性的数据库迁移。
-   运行一个计算密集的科学模拟。
-   发送一批电子邮件通讯。
-   定期地（如每天凌晨）执行数据备份或清理工作。

对于这些需求，Kubernetes 提供了 `Job` 和 `CronJob`。

## Job：一次性任务

`Job` 对象会创建一个或多个 Pod，并确保其中指定数量的 Pod **成功执行到完成**。与 `Deployment` 不同，`Job` 管理的 Pod 在成功完成后不会被重启。

**`Job` 的核心行为**:
-   `Job` 会持续创建 Pod，直到指定数量 (`.spec.completions`) 的 Pod 成功终止（即容器进程以退出码 `0` 退出）。
-   如果一个 Pod 失败了（例如，因为节点故障或容器错误），`Job` 控制器会根据重试策略启动一个新的 Pod 来替代它。
-   一旦达到了期望的完成数量，`Job` 就被视为完成，并且不会再创建任何新的 Pod。

### Job 的 YAML 定义

一个计算圆周率到 2000 位的 `Job` 示例：
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: pi-calculation
spec:
  template: # 1. Pod 模板
    spec:
      containers:
      - name: pi
        image: perl:5.34
        command: ["perl",  "-Mbignum=bpi", "-wle", "print bpi(2000)"]
      restartPolicy: Never # 2. 重启策略
  backoffLimit: 4 # 3. 重试次数限制
```
1.  `template`: 和其他工作负载一样，定义了要运行的 Pod 的模板。
2.  `restartPolicy`: **对于 `Job`，这个策略指的是 Pod 内的容器**。它只能是 `Never` 或 `OnFailure`。它不能是 `Always`（`Deployment` 的默认值），因为 `Job` 的目标是完成任务，而不是永远运行。
3.  `backoffLimit`: `Job` 级别的重试次数。如果一个 `Job` 的 Pod 失败了 `backoffLimit` 次，`Job` 控制器将不再创建新的 Pod，并将该 `Job` 标记为 `Failed`。

### 并行 Job

`Job` 还可以用于并行处理任务，例如一个任务队列。
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: parallel-job
spec:
  completions: 8 # 1. 总共需要 8 个 Pod 成功完成
  parallelism: 2 # 2. 同时最多运行 2 个 Pod
  template:
    # ...
```
1.  `completions`: 指定了 `Job` 成功的标志是"有 8 个 Pod 成功完成"。
2.  `parallelism`: 指定了在任何时刻，最多可以有多少个 Pod 并行运行。`Job` 控制器会确保运行的 Pod 数量不超过这个值。

---

## CronJob：周期性任务

`CronJob` 在 `Job` 的基础上增加了一个**时间调度**的功能。它就像 Linux 系统中经典的 `crontab` 一样，可以让你在未来的某个时间点或以固定的周期来运行一个 `Job`。

**`CronJob` 的核心行为**:
-   `CronJob` 控制器在其调度时间点 (`.spec.schedule`) 到来时，会根据 `Job` 模板 (`.spec.jobTemplate`) 创建一个 `Job` 对象。
-   `CronJob` 只负责创建 `Job`，之后的所有工作（如创建 Pod、重试等）都由这个新创建的 `Job` 对象自己来管理。

### CronJob 的 YAML 定义

一个每分钟打印一次当前时间的 `CronJob` 示例：
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: hello-cronjob
spec:
  schedule: "*/1 * * * *" # 1. Cron 调度表达式
  jobTemplate: # 2. Job 模板
    spec:
      template:
        spec:
          containers:
          - name: hello
            image: busybox:1.28
            command:
            - /bin/sh
            - -c
            - date; echo "Hello from the Kubernetes cluster"
          restartPolicy: OnFailure
  concurrencyPolicy: Allow # 3. 并发策略
  successfulJobsHistoryLimit: 3 # 4. 历史记录限制
  failedJobsHistoryLimit: 1
```
1.  `schedule`: 定义任务执行周期的 **Cron 表达式**。格式为 `分 时 日 月 周`。`"*/1 * * * *"` 表示"每分钟"。
2.  `jobTemplate`: **必需字段**。它定义了每次调度触发时要创建的 `Job` 的模板。
3.  `concurrencyPolicy`: 定义当上一个 `Job` 还没执行完时，如何处理下一个要被创建的 `Job`。
    -   `Allow` (默认): 允许并发运行多个 `Job`。
    -   `Forbid`: 禁止并发。如果上一个 `Job` 还在运行，就跳过本次调度。
    -   `Replace`: 取消当前正在运行的 `Job`，并用新的 `Job` 替代它。
4.  `successfulJobsHistoryLimit` 和 `failedJobsHistoryLimit`: 为了避免集群中残留大量已完成的 `Job` 和 Pod，这两个字段指定了要保留多少个成功和失败的 `Job` 历史记录。

`Job` 和 `CronJob` 扩展了 Kubernetes 的能力，使其不仅能处理传统的长时间运行服务，还能胜任各种批处理和定时任务，是实现自动化运维和数据处理流程的强大工具。 