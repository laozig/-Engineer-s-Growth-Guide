# 16. Jobs & CronJobs：处理批处理任务

我们之前讨论的工作负载（Deployment, StatefulSet, DaemonSet）都是为**长期运行**的服务设计的。但还有一类很重要的任务：**批处理任务**。这些任务会运行一段时间，完成一个特定的工作，然后正常退出。

例如：
- 一次性的数据迁移或初始化。
- 定期的数据库备份或报告生成。
- 运行一个计算密集型的科学模拟。

为了处理这类需求，Kubernetes 提供了 `Job` 和 `CronJob`。

## 16.1 Job：一次性任务

**Job** 控制器会创建一个或多个 Pod，并确保其中指定数量的 Pod **成功终止**。一旦满足了成功完成的 Pod 数量，Job 本身就完成了。

**核心特性**：
- **确保完成**：如果 Job 管理的 Pod 因节点故障或其他原因而失败，Job 会重新创建一个新的 Pod 来替代它，直到任务成功完成。
- **完成状态**：Job 的最终状态是 `Completed` 或 `Failed`。
- **资源清理**：默认情况下，Job 完成后，其创建的 Pod 不会被自动删除，以便你检查日志和结果。你可以手动删除它们，或者使用 TTL 控制器自动清理。

### 如何定义一个 Job (YAML)

下面是一个计算 π 到 2000 位的 Job 示例。

`pi-job.yaml`:
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: pi
spec:
  # Pod 模板
  template:
    spec:
      containers:
      - name: pi
        image: perl
        command: ["perl",  "-Mbignum=bpi", "-wle", "print bpi(2000)"]
      # 重启策略
      restartPolicy: Never # 或 OnFailure
  # 控制 Job 行为的字段
  backoffLimit: 4 # 最多重试4次
```

**关键字段解释**:
- `apiVersion`: 对于 Job，使用 `batch/v1`。
- `spec.template.spec.restartPolicy`: 定义了 Pod 内的容器失败时该**如何**重启。
    - `Never`: 容器失败后，Pod 状态变为 `Failed`，Job 控制器会重新创建一个新 Pod。
    - `OnFailure` (默认): 容器失败后，kubelet 会在原地重启容器。
    - **注意**：Job 的 Pod 不能使用 `Always` 重启策略，因为这与"会终止"的任务性质相悖。
- `spec.backoffLimit`: 指定 Job 在被标记为 `Failed` 之前可以重试的次数。

## 16.2 CronJob：定时任务

**CronJob** 在 Job 的基础上增加了一个 **定时调度** 的功能，类似于 Linux 系统中的 `crontab`。

你可以定义一个调度周期（schedule），CronJob 控制器会在每个周期点上创建一个新的 Job 对象。

### 如何定义一个 CronJob (YAML)

下面是一个每分钟执行一次的 CronJob 示例。

`hello-cronjob.yaml`:
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: hello
spec:
  # 1. 定时调度表达式 (Cron 格式)
  schedule: "*/1 * * * *"
  # 2. Job 模板
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: hello
            image: busybox
            command:
            - /bin/sh
            - -c
            - date; echo "Hello from the Kubernetes cluster"
          restartPolicy: OnFailure
  # 控制 CronJob 行为的字段
  successfulJobsHistoryLimit: 3 # 保留3个成功的 Job 历史记录
  failedJobsHistoryLimit: 1     # 保留1个失败的 Job 历史记录
  concurrencyPolicy: Allow      # 并发策略
```

**关键字段解释**:
- `spec.schedule`: 定义了任务的执行周期，使用标准的 Cron 表达式。
- `spec.jobTemplate`: 这是 Job 的模板，定义了每次调度时要创建的 Job 是什么样子的。其内容与一个标准的 Job `spec` 完全一样。
- `spec.successfulJobsHistoryLimit` 和 `spec.failedJobsHistoryLimit`: 为了防止旧的 Job 无限堆积，可以定义保留多少个已完成或已失败的 Job 记录。
- `spec.concurrencyPolicy`: 定义了当上一个 Job 还没执行完，下一个调度点又到了该怎么办。
    - `Allow` (默认): 允许并发运行多个 Job。
    - `Forbid`: 禁止并发运行。如果上一个 Job 还在运行，则跳过本次调度。
    - `Replace`: 替换旧的。取消当前正在运行的 Job，并用新的 Job 替换它。

## 16.3 暂停 CronJob

有时你可能需要临时暂停一个定时任务，而不想删除整个 CronJob 对象。

```bash
# 暂停 CronJob
kubectl patch cronjob hello --patch '{"spec":{"suspend":true}}'

# 恢复 CronJob
kubectl patch cronjob hello --patch '{"spec":{"suspend":false}}'
```

## 16.4 总结

Job 和 CronJob 为 Kubernetes 提供了强大的批处理和定时任务执行能力。Job 保证了一次性任务的成功完成，而 CronJob 则在其之上实现了类似 `crontab` 的定时调度功能。它们是完成数据处理、备份、定时清理等运维任务的理想工具。

至此，我们已经学习完了 Kubernetes 中所有主要的工作负载类型。在下一部分，我们将进入可观测性和包管理的世界。