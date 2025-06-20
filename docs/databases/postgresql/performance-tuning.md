# 18. 性能监控与调优

PostgreSQL 是一个开箱即用性能就非常出色的数据库，但对于高负载的生产环境，进行持续的性能监控和针对性的调优是必不可少的。本章将介绍一些核心的监控指标和调优手段。

## 性能调优的基本思路

性能调优不是一次性的任务，而是一个持续的循环：
1.  **设定基线**: 了解系统在正常负载下的性能表现。
2.  **监控与识别瓶颈**: 通过各种工具持续监控系统，找出性能瓶颈所在（是CPU、内存、I/O还是特定查询？）。
3.  **分析与假设**: 分析瓶颈产生的原因，提出优化假设。
4.  **实施与测试**: 在测试环境中实施优化方案，并验证其效果。
5.  **部署与评估**: 部署到生产环境，并评估其对整体性能的影响。

## 关键配置参数 (`postgresql.conf`)

`postgresql.conf` 文件包含了数百个配置参数，但对性能影响最大的通常是以下几个：

- **`shared_buffers`**:
  - **作用**: 设置PostgreSQL用于缓存数据页的共享内存大小。这是**最重要的性能参数**。
  - **建议值**: 通常设置为系统总内存的 **25%**。对于专用数据库服务器，可以更高，但不建议超过40%，因为PostgreSQL也需要内存用于其他目的，并且依赖操作系统的文件系统缓存。
  - **示例**: `shared_buffers = 4GB`

- **`work_mem`**:
  - **作用**: 设置单个查询操作（如排序、哈希连接、位图扫描）在转而使用临时磁盘文件之前可以使用的内存量。
  - **建议值**: 这个值需要权衡。设置太低会导致大量查询因内存不足而使用慢速的磁盘排序；设置太高则可能导致内存耗尽，因为`max_connections`个连接可能同时请求`work_mem`大小的内存。可以先从一个较小的值开始（如`16MB`），然后通过`EXPLAIN ANALYZE`观察日志中关于"work_mem"的提示来逐步调高。

- **`maintenance_work_mem`**:
  - **作用**: 设置维护性操作（如`VACUUM`, `CREATE INDEX`, `REINDEX`, `ALTER TABLE ADD FOREIGN KEY`）可以使用的内存量。
  - **建议值**: 可以比`work_mem`设置得更高（如`256MB`或`1GB`），因为这些操作通常不会高并发地执行。较大的值可以显著加快索引创建和清理的速度。

- **`effective_cache_size`**:
  - **作用**: 这不是一个内存分配参数，而是**告知查询优化器**操作系统和PostgreSQL自身总共可用于磁盘缓存的内存大约有多少。
  - **建议值**: 通常设置为系统总内存的 **50% 到 75%**。一个更精确的值有助于优化器生成更准确的执行计划（例如，它会更倾向于选择能够利用缓存的索引扫描）。

- **`wal_buffers`**:
  - **作用**: 设置用于暂存WAL（预写式日志）记录的共享内存大小，在它们被写入磁盘之前。
  - **建议值**: 默认值通常足够，但对于写密集型系统，可以适当增加到`16MB`左右。

**重要提示**: 修改`postgresql.conf`后，必须**重载(reload)或重启(restart)** PostgreSQL服务才能使更改生效。对于`shared_buffers`等参数，需要重启服务。

## 性能监控工具

### 统计视图

PostgreSQL内部记录了大量的统计信息，可以通过系统视图进行查询。

- **`pg_stat_activity`**:
  - **作用**: 显示当前所有连接的详细信息，包括连接状态、正在执行的查询、等待事件等。这是**排查实时问题的首选工具**。
  - **查询示例**: 查找运行时间超过5分钟的慢查询。
    ```sql
    SELECT pid, age(clock_timestamp(), query_start), usename, query
    FROM pg_stat_activity
    WHERE state != 'idle' AND query_start < now() - interval '5 minutes';
    ```

- **`pg_stat_user_tables`**:
  - **作用**: 显示关于用户表的活动统计，如顺序扫描次数(`seq_scan`)、索引扫描次数(`idx_scan`)、插入/更新/删除的行数、"死元组"数量(`n_dead_tup`)等。
  - **查询示例**: 查找顺序扫描次数远高于索引扫描次数的表（可能是缺少索引的信号）。
    ```sql
    SELECT relname, seq_scan, idx_scan
    FROM pg_stat_user_tables
    WHERE seq_scan > idx_scan AND seq_scan > 1000
    ORDER BY seq_scan DESC;
    ```

- **`pg_statio_user_tables`**:
  - **作用**: 显示I/O相关的统计信息，如从磁盘读取的块数(`heap_blks_read`)和在缓冲区中命中的块数(`heap_blks_hit`)。
  - **查询示例**: 计算表的缓存命中率。
    ```sql
    SELECT
        relname,
        heap_blks_hit * 100.0 / (heap_blks_hit + heap_blks_read) as cache_hit_ratio
    FROM
        pg_statio_user_tables
    WHERE (heap_blks_hit + heap_blks_read) > 0
    ORDER BY cache_hit_ratio;
    ```

### `pg_stat_statements` 扩展

这是一个**必须安装**的扩展。它会跟踪服务器上执行的所有SQL语句的统计信息，包括执行次数、总耗时、平均耗时等。这是定位消耗资源最多的查询的利器。

1.  **安装**: `CREATE EXTENSION pg_stat_statements;`
2.  **配置**: 在`postgresql.conf`中，将`pg_stat_statements`添加到`shared_preload_libraries`并重启服务。
3.  **查询**:
    ```sql
    SELECT
        query,
        calls,
        total_exec_time,
        rows,
        100.0 * shared_blks_hit / nullif(shared_blks_hit + shared_blks_read, 0) AS hit_percent
    FROM
        pg_stat_statements
    ORDER BY
        total_exec_time DESC
    LIMIT 10;
    ```
    这个查询会列出总执行时间最长的前10个查询。

## 常见的性能问题与对策

- **问题：慢查询**
  - **对策**: 使用`EXPLAIN ANALYZE`分析查询计划。最常见的原因是缺少合适的索引，导致全表扫描。参考[索引与查询优化](indexing-query-optimization.md)章节。

- **问题：表膨胀 (Bloat)**
  - **原因**: PostgreSQL的MVCC机制会导致表中积累大量的"死元组"（已删除或过时的行版本）。如果`VACUUM`进程无法及时清理它们，表和索引的物理体积会远大于其实际数据大小，导致查询性能下降。
  - **对策**:
    - 确保`autovacuum`是开启并有效运行的。
    - 监控`pg_stat_user_tables`中的`n_dead_tup`。
    - 对于严重膨胀的表，可能需要手动执行`VACUUM FULL`（会锁表）或使用`pg_repack`等工具进行在线重组。

- **问题：连接风暴**
  - **原因**: 大量短暂的数据库连接会消耗大量资源，因为每个连接都需要fork一个新的进程。
  - **对策**: 使用连接池（Connection Pooler），如`PgBouncer`或`pgpool-II`。连接池在应用程序和数据库之间维护一个连接池，应用程序可以快速地从中获取和释放连接，避免了直接与数据库建立连接的开销。

性能调优是一个涉及系统配置、SQL优化、索引设计和架构选择的综合性工程。通过使用PostgreSQL提供的丰富工具进行监控和分析，您可以系统地提升数据库的性能和稳定性。 