# 分布式存储系统指南

本指南旨在全面介绍分布式存储系统的核心概念、关键技术、主流解决方案以及在不同场景下的应用实践，帮助读者构建对大规模数据存储的系统性认知。

## 学习路径

### 第一部分：核心概念与理论基础

1.  [x] [分布式系统简介](introduction.md)
2.  [x] [CAP理论与BASE理论](cap-base-theorem.md)
3.  [x] [数据分布与一致性哈希](data-distribution-consistent-hashing.md)
4.  [x] [共识算法 (Paxos, Raft)](consensus-algorithms.md)
5.  [x] [数据一致性模型](consistency-models.md)
6.  [x] [故障检测与容错机制](failure-detection-fault-tolerance.md)

### 第二部分：分布式文件系统

7.  [x] [HDFS (Hadoop Distributed File System)](hdfs.md)
8.  [x] [GlusterFS](glusterfs.md)
9.  [x] [Ceph FS](ceph-fs.md)

### 第三部分：分布式键值/NoSQL存储

10. [x] [Amazon DynamoDB 核心思想](dynamodb.md)
11. [x] [Cassandra](cassandra.md)
12. [x] [TiKV](tikv.md)
13. [x] [etcd](etcd.md)

### 第四部分：对象存储系统

14. [x] [对象存储介绍 (S3 API)](object-storage-intro.md)
15. [x] [MinIO](minio.md)
16. [x] [Ceph RADOS Gateway](ceph-rados-gateway.md)

### 第五部分：新一代分布式数据库

17. [x] [NewSQL 数据库概览](newsql-overview.md)
18. [x] [TiDB](tidb.md)
19. [x] [CockroachDB](cockroachdb.md)

### 第六部分：设计与实践

20. [x] [如何选择合适的存储系统](choosing-storage-system.md)
21. [x] [大规模存储系统的运维挑战](operational-challenges.md)

## 如何贡献

欢迎您通过提交Pull Request来改进本指南。详情请参阅 [CONTRIBUTING.md](../../CONTRIBUTING.md)。 