# 1. Kubernetes 简介

欢迎来到 Kubernetes 的世界！本章将为你揭开 Kubernetes 的神秘面纱，介绍它的核心概念、解决了什么问题以及其基本架构。

## 1.1 什么是 Kubernetes？

Kubernetes（常简称为 K8s）是一个开源的**容器编排平台**，由 Google 设计并捐赠给云原生计算基金会（CNCF）。它的目标是自动化容器化应用的部署、扩展和管理。

想象一下，你有一个复杂的应用程序，由几十个甚至几百个容器组成。手动管理这些容器的生命周期、网络、存储和扩缩容将是一场噩梦。Kubernetes 就是为了解决这个问题而生的。

## 1.2 Kubernetes 解决了什么问题？

在没有 Kubernetes 的世界里，开发者和运维团队会面临以下挑战：

- **服务发现与负载均衡**：一个容器如何找到并与另一个容器通信？如何将流量均匀分配给多个实例？
- **自动化部署与回滚**：如何安全地发布新版本？如果新版本有问题，如何快速回滚？
- **自动扩缩容**：如何根据流量自动增加或减少容器数量？
- **自我修复**：如何自动替换掉死掉或无响应的容器？
- **配置与密钥管理**：如何管理不同环境的配置信息和敏感数据？
- **存储编排**：如何为有状态应用提供持久化存储？

Kubernetes 通过一套强大的抽象和组件，优雅地解决了以上所有问题。

## 1.3 核心架构与组件

Kubernetes 采用**主从（Master-Node）架构**。集群由一个或多个 Master 节点和多个 Node（也称为 Worker）节点组成。

<div align="center">
  <img src="https://i.imgur.com/l3bA636.png" alt="Kubernetes Architecture" width="700">
</div>

### Master 节点组件 (控制平面)

Master 节点是集群的大脑，负责管理整个集群的状态。主要组件包括：

- **API Server (`kube-apiserver`)**: 集群的统一入口，所有组件都通过它进行通信和交互。它提供 RESTful API，是执行所有增删改查操作的唯一途径。
- **Controller Manager (`kube-controller-manager`)**: 负责维护集群的状态，例如处理节点故障、保持副本数量、创建端点等。它由多个控制器组成，如节点控制器、副本控制器等。
- **Scheduler (`kube-scheduler`)**: 负责将新创建的 Pod 分配到合适的 Node 节点上运行。它会根据资源需求、亲和性、污点等多种策略进行决策。
- **etcd**: 一个高可用的键值存储系统，用于持久化存储整个集群的状态和配置信息。

### Node 节点组件 (工作节点)

Node 节点是真正运行应用程序容器的地方。主要组件包括：

- **Kubelet**: Master 在每个 Node 上的代理。它负责与 Master 通信，管理本机上的 Pod 和容器的生命周期，确保容器按照预期运行。
- **Kube-proxy (`kube-proxy`)**: 负责实现 Kubernetes Service 的网络通信和负载均衡。它维护节点上的网络规则，允许内外流量访问 Pod。
- **Container Runtime**: 负责运行容器的软件，例如 Docker、containerd 或 CRI-O。Kubelet 通过它来启动和停止容器。

## 1.4 总结

本章我们了解了 Kubernetes 的基本概念，它是一个强大的容器编排平台，旨在自动化应用的部署、扩展和管理。我们还探讨了它的核心架构，包括 Master 节点和 Node 节点的关键组件。

在接下来的章节中，我们将动手实践，搭建一个本地的 Kubernetes 环境，并学习如何使用 `kubectl` 与集群进行交互。 