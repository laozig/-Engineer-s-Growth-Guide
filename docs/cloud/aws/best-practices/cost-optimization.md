# AWS 成本优化策略

本文详细介绍AWS环境的成本优化策略，包括资源规划、成本监控、优化方案和自动化管理等方面。

## 目录

1. [成本可视化与监控](#成本可视化与监控)
2. [计算资源优化](#计算资源优化)
3. [存储成本优化](#存储成本优化)
4. [数据传输优化](#数据传输优化)
5. [数据库服务优化](#数据库服务优化)
6. [自动化成本管理](#自动化成本管理)
7. [预算与成本分配](#预算与成本分配)

## 成本可视化与监控

### Cost Explorer配置

```json
{
    "CostExplorer": {
        "Reports": {
            "Daily": {
                "Granularity": "DAILY",
                "Metrics": ["UnblendedCost", "UsageQuantity"],
                "GroupBy": [
                    {"Type": "DIMENSION", "Key": "SERVICE"},
                    {"Type": "TAG", "Key": "Environment"}
                ]
            },
            "Monthly": {
                "Granularity": "MONTHLY",
                "Metrics": ["AmortizedCost", "NetUnblendedCost"],
                "GroupBy": [
                    {"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"},
                    {"Type": "TAG", "Key": "CostCenter"}
                ]
            }
        },
        "Alerts": {
            "SpendingTrends": {
                "Threshold": 20,
                "ComparisonOperator": "GREATER_THAN",
                "NotificationChannel": "SNS"
            }
        }
    }
}
```

### 成本分配标签

```json
{
    "TaggingStrategy": {
        "RequiredTags": {
            "CostCenter": {
                "Description": "业务成本中心",
                "Format": "CC-[0-9]{4}",
                "Required": true
            },
            "Environment": {
                "Description": "部署环境",
                "AllowedValues": ["prod", "staging", "dev"],
                "Required": true
            },
            "Project": {
                "Description": "项目名称",
                "Format": "PROJ-[A-Z]{2,5}",
                "Required": true
            }
        },
        "AutomatedTagging": {
            "CreatedBy": "Lambda",
            "CreationDate": "CloudTrail",
            "BackupRetention": "DLM"
        }
    }
}
```

## 计算资源优化

### EC2实例策略

1. **预留实例规划**
   ```json
   {
       "ReservedInstances": {
           "Strategy": {
               "StandardRI": {
                   "Term": "1year",
                   "PaymentOption": "partial_upfront",
                   "InstanceTypes": {
                       "Production": ["m5.xlarge", "c5.2xlarge"],
                       "Coverage": 80
                   }
               },
               "ConvertibleRI": {
                   "Term": "3year",
                   "PaymentOption": "all_upfront",
                   "FlexibilityNeeded": true
               }
           },
           "AutoScaling": {
               "BaseCapacity": "Reserved",
               "PeakCapacity": "Spot"
           }
       }
   }
   ```

2. **Spot实例使用**
   ```json
   {
       "SpotStrategy": {
           "UseCase": {
               "BatchProcessing": {
                   "MaxPrice": "on-demand-price",
                   "InstanceTypes": ["c5.xlarge", "c5a.xlarge"],
                   "InterruptionHandling": true
               },
               "WebServices": {
                   "MaxPrice": "on-demand-price * 0.8",
                   "InstanceTypes": ["t3.medium", "t3a.medium"],
                   "MixedInstancesPolicy": true
               }
           },
           "FallbackStrategy": {
               "OnDemandBackup": true,
               "AutoRecovery": true
           }
       }
   }
   ```

### 容器优化

```json
{
    "ContainerOptimization": {
        "ECS": {
            "CapacityProviders": {
                "FARGATE_SPOT": {
                    "BaseWeight": 3,
                    "UseCase": "non-critical-workloads"
                },
                "FARGATE": {
                    "BaseWeight": 1,
                    "UseCase": "critical-workloads"
                }
            }
        },
        "EKS": {
            "NodeGroups": {
                "OnDemand": {
                    "MinSize": 2,
                    "MaxSize": 10,
                    "InstanceTypes": ["t3.large"]
                },
                "Spot": {
                    "MinSize": 1,
                    "MaxSize": 20,
                    "InstanceTypes": ["t3.large", "t3a.large"]
                }
            }
        }
    }
}
```

## 存储成本优化

### S3优化策略

```json
{
    "S3Optimization": {
        "LifecycleRules": {
            "StandardToIA": {
                "DaysAfterCreation": 30,
                "MinObjectSize": "128KB"
            },
            "IAToGlacier": {
                "DaysAfterIA": 60,
                "ObjectPatterns": ["backup/*", "archive/*"]
            },
            "ExpireOldVersions": {
                "DaysAfterVersioning": 90,
                "CleanupIncomplete": true
            }
        },
        "IntelligentTiering": {
            "Enabled": true,
            "MinObjectSize": "50MB",
            "ExcludePatterns": ["temp/*"]
        },
        "Analytics": {
            "StorageClassAnalysis": true,
            "ReportFrequency": "Daily"
        }
    }
}
```

### EBS优化

```json
{
    "EBSOptimization": {
        "VolumeTypes": {
            "gp3": {
                "BaselineIOPS": 3000,
                "BaselineThroughput": "125MB/s",
                "UseCase": "general-purpose"
            },
            "st1": {
                "UseCase": "big-data",
                "MinVolumeSize": "500GB"
            }
        },
        "Snapshots": {
            "Lifecycle": {
                "RetentionSchedule": {
                    "Daily": 7,
                    "Weekly": 4,
                    "Monthly": 12
                },
                "CrossRegion": {
                    "Enabled": true,
                    "Regions": ["ap-northeast-1"]
                }
            }
        }
    }
}
```

## 数据传输优化

### CDN优化

```json
{
    "CloudFrontOptimization": {
        "CachingStrategy": {
            "DefaultTTL": 86400,
            "MinTTL": 0,
            "MaxTTL": 31536000,
            "CompressObjects": true
        },
        "OriginStrategy": {
            "S3Origin": {
                "UseOAI": true,
                "RegionalEndpoint": true
            },
            "CustomOrigin": {
                "KeepAliveTimeout": 5,
                "ConnectionAttempts": 3
            }
        },
        "EdgeLocations": {
            "PriceClass": "PriceClass_200",
            "RegionalRestrictions": {
                "Enabled": true,
                "Whitelist": ["CN", "HK", "TW"]
            }
        }
    }
}
```

### VPC传输优化

```json
{
    "NetworkOptimization": {
        "VPCEndpoints": {
            "Gateway": ["s3", "dynamodb"],
            "Interface": ["ecr.api", "ecr.dkr"],
            "CostBenefit": "savings-over-nat-gateway"
        },
        "DirectConnect": {
            "Capacity": "1Gbps",
            "DataTransferOut": {
                "ToInternet": "via-internet-gateway",
                "ToOtherRegions": "via-direct-connect"
            }
        }
    }
}
```

## 数据库服务优化

### RDS优化

```json
{
    "RDSOptimization": {
        "InstanceStrategy": {
            "Reserved": {
                "Coverage": 80,
                "Term": "1year",
                "PaymentOption": "partial_upfront"
            },
            "Scaling": {
                "AutoScaling": true,
                "MinCapacity": "db.t3.medium",
                "MaxCapacity": "db.r5.xlarge"
            }
        },
        "StorageOptimization": {
            "AutoScaling": {
                "Enabled": true,
                "MaxStorage": "1TB",
                "ScaleIncrement": "10%"
            },
            "PerformanceInsights": {
                "RetentionPeriod": 7,
                "EnableLongTerm": false
            }
        }
    }
}
```

### DynamoDB优化

```json
{
    "DynamoDBOptimization": {
        "CapacityMode": {
            "OnDemand": {
                "UseCase": "unpredictable-workloads",
                "PeakTraffic": true
            },
            "ProvisionedCapacity": {
                "UseCase": "predictable-workloads",
                "AutoScaling": {
                    "TargetUtilization": 70,
                    "MinCapacity": 5,
                    "MaxCapacity": 100
                }
            }
        },
        "TableOptimization": {
            "TTL": {
                "Enabled": true,
                "AttributeName": "expiryDate"
            },
            "BackupStrategy": {
                "PointInTimeRecovery": false,
                "OnDemandBackup": true
            }
        }
    }
}
```

## 自动化成本管理

### 资源调度

```json
{
    "ResourceScheduling": {
        "EC2Scheduling": {
            "NonProduction": {
                "StartTime": "08:00",
                "StopTime": "18:00",
                "TimeZone": "Asia/Shanghai",
                "WorkingDays": ["Monday-Friday"],
                "ExcludeHolidays": true
            }
        },
        "RDSScheduling": {
            "Development": {
                "StartTime": "09:00",
                "StopTime": "19:00",
                "TimeZone": "Asia/Shanghai",
                "ExcludeInstances": ["primary-db"]
            }
        }
    }
}
```

### 自动清理

```json
{
    "ResourceCleaning": {
        "UnusedResources": {
            "EBS": {
                "UnattachedVolumes": {
                    "RetentionDays": 7,
                    "ExcludeTags": ["keep=true"]
                }
            },
            "EIP": {
                "UnassociatedAddresses": {
                    "RetentionDays": 3,
                    "NotifyOwner": true
                }
            },
            "Snapshots": {
                "Outdated": {
                    "RetentionDays": 30,
                    "ExcludePatterns": ["backup-*"]
                }
            }
        },
        "AutomationSchedule": "cron(0 0 * * ? *)"
    }
}
```

## 预算与成本分配

### 预算配置

```json
{
    "Budgets": {
        "Monthly": {
            "Overall": {
                "Amount": 10000,
                "Unit": "USD",
                "TimeUnit": "MONTHLY",
                "Alerts": [
                    {
                        "Threshold": 80,
                        "Type": "ACTUAL",
                        "Subscribers": ["finance@company.com"]
                    },
                    {
                        "Threshold": 100,
                        "Type": "FORECASTED",
                        "Subscribers": ["management@company.com"]
                    }
                ]
            },
            "PerService": {
                "EC2": {
                    "Amount": 5000,
                    "Alerts": [{"Threshold": 90}]
                },
                "RDS": {
                    "Amount": 2000,
                    "Alerts": [{"Threshold": 85}]
                }
            }
        }
    }
}
```

### 成本分配策略

```json
{
    "CostAllocation": {
        "TagPolicies": {
            "Mandatory": ["CostCenter", "Project", "Environment"],
            "Optional": ["Owner", "Application"],
            "Enforcement": {
                "PreventLaunch": true,
                "NotifyNonCompliance": true
            }
        },
        "Chargeback": {
            "Direct": {
                "ComputeResources": "per-instance-hour",
                "StorageResources": "per-gb-month",
                "NetworkResources": "per-gb-transfer"
            },
            "Shared": {
                "ManagementOverhead": "by-resource-count",
                "SecurityServices": "by-user-count"
            }
        }
    }
}
```

## 最佳实践建议

### 成本优化原则

1. **持续监控与分析**
   - 定期审查使用情况
   - 识别成本异常
   - 优化资源配置

2. **自动化管理**
   - 资源生命周期管理
   - 成本异常响应
   - 定期报告生成

### 优化策略实施

1. **分阶段实施**
   - 从高成本区域开始
   - 逐步扩展优化范围
   - 持续评估效果

2. **团队协作**
   - 成本意识培训
   - 责任分配明确
   - 定期优化会议

## 总结

AWS成本优化是一个持续的过程，需要从多个维度进行规划和实施。通过合理的资源规划、有效的监控机制、自动化的管理工具，以及清晰的成本分配策略，可以实现AWS支出的有效控制和优化。关键是要建立长期的成本优化文化，并持续改进优化策略。 