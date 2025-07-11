# AWS 安全最佳实践

本文详细介绍AWS环境的安全最佳实践，包括身份认证、访问控制、数据保护、网络安全等方面。

## 目录

1. [身份认证与访问控制](#身份认证与访问控制)
2. [数据保护](#数据保护)
3. [网络安全](#网络安全)
4. [监控与审计](#监控与审计)
5. [合规性与治理](#合规性与治理)
6. [事件响应](#事件响应)
7. [安全自动化](#安全自动化)

## 身份认证与访问控制

### IAM 最佳实践

1. **根用户保护**
   ```json
   {
       "RootAccount": {
           "MFAEnabled": true,
           "AccessKeysDisabled": true,
           "LoginAlerts": true,
           "EmergencyUseOnly": true,
           "SecurityQuestions": "Complex",
           "PasswordPolicy": {
               "MinLength": 14,
               "RequireSymbols": true,
               "RequireNumbers": true,
               "RequireUppercase": true,
               "RequireLowercase": true
           }
       }
   }
   ```

2. **最小权限原则**
   ```json
   {
       "Version": "2012-10-17",
       "Statement": [
           {
               "Effect": "Allow",
               "Action": [
                   "s3:GetObject",
                   "s3:PutObject"
               ],
               "Resource": [
                   "arn:aws:s3:::bucket-name/department/${aws:username}/*"
               ],
               "Condition": {
                   "Bool": {
                       "aws:MultiFactorAuthPresent": "true"
                   },
                   "IpAddress": {
                       "aws:SourceIp": ["10.0.0.0/8"]
                   }
               }
           }
       ]
   }
   ```

### 身份联合

```json
{
    "SAML": {
        "Provider": "Azure AD/Okta",
        "Features": {
            "SingleSignOn": true,
            "JustInTimeProvisioning": true,
            "RoleMappings": {
                "Developer": "arn:aws:iam::ACCOUNT_ID:role/Developer",
                "Admin": "arn:aws:iam::ACCOUNT_ID:role/Admin"
            }
        },
        "SessionDuration": "8hours"
    },
    "AssumeRolePolicies": {
        "CrossAccount": {
            "TrustedAccounts": ["123456789012"],
            "RequireMFA": true,
            "ExternalId": "required"
        }
    }
}
```

## 数据保护

### 加密配置

1. **KMS配置**
   ```json
   {
       "KMS": {
           "Keys": {
               "Type": "SYMMETRIC_DEFAULT",
               "KeyRotation": true,
               "DeletionWindow": 30,
               "Aliases": ["alias/app-secrets"],
               "Tags": {
                   "Environment": "Production",
                   "Application": "CustomerData"
               }
           },
           "Policies": {
               "KeyAdministrators": ["arn:aws:iam::ACCOUNT_ID:role/SecurityAdmin"],
               "KeyUsers": ["arn:aws:iam::ACCOUNT_ID:role/ApplicationRole"]
           }
       }
   }
   ```

2. **S3加密**
   ```json
   {
       "S3": {
           "DefaultEncryption": {
               "SSEAlgorithm": "aws:kms",
               "KMSMasterKeyID": "arn:aws:kms:region:account-id:key/key-id"
           },
           "BucketPolicy": {
               "DenyUnencryptedUploads": true,
               "EnforceSSLOnly": true,
               "BlockPublicAccess": {
                   "BlockPublicAcls": true,
                   "IgnorePublicAcls": true,
                   "BlockPublicPolicy": true,
                   "RestrictPublicBuckets": true
               }
           }
       }
   }
   ```

### 数据分类

```json
{
    "DataClassification": {
        "Public": {
            "Description": "可公开访问的数据",
            "Examples": ["产品目录", "公共文档"],
            "SecurityControls": ["基本加密"]
        },
        "Internal": {
            "Description": "内部使用数据",
            "Examples": ["内部文档", "代码"],
            "SecurityControls": ["加密", "访问控制"]
        },
        "Confidential": {
            "Description": "机密数据",
            "Examples": ["客户信息", "财务数据"],
            "SecurityControls": ["强加密", "严格访问控制", "审计日志"]
        }
    }
}
```

## 网络安全

### VPC 安全

1. **网络访问控制**
   ```json
   {
       "VPC": {
           "NetworkACLs": {
               "Inbound": [
                   {
                       "RuleNumber": 100,
                       "Protocol": "tcp",
                       "PortRange": "443",
                       "Allow": true,
                       "Source": "0.0.0.0/0"
                   },
                   {
                       "RuleNumber": 200,
                       "Protocol": "tcp",
                       "PortRange": "22",
                       "Allow": true,
                       "Source": "10.0.0.0/8"
                   }
               ],
               "Outbound": [
                   {
                       "RuleNumber": 100,
                       "Protocol": "-1",
                       "PortRange": "all",
                       "Allow": true,
                       "Destination": "0.0.0.0/0"
                   }
               ]
           }
       }
   }
   ```

2. **安全组配置**
   ```json
   {
       "SecurityGroups": {
           "WebTier": {
               "Inbound": [
                   {
                       "Protocol": "tcp",
                       "Port": 443,
                       "Source": ["ALB-SecurityGroup"]
                   }
               ],
               "Outbound": [
                   {
                       "Protocol": "tcp",
                       "Port": 3306,
                       "Destination": ["DB-SecurityGroup"]
                   }
               ]
           },
           "DBTier": {
               "Inbound": [
                   {
                       "Protocol": "tcp",
                       "Port": 3306,
                       "Source": ["Web-SecurityGroup"]
                   }
               ],
               "Outbound": []
           }
       }
   }
   ```

### WAF配置

```json
{
    "WAF": {
        "Rules": {
            "IPRateLimit": {
                "Type": "RateBasedRule",
                "RateLimit": 2000,
                "Action": "BLOCK"
            },
            "SQLInjection": {
                "Type": "ManagedRule",
                "RuleGroupName": "AWSManagedRulesSQLiRuleSet",
                "Action": "BLOCK"
            },
            "XSS": {
                "Type": "ManagedRule",
                "RuleGroupName": "AWSManagedRulesCommonRuleSet",
                "Action": "BLOCK"
            }
        },
        "IPSets": {
            "Whitelist": ["192.0.2.0/24"],
            "Blacklist": ["198.51.100.0/24"]
        }
    }
}
```

## 监控与审计

### CloudTrail配置

```json
{
    "CloudTrail": {
        "Trails": {
            "OrganizationTrail": {
                "IsMultiRegionTrail": true,
                "IncludeGlobalServices": true,
                "EnableLogFileValidation": true,
                "KMSKeyId": "arn:aws:kms:region:account-id:key/key-id",
                "S3BucketName": "org-audit-logs",
                "CloudWatchLogsRole": "arn:aws:iam::account-id:role/CloudTrailRole"
            }
        },
        "EventSelectors": [
            {
                "ReadWriteType": "WriteOnly",
                "IncludeManagementEvents": true,
                "DataResources": [
                    {
                        "Type": "AWS::S3::Object",
                        "Values": ["arn:aws:s3:::"]
                    }
                ]
            }
        ]
    }
}
```

### GuardDuty配置

```json
{
    "GuardDuty": {
        "Detectors": {
            "Enabled": true,
            "DataSources": {
                "S3Logs": true,
                "CloudTrail": true,
                "VPCFlowLogs": true,
                "DNS": true
            }
        },
        "Findings": {
            "ExportDestination": "S3",
            "UpdateFrequency": "FIFTEEN_MINUTES",
            "NotificationTargets": ["SecurityTeam-SNS-Topic"]
        },
        "ThreatIntelSets": {
            "CustomLists": ["trusted-ips", "known-threats"]
        }
    }
}
```

## 合规性与治理

### AWS Config规则

```json
{
    "Config": {
        "RecordingGroup": {
            "AllSupported": true,
            "IncludeGlobalResources": true
        },
        "Rules": {
            "EncryptedVolumes": {
                "Source": "AWS::Config::Rule",
                "Scope": {
                    "ComplianceResourceTypes": ["AWS::EC2::Volume"]
                }
            },
            "RootAccountMFA": {
                "Source": "AWS::Config::Rule",
                "Scope": {
                    "ComplianceResourceTypes": ["AWS::IAM::User"]
                }
            },
            "S3PublicAccess": {
                "Source": "AWS::Config::Rule",
                "Scope": {
                    "ComplianceResourceTypes": ["AWS::S3::Bucket"]
                }
            }
        }
    }
}
```

### Security Hub集成

```json
{
    "SecurityHub": {
        "Standards": {
            "Enabled": [
                "CIS AWS Foundations Benchmark",
                "AWS Foundational Security Best Practices",
                "PCI DSS"
            ]
        },
        "Integrations": {
            "GuardDuty": true,
            "Inspector": true,
            "IAM Access Analyzer": true,
            "Macie": true
        },
        "CustomActions": {
            "SendToJira": {
                "Trigger": "Critical Findings",
                "Project": "SEC",
                "Priority": "High"
            }
        }
    }
}
```

## 事件响应

### 事件响应计划

```json
{
    "IncidentResponse": {
        "Phases": {
            "Preparation": {
                "Runbooks": ["SecurityIncident.md"],
                "Tools": ["AWS Systems Manager", "AWS Security Hub"],
                "Team": ["SecurityOps", "CloudOps"]
            },
            "Detection": {
                "Services": ["GuardDuty", "CloudWatch", "SecurityHub"],
                "Alerts": {
                    "Critical": {
                        "SNSTopic": "arn:aws:sns:region:account:critical-alerts",
                        "Escalation": "Immediate"
                    }
                }
            },
            "Containment": {
                "Actions": [
                    "IsolateInstance",
                    "BlockIP",
                    "RevokeIAMCredentials"
                ],
                "Automation": "AWS Systems Manager"
            },
            "Recovery": {
                "Procedures": [
                    "RestoreFromBackup",
                    "RotateCredentials",
                    "UpdateSecurityGroups"
                ]
            }
        }
    }
}
```

### 自动响应

```json
{
    "AutoResponse": {
        "GuardDutyFindings": {
            "UnauthorizedAccess": {
                "Actions": [
                    "BlockIP",
                    "NotifySecurityTeam",
                    "CreateJiraTicket"
                ],
                "Priority": "High"
            },
            "CryptoCurrency": {
                "Actions": [
                    "StopInstance",
                    "IsolateSecurityGroup",
                    "NotifySecurityTeam"
                ],
                "Priority": "Critical"
            }
        }
    }
}
```

## 安全自动化

### 安全基线自动化

```json
{
    "SecurityBaseline": {
        "IAM": {
            "PasswordPolicy": {
                "MinimumLength": 14,
                "RequireSymbols": true,
                "RequireNumbers": true,
                "RequireUppercase": true,
                "RequireLowercase": true,
                "AllowPasswordReuse": false,
                "MaxPasswordAge": 90
            },
            "AccessKeyRotation": {
                "MaxAge": 90,
                "NotificationDays": [7, 14, 30]
            }
        },
        "Networking": {
            "VPCFlowLogs": {
                "Enabled": true,
                "RetentionDays": 90,
                "TrafficType": "ALL"
            },
            "DefaultSecurityGroups": {
                "RemoveAllRules": true,
                "PreventModification": true
            }
        }
    }
}
```

### 合规性检查自动化

```json
{
    "ComplianceAutomation": {
        "DailyChecks": {
            "Schedule": "cron(0 0 * * ? *)",
            "Checks": [
                "UnencryptedVolumes",
                "PublicS3Buckets",
                "WeakSecurityGroups",
                "IAMUserCredentials"
            ],
            "Reporting": {
                "Format": "HTML",
                "Recipients": ["security@company.com"],
                "Dashboard": "SecurityCompliance"
            }
        },
        "Remediation": {
            "AutoRemediate": {
                "UnencryptedSnapshots": true,
                "PublicS3ACLs": true,
                "InactiveIAMUsers": true
            },
            "ApprovalRequired": {
                "SecurityGroupChanges": true,
                "IAMPolicyChanges": true,
                "KMSKeyDeletion": true
            }
        }
    }
}
```

## 最佳实践建议

### 安全架构原则

1. **纵深防御**
   - 多层安全控制
   - 故障隔离
   - 最小权限原则

2. **自动化优先**
   - 自动化安全检查
   - 自动化响应措施
   - 自动化合规性检查

### 安全运营

1. **持续监控**
   - 实时威胁检测
   - 异常行为分析
   - 合规性监控

2. **定期评估**
   - 漏洞扫描
   - 渗透测试
   - 安全配置审查

## 总结

AWS环境的安全保护需要多层次、全方位的防护措施。通过实施这些最佳实践，可以显著提高AWS环境的安全性。关键是要持续更新和改进安全措施，保持警惕，并及时响应新的安全威胁。定期的安全评估和更新是维护强大安全态势的基础。
