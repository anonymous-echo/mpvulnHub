#  MetaHub：一款针对漏洞管理的自动化安全上下文信息扩充与影响评估工具   
Alpha_h4ck  FreeBuf   2024-04-27 09:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
MetaHub是一款针对漏洞管理的自动化安全上下文信息扩充与影响评估工具，该工具支持与AWS Security Hub或任何与ASFF兼容的安全扫描仪一起使用。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39YKrISbxRdA8XI8oOqjpJNwOlBg20urpLc42iapsYUyYFP2rwCQV9sJqj9tf4p0dibobFmLuWoefVA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
在该工具的帮助下，广大研究人员可以完善漏洞管理工作流，并根据当前安全上下文来扩充安全分析信息，从而更好地评估安全风险所带来的影响。MetaHub提供了一系列技术方法来枚举、管理和输出我们的安全发现，以更好地对事件进行调查，并于其他工具集成。该工具支持以单独的CLI工具使用，或在自动化工作流中使用。该工具还支持不同的输出，其中包括JSON、HTML、XLSX和CSV。  
  
  
**工具架构**  
  
  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39YKrISbxRdA8XI8oOqjpJNanRZhQq2CGcpz7AySmfI9U2CsqtN9EAorsTvdEVNic5a9OTg0JKhThw/640?wx_fmt=jpeg&from=appmsg "")  
##   
  
**影响评估**  
  
  
##   
  
MetaHub的影响模块主要针对下列7个关键属性，工具会结合下列7个方面对给定资源进行评估，分数为0-100分，100分为最高的影响评分：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39YKrISbxRdA8XI8oOqjpJNrlVibWxUBr86IqMeEh7iamCYPuz6aSTwcfh1927xroAAkBoKKTDURI2g/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**工具依赖**  
  
##   
  
Python 3  
  
alive_progress  
  
aws-arn==0.0.13  
  
boto3  
  
jinja2  
  
pyyaml  
  
rich  
  
xlsxwriter  
##   
  
**工具下载**  
  
  
##   
### 源码安装  
  
  
由于该工具基于Python 3开发，因此我们首先需要在本地设备上安装并配置好最新版本的Python 3环境。  
  
  
接下来，广大研究人员可以直接使用下列命令将该项目源码克隆至本地：  
```
git clone https://github.com/gabrielsoltz/metahub.git
```  
  
然后切换到项目目录中，使用pip工具和项目提供的requirements.txt文件安装该工具所需的其他依赖组件：  
```
cd metahub

pip3 install -r requirements.txt
```  
### 虚拟环境使用  
```
git clone git@github.com:gabrielsoltz/metahub.git

cd metahub

python3 -m venv venv/metahub

source venv/metahub/bin/activate

pip3 install -r requirements.txt

./metahub -h

deactivate
```  
  
**工具使用**  
  
  
##   
  
从AWS Security Hub读取发现的安全数据，使用默认过滤器，并执行默认上下文选项：  
```
./metahub
```  
  
从Prowler读取发现的安全数据，然后作为输入文件传递给MetaHub，并执行默认上下文选项：  
```
python3 prowler.py aws -M json-asff -q

./metahub --inputs file-asff --input-asff /path/to/prowler-findings.json.asff
```  
  
从AWS Security Hub读取发现的指定安全数据（通过ID过滤），并执行默认上下文选项：  
```
./metahub --sh-filters Id=arn:aws:securityhub:us-east-1:123456789012:security-control/CloudFront.1/finding/8bd4d049-dcbc-445b-a5d1-595d8274b4c1
```  
  
从AWS Security Hub读取影响某个活动资源的所有安全发现，并执行默认上下文选项：  
```
./metahub --sh-filters RecordState=ACTIVE ResourceId=arn:aws:ec2:eu-west-1:123456789012:subnet/subnet-0b7d243ff90ebc03e
```  
  
  
从一个活动AWS账号读取所有的安全发现，使用Environment、stg、config和tags选项执行上下文选型：  
```
./metahub --sh-filters RecordState=ACTIVE AwsAccountId=123456789012 --mh-filters-tags Environment=stg --context config tags
```  
### S3 Bucket配置密钥样例  
```
"config": {

"resource_policy": {

"Version": "2012-10-17",

"Statement": [

      {

"Sid": "Test",

"Effect": "Allow",

"Principal": {

"Service": "config.amazonaws.com"

        },

"Action": "s3:GetBucketAcl",

"Resource": "arn:aws:s3:::metahub-bucket",

"Condition": {

"StringEquals": {

"AWS:SourceAccount": "123456789012"

          }

        }

      },

    ]

  },

"website_enabled": false,

"bucket_acl": [

    {

"Grantee": {

"DisplayName": "gabriel.soltz",

"ID": "1234564bd76c6c64080717b68eafaa588b41706daaf22d3d0705b398bd7cbd57",

"Type": "CanonicalUser"

      },

"Permission": "FULL_CONTROL"

    }

  ],

"cannonical_user_id": "1234564bd76c6c64080717b68eafaa588b41706daaf22d3d0705b398bd7cbd57",

"public_access_block_enabled": {

"BlockPublicAcls": true,

"IgnorePublicAcls": true,

"BlockPublicPolicy": true,

"RestrictPublicBuckets": true

  },

"account_public_access_block_enabled": false,

"public": false,

"bucket_encryption": [

    {

"ApplyServerSideEncryptionByDefault": {

"SSEAlgorithm": "AES256"

      },

"BucketKeyEnabled": false

    }

  ]

},
```  
###   
### EC2实例关联密钥样例  
```
"associations": {

"security_groups": {

"arn:aws:ec2:eu-west-1:123456789012:security-group/sg-020cc749a58678e05": {

"associations": {

"vpcs": {

"arn:aws:ec2:eu-west-1:123456789012:vpc/vpc-03cc56a1c2afb5760": {

"associations": {

"subnets": {

"arn:aws:ec2:eu-west-1:123456789012:subnet/subnet-03d86f1ccd7729d85": {},

"arn:aws:ec2:eu-west-1:123456789012:subnet/subnet-0ccfb8dea658f49ec": {},

"arn:aws:ec2:eu-west-1:123456789012:subnet/subnet-05e85a7b0ec9e404c": {},

"arn:aws:ec2:eu-west-1:123456789012:subnet/subnet-0e177ea95bcc76256": {}

              }

            },

"config": {

"cidr": "172.10.0.0/16",

"default": false,

"public": null

            }

          }

        },

"network_interfaces": {

"arn:aws:ec2:eu-west-1:123456789012:network-interface/eni-041a6e5bb59c336ee": {}

        },

"instances": {

"arn:aws:ec2:eu-west-1:123456789012:instance/i-018daeedcf06398c0": {}

        }

      },

"config": {

"public_ips": [

"100.100.100.100"

        ],

"managed_services": [],

"its_referenced_by_a_security_group": false,

"security_group_rules": [

          {

"SecurityGroupRuleId": "sgr-08cdc9fdac8fd1a5b",

"GroupId": "sg-020cc749a58678e05",

"GroupOwnerId": "123456789012",

"IsEgress": true,

"IpProtocol": "-1",

"FromPort": -1,

"ToPort": -1,

"CidrIpv4": "0.0.0.0/0",

"Tags": []

          },

          {

"SecurityGroupRuleId": "sgr-0e6cd39169dc137ab",

"GroupId": "sg-020cc749a58678e05",

"GroupOwnerId": "123456789012",

"IsEgress": false,

"IpProtocol": "tcp",

"FromPort": 22,

"ToPort": 22,

"CidrIpv4": "0.0.0.0/0",

"Tags": []

          }

        ],

"public": true,

"default": false,

"attached": true,

"resource_policy": null

      }

    },

  },

"iam_roles": {

"arn:aws:iam::123456789012:role/eu-west-1-stg-backend-iam-role": {

"associations": {

"iam_policies": {

"arn:aws:iam::123456789012:policy/eu-west-1-stg-backend-iam-policy-cw": {

"associations": {

"iam_roles": {

"arn:aws:iam::123456789012:role/eu-west-1-stg-backend-iam-role": {}

              },

"iam_groups": {},

"iam_users": {}

            },

"config": {

"name": "eu-west-1-stg-backend-iam-policy-cw",

"description": false,

"customer_managed": true,

"attached": true,

"public": null,

"resource_policy": {

"Version": "2012-10-17",

"Statement": [

                  {

"Effect": "Allow",

"Action": [

"logs:CreateLogGroup",

"logs:CreateLogStream",

"logs:PutLogEvents",

"logs:DescribeLogStreams"

                    ],

"Resource": [

"arn:aws:logs:*:*:*"

                    ]

                  }

                ]

              }

            }

          },

        }

      },

"config": {

"iam_inline_policies": {},

"instance_profile": "arn:aws:iam::123456789012:instance-profile/eu-west-1-stg-backend-iam-profile",

"trust_policy": {

"Version": "2012-10-17",

"Statement": [

            {

"Sid": "",

"Effect": "Allow",

"Principal": {

"Service": "ec2.amazonaws.com"

              },

"Action": "sts:AssumeRole"

            }

          ]

        },

"permissions_boundary": false,

"public": null,

"resource_policy": null

      }

    }

  },

"volumes": {

"arn:aws:ec2:eu-west-1:123456789012:volume/vol-0371a09e338f582da": {

"associations": {

"instances": {

"arn:aws:ec2:eu-west-1:123456789012:instance/i-018daeedcf06398c0": {}

        }

      },

"config": {

"encrypted": true,

"attached": true,

"public": null,

"resource_policy": null

      }

    }

  },

"autoscaling_groups": {

"arn:aws:autoscaling:eu-west-1:123456789012:autoScalingGroup/stg-backend-20201205160228428400000002": {

"associations": {

"instances": {

"arn:aws:ec2:eu-west-1:123456789012:instance/i-018daeedcf06398c0": {}

        },

"launch_templates": {

"arn:aws:ec2:eu-west-1:123456789012:launch-template/lt-06b73d2e77f10446f": {}

        },

"launch_configurations": {}

      },

"config": {

"name": "stg-backend-20201205160228428400000002",

"public": null,

"resource_policy": null

      }

    }

  },

"vpcs": {

"arn:aws:ec2:eu-west-1:123456789012:vpc/vpc-03cc56a1c2afb5760": {

"associations": {

"subnets": {

"arn:aws:ec2:eu-west-1:123456789012:subnet/subnet-03d86f1ccd7729d85": {},

"arn:aws:ec2:eu-west-1:123456789012:subnet/subnet-0ccfb8dea658f49ec": {},

"arn:aws:ec2:eu-west-1:123456789012:subnet/subnet-05e85a7b0ec9e404c": {},

"arn:aws:ec2:eu-west-1:123456789012:subnet/subnet-0e177ea95bcc76256": {}

        }

      },

"config": {

"cidr": "172.10.0.0/16",

"default": false,

"public": null

      }

    }

  },

"subnets": {

"arn:aws:ec2:eu-west-1:123456789012:subnet/subnet-03d86f1ccd7729d85": {

"associations": {

"route_tables": {

"arn:aws:ec2:eu-west-1:123456789012:route-table/rtb-0ebae6462f919943d": {

"associations": {},

"config": {

"default": false,

"route_to_internet_gateway": [

                {

"DestinationCidrBlock": "0.0.0.0/0",

"GatewayId": "igw-0790540d8d726f9d4",

"Origin": "CreateRoute",

"State": "active"

                }

              ],

"route_to_nat_gateway": [],

"route_to_transit_gateway": [],

"route_to_vpc_peering": [],

"public": null

            }

          }

        },

"network_interfaces": {

"arn:aws:ec2:eu-west-1:123456789012:network-interface/eni-0e8918fa31d2acd55": {},

"arn:aws:ec2:eu-west-1:123456789012:network-interface/eni-0f6c936934fd9d6a6": {},

"arn:aws:ec2:eu-west-1:123456789012:network-interface/eni-041a6e5bb59c336ee": {},

"arn:aws:ec2:eu-west-1:123456789012:network-interface/eni-0e5f6cfdc7c286224": {}

        },

"instances": {

"arn:aws:ec2:eu-west-1:123456789012:instance/i-018daeedcf06398c0": {}

        }

      },

"config": {

"cidr": "172.11.11.0/24",

"map_public_ip_on_launch_enabled": true,

"default": false,

"public": true,

"resource_policy": null,

"public_ips": [

"100.100.100.100",

        ],

"managed_services": [

"ELB app/stg-alb-backend/3567d780bd062d75",

"Interface for NAT Gateway nat-0805d9808347bba69"

        ],

"attached": true

      }

    }

  },

}
```  
###   
### 账号密钥样例  
```
"account": {

"Alias": "metahub-demo",

"AlternateContact": {

"AlternateContactType": "SECURITY",

"EmailAddress": "gabriel@domain.com",

"Name": "Gabriel",

"PhoneNumber": "+1234567890",

"Title": "Security"

  },

"Organizations": {

"Arn": "arn:aws:organizations::123456789012:organization/o-12349772jb",

"Id": "o-12349772jb",

"MasterAccountId": "123456789012",

"MasterAccountEmail": "gabriel.soltz@domain.com",

"FeatureSet": "ALL",

"DelegatedAdministrators": {},

"Details": {

"ParentId": "r-k123",

"ParentType": "ROOT",

"OU": "ROOT",

"Policies": {

"p-FullAWSAccess": {

"Name": "FullAWSAccess",

"Arn": "arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess",

"Type": "SERVICE_CONTROL_POLICY",

"Description": "Allows access to every operation",

"AwsManaged": true,

"Targets": []

        }

      }

    }

  }

},
```  
##   
  
**工具输出**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39YKrISbxRdA8XI8oOqjpJNIQMwcARmchu5yUgG1bAs2zKpL5jHcFho6VeibowDjGxJZ49iaokJviazg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39YKrISbxRdA8XI8oOqjpJN7pTuj6S1SSOzkliayliclfibHEyv3SZWvEbicWmicWV2X3tibLJ9jDajlPiag/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39YKrISbxRdA8XI8oOqjpJNrOpK0CeSt33SBsAWW4HpXRzKA8nbNktRTFmBRA7ibzbALFbUx2Kb5sw/640?wx_fmt=jpeg&from=appmsg "")  
##   
  
**许可证协议**  
  
  
##   
  
本项目的开发与发布遵循  
Apache-2.0  
开源许可证协议。  
  
  
**项目地址**  
  
  
##   
  
**MetaHub：**  
  
https://github.com/gabrielsoltz/metahub  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复“加群”，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
> https://aws.amazon.com/security-hub  
> https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493362&idx=1&sn=39c9b1c4d709e5ad0babb44995b0e412&chksm=ce1f1c6df968957be704d2843b3f448b252d2a2e1b5271efa486c3e57819849e0e287b04568b&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493318&idx=1&sn=02dc5120e00a3d6759be8fcf1b49ec0a&chksm=ce1f1c59f968954fd868b2f8cefa0e8bc5dd703c36dd6db4fc03923be36783a7d4cc791c18b6&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
