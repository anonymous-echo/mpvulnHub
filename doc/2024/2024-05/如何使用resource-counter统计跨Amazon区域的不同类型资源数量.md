#  如何使用resource-counter统计跨Amazon区域的不同类型资源数量   
Alpha_h4ck  FreeBuf   2024-05-06 19:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
**关于resource-counter**  
  
  
  
resource-counter是一款功能强大的命令行工具，该工具基于纯Python 3开发，可以帮助广大研究人员跨Amazon区域统计不同类型资源的数量。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38CjpE7SgibY8ZVMThOhz1b0swKAj9f7GHzhPaaElvibjhIP5Rc7ImjRXJuW7Xfwy6a6nL2n7vVw6fg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
该工具在统计完不同区域的各类资源数量后，可以在命令行中输出并显示统计结果。resource-counter首先会以每个区域为基础显示受监控服务的结果字典，然后以更友好的格式显示所有区域的资源数量总计信息。该工具会尝试为每个资源使用最有效的查询机制，以最小化API活动的影响。广大安全管理人员还可以使用该工具确定安全评估范围，并了解目标客户的资源位置和其他信息。  
  
  
**支持的资源类型**  
  
  
##   
  
当前版本的resource-counter支持收集和统计下列资源的数量：  
  
> 应用程序和网络负载均衡器  
> Autoscale组  
> 传统负载均衡器  
> CloudTrail Trail  
> Cloudwatch规则  
> Config规则  
> Dynamo表  
> Elastic IP地址  
> Glacier Vault  
> IAM组  
> 镜像  
> 实例  
> KMS密钥  
> Lambda函数  
> 启动配置  
> NAT网关  
> 网络访问控制列表  
> IAM策略  
> RDS实例  
> IAM规则  
> S3 Bucket  
> SAML Provider  
> SNS  
> 安全组  
> 快照  
> 子网  
> IAM用户  
> VPC节点  
> VPC对等节点连接  
> VPC  
> 卷  
  
##   
  
**工具依赖**  
  
  
##   
> Python 3.6+  
> click  
> boto3  
> botocore  
  
##   
  
**工具下载**  
  
  
##   
  
由于该工具基于Python 3.6开发，因此我们首先需要在本地设备上安装并配置好最新版本的Python 3.6+环境。  
  
  
接下来，广大研究人员可以直接使用下列命令将该项目源码克隆至本地：  
```
git clone https://github.com/disruptops/resource-counter.git
```  
  
然后切换到项目目录中，使用pip3工具和项目提供的requirements.txt文件安装该工具所需的其他依赖组件：  
```
cd resource-counter

pip install -r ./requirements.txt
```  
  
**工具运行**  
  
  
##   
  
下列命令即可执行resource-counter脚本：  
```
python count_resources.py
```  
  
  
默认配置下，该工具会直接使用系统中已配置的任何AWS凭证。我们也可以在运行时指定一个访问密钥或凭证，但不会存储在工具中。该工具只需要目标列表服务中的读取权限即可，工具默认使用了ReadOnlyAccess管理策略，但我们也可以根据需要去使用SecurityAudit策略。  
  
  
下面给出的是该工具的使用帮助信息：  
```
Usage: count_resources.py [OPTIONS]



Options:

--access TEXT   设置AWS访问密钥，否则将使用AWS CLI路径下的默认凭证

--secret TEXT    AWS敏感信息密钥

--profile TEXT   如果你拥有多个凭证资料，可以使用该参数来指定使用其中一个

--help          显示工具帮助信息和退出
```  
  
**工具输出样例**  
  
  
##   
  
在下列示例中，我们将使用凭证配置文件建立AWS会话，并跨区域统计资源数量，整个过程可能需要花费几分钟的时间：  
```
Resources by region {'ap-northeast-1': {'instances': 0, 'volumes': 0, 'security_groups': 1, 'snapshots': 0, 'images': 0, 'vpcs': 1, 'subnets': 3, 'peering connections': 0, 'network ACLs': 1, 'elastic IPs': 0, 'NAT gateways': 0, 'VPC Endpoints': 0, 'autoscale groups': 0, 'launch configurations': 0, 'classic load balancers': 0, 'application and network load balancers': 0, 'lambdas': 0, 'glacier vaults': 0, 'cloudwatch rules': 0, 'config rules': 0, 'cloudtrail trails': 1, 'sns topics': 0, 'kms keys': 0, 'dynamo tables': 0, 'rds instances': 0}, 'ap-northeast-2': {'instances': 0, 'volumes': 0, 'security_groups': 1, 'snapshots': 0, 'images': 0, 'vpcs': 1, 'subnets': 2, 'peering connections': 0, 'network ACLs': 1, 'elastic IPs': 0, 'NAT gateways': 0, 'VPC Endpoints': 0, 'autoscale groups': 0, 'launch configurations': 0, 'classic load balancers': 0, 'application and network load balancers': 0, 'lambdas': 0, 'glacier vaults': 0, 'cloudwatch rules': 0, 'config rules': 0, 'cloudtrail trails': 1, 'sns topics': 0, 'kms keys': 0, 'dynamo tables': 0, 'rds instances': 0}, 'ap-south-1': {'instances': 0, 'volumes': 0, 'security_groups': 1, 'snapshots': 0, 'images': 0, 'vpcs': 1, 'subnets': 2, 'peering connections': 0, 'network ACLs': 1, 'elastic IPs': 0, 'NAT gateways': 0, 'VPC Endpoints': 0, 'autoscale groups': 0, 'launch configurations': 0, 'classic load balancers': 0, 'application and network load balancers': 0, 'lambdas': 0, 'glacier vaults': 0, 'cloudwatch rules': 0, 'config rules': 0, 'cloudtrail trails': 1, 'sns topics': 0, 'kms keys': 0, 'dynamo tables': 0, 'rds instances': 0}, 'ap-southeast-1': {'instances': 0, 'volumes': 0, 'security_groups': 1, 'snapshots': 0, 'images': 0, 'vpcs': 1, 'subnets': 3, 'peering connections': 0, 'network ACLs': 1, 'elastic IPs': 0, 'NAT gateways': 0, 'VPC Endpoints': 0, 'autoscale groups': 0, 'launch configurations': 0, 'classic load balancers': 0, 'application and network load balancers': 0, 'lambdas': 0, 'glacier vaults': 0, 'cloudwatch rules': 0, 'config rules': 0, 'cloudtrail trails': 1, 'sns topics': 0, 'kms keys': 0, 'dynamo tables': 0, 'rds instances': 0}, 'ap-southeast-2': {'instances': 0, 'volumes': 0, 'security_groups': 1, 'snapshots': 0, 'images': 0, 'vpcs': 1, 'subnets': 3, 'peering connections': 0, 'network ACLs': 1, 'elastic IPs': 0, 'NAT gateways': 0, 'VPC Endpoints': 0, 'autoscale groups': 0, 'launch configurations': 0, 'classic load balancers': 0, 'application and network load balancers': 0, 'lambdas': 0, 'glacier vaults': 0, 'cloudwatch rules': 0, 'config rules': 0, 'cloudtrail trails': 1, 'sns topics': 0, 'kms keys': 0, 'dynamo tables': 0, 'rds instances': 0}, 'ca-central-1': {'instances': 0, 'volumes': 0, 'security_groups': 1, 'snapshots': 0, 'images': 0, 'vpcs': 1, 'subnets': 2, 'peering connections': 0, 'network ACLs': 1, 'elastic IPs': 0, 'NAT gateways': 0, 'VPC Endpoints': 0, 'autoscale groups': 0, 'launch configurations': 0, 'classic load balancers': 0, 'application and network load balancers': 0, 'lambdas': 0, 'glacier vaults': 0, 'cloudwatch rules': 0, 'config rules': 0, 'cloudtrail trails': 1, 'sns topics': 0, 'kms keys': 0, 'dynamo tables': 0, 'rds instances': 0}, 'eu-central-1': {'instances': 0, 'volumes': 0, 'security_groups': 1, 'snapshots': 0, 'images': 0, 'vpcs': 1, 'subnets': 3, 'peering connections': 0, 'network ACLs': 1, 'elastic IPs': 0, 'NAT gateways': 0, 'VPC Endpoints': 0, 'autoscale groups': 0, 'launch configurations': 0, 'classic load balancers': 0, 'application and network load balancers': 0, 'lambdas': 0, 'glacier vaults': 0, 'cloudwatch rules': 0, 'config rules': 0, 'cloudtrail trails': 1, 'sns topics': 0, 'kms keys': 0, 'dynamo tables': 0, 'rds instances': 0}, 'eu-west-1': {'instances': 0, 'volumes': 0, 'security_groups': 1, 'snapshots': 0, 'images': 0, 'vpcs': 1, 'subnets': 3, 'peering connections': 0, 'network ACLs': 1, 'elastic IPs': 0, 'NAT gateways': 0, 'VPC Endpoints': 0, 'autoscale groups': 0, 'launch configurations': 0, 'classic load balancers': 0, 'application and network load balancers': 0, 'lambdas': 0, 'glacier vaults': 0, 'cloudwatch rules': 0, 'config rules': 0, 'cloudtrail trails': 1, 'sns topics': 0, 'kms keys': 0, 'dynamo tables': 0, 'rds instances': 0}, 'eu-west-2': {'instances': 3, 'volumes': 3, 'security_groups': 1, 'snapshots': 0, 'images': 0, 'vpcs': 1, 'subnets': 3, 'peering connections': 0, 'network ACLs': 1, 'elastic IPs': 0, 'NAT gateways': 0, 'VPC Endpoints': 0, 'autoscale groups': 0, 'launch configurations': 0, 'classic load balancers': 0, 'application and network load balancers': 0, 'lambdas': 0, 'glacier vaults': 0, 'cloudwatch rules': 0, 'config rules': 0, 'cloudtrail trails': 1, 'sns topics': 0, 'kms keys': 0, 'dynamo tables': 0, 'rds instances': 0}, 'eu-west-3': {'instances': 0, 'volumes': 0, 'security_groups': 1, 'snapshots': 0, 'images': 0, 'vpcs': 1, 'subnets': 3, 'peering connections': 0, 'network ACLs': 1, 'elastic IPs': 0, 'NAT gateways': 0, 'VPC Endpoints': 0, 'autoscale groups': 0, 'launch configurations': 0, 'classic load balancers': 0, 'application and network load balancers': 0, 'lambdas': 0, 'glacier vaults': 0, 'cloudwatch rules': 0, 'config rules': 0, 'cloudtrail trails': 1, 'sns topics': 0, 'kms keys': 0, 'dynamo tables': 0, 'rds instances': 0}, 'sa-east-1': {'instances': 0, 'volumes': 0, 'security_groups': 1, 'snapshots': 0, 'images': 0, 'vpcs': 1, 'subnets': 3, 'peering connections': 0, 'network ACLs': 1, 'elastic IPs': 0, 'NAT gateways': 0, 'VPC Endpoints': 0, 'autoscale groups': 0, 'launch configurations': 0, 'classic load balancers': 0, 'application and network load balancers': 0, 'lambdas': 0, 'cloudwatch rules': 0, 'config rules': 0, 'cloudtrail trails': 1, 'sns topics': 0, 'kms keys': 0, 'dynamo tables': 0, 'rds instances': 0}, 'us-east-1': {'instances': 2, 'volumes': 2, 'security_groups': 19, 'snapshots': 0, 'images': 0, 'vpcs': 2, 'subnets': 3, 'peering connections': 0, 'network ACLs': 2, 'elastic IPs': 0, 'NAT gateways': 0, 'VPC Endpoints': 0, 'autoscale groups': 0, 'launch configurations': 0, 'classic load balancers': 0, 'application and network load balancers': 0, 'lambdas': 0, 'glacier vaults': 0, 'cloudwatch rules': 0, 'config rules': 1, 'cloudtrail trails': 2, 'sns topics': 3, 'kms keys': 5, 'dynamo tables': 0, 'rds instances': 0}, 'us-east-2': {'instances': 0, 'volumes': 0, 'security_groups': 2, 'snapshots': 0, 'images': 0, 'vpcs': 1, 'subnets': 3, 'peering connections': 0, 'network ACLs': 1, 'elastic IPs': 0, 'NAT gateways': 0, 'VPC Endpoints': 0, 'autoscale groups': 0, 'launch configurations': 0, 'classic load balancers': 0, 'application and network load balancers': 0, 'lambdas': 0, 'glacier vaults': 0, 'cloudwatch rules': 0, 'config rules': 0, 'cloudtrail trails': 1, 'sns topics': 0, 'kms keys': 0, 'dynamo tables': 0, 'rds instances': 0}, 'us-west-1': {'instances': 1, 'volumes': 3, 'security_groups': 14, 'snapshots': 1, 'images': 0, 'vpcs': 0, 'subnets': 0, 'peering connections': 0, 'network ACLs': 0, 'elastic IPs': 0, 'NAT gateways': 0, 'VPC Endpoints': 0, 'autoscale groups': 0, 'launch configurations': 0, 'classic load balancers': 0, 'application and network load balancers': 0, 'lambdas': 0, 'glacier vaults': 0, 'cloudwatch rules': 0, 'config rules': 0, 'cloudtrail trails': 1, 'sns topics': 0, 'kms keys': 1, 'dynamo tables': 0, 'rds instances': 0}, 'us-west-2': {'instances': 9, 'volumes': 29, 'security_groups': 76, 'snapshots': 171, 'images': 104, 'vpcs': 7, 'subnets': 15, 'peering connections': 1, 'network ACLs': 8, 'elastic IPs': 7, 'NAT gateways': 1, 'VPC Endpoints': 0, 'autoscale groups': 1, 'launch configurations': 66, 'classic load balancers': 1, 'application and network load balancers': 2, 'lambdas': 10, 'glacier vaults': 1, 'cloudwatch rules': 8, 'config rules': 1, 'cloudtrail trails': 1, 'sns topics': 6, 'kms keys': 7, 'dynamo tables': 1, 'rds instances': 0}}
```  
> 应用程序和网络负载均衡器：2个  
> Autoscal组：1个  
> 传统负载均衡器：1个  
> CloudTrail Trail：16个  
> Cloudwatch规则：8个  
> 配置规则：2个  
> Dynamo表：1个  
> 弹性IP地址：7个  
> Glacier Vault：1个  
> 组：12个  
> 镜像：104个  
> 实例：15 KMS密钥：13个  
> Lambda函数：10个启动配置：66个  
> NAT网关：1个  
> 网络ACL:22个  
> 策略：15个  
> RDS实例：0个  
> IAM角色：40个  
> S3 Bucket：31个  
> SAML Provider：1个  
> SNS主题：9个  
> 安全组：122个  
> 快照：172个  
> 子网：51个  
> 用户：14个  
> VPC端点：0个  
> VPC对等连接：1个  
> VPC：21个  
> 卷：37个  
  
```
```  
##   
  
**许可证协议**  
  
  
##   
  
本项目的开发与发布遵循  
MIT  
开源许可证协议。  
  
  
**项目地址**  
  
  
##   
  
**resource-counter：**  
  
https://github.com/disruptops/resource-counter  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493411&idx=1&sn=6e2fc6872803cd754a1d6796ea8d1153&chksm=ce1f1dbcf96894aa2d841924f91841720a1f96f4350d488f736af89e16d901aa1d02ca372a4c&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493362&idx=1&sn=39c9b1c4d709e5ad0babb44995b0e412&chksm=ce1f1c6df968957be704d2843b3f448b252d2a2e1b5271efa486c3e57819849e0e287b04568b&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
