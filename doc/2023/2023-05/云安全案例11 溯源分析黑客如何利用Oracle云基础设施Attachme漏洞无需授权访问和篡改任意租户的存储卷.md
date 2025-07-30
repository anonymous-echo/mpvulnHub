#  云安全案例11: 溯源分析黑客如何利用Oracle云基础设施Attachme漏洞无需授权访问和篡改任意租户的存储卷   
原创 debugeeker  奶牛安全   2023-05-10 08:05  
  
2022年6 月，wiz 工程师发现并报告了Oracle云基础设施(OCI) 中的一个主要云隔离漏洞#AttachMe，促使 Oracle 在数小时内修补该漏洞，而无需客户采取行动。  
- 潜在影响：在打补丁之前，所有 OCI 客户都可能成为了解#AttachMe的黑客的目标。只要黑客拥有其 Oracle 云标识符 (OCID)，就可以读取或写入任何未挂载的存储卷或允许多重挂载的挂载存储卷，从而允许泄露敏感数据或发起更具破坏性的攻击可执行文件操作。  
  
- 修复：在收到 wiz 通知的 24 小时内，Oracle为所有 OCI 客户修补了#AttachMe 。 无需客户操作。  
  
- 主要结论：云租户隔离是云中的一个关键要素。客户希望其他客户无法访问他们的数据。然而，云隔离漏洞打破了租户之间的壁垒。这凸显了主动云漏洞研究、负责任地披露和公开跟踪云漏洞对云安全的重要性。  
  
## AttachMe 是什么？  
  
#AttachMe是报告的最严重的云漏洞之一，因为它可能影响所有 OCI 客户。云隔离漏洞通常会影响特定的云服务。但是，在这种情况下，影响与核心云服务有关。  
  
wiz 工程师发现将磁盘挂载到另一个帐户中的 VM 不需要任何权限。这意味着潜在的黑客可以访问和修改任何 OCI 客户的数据，在某些情况下甚至可以接管环境。  
  
潜在的攻击流程很简单：  
1. 通过搜索网络发现目标受害者卷的 ID (OCID)或使用低权限用户从受害者环境中读取卷 OCID 。  
  
1. 在与目标卷位于同一可用性域 (AD) 中由黑客控制的租户中启动计算实例。  
  
1. 将受害者的卷挂载到黑客的计算实例，从而获得对该卷的读/写权限。  
  
从那里，潜在的黑客可能已经执行了许多严重的操作：  
- 泄露存储在卷上的敏感数据。  
  
- 在卷中搜索明文密钥，以便在受害者的环境中横向移动和/或提升权限。  
  
- 改变现有的块卷和引导卷——例如通过操作二进制文件——以便在卷挂载到计算实例上时获得代码执行。  
  
## wiz 是如何发现 AttachMe 的  
  
在为 wiz 构建 OCI 连接器时，软件工程师注意到，只要获得卷的 Oracle 云标识符 (OCID)，而无需明确授权, 几乎所有块卷和引导卷都可以挂载到一个计算实例。经过更多测试后，发现即使卷和计算实例驻留在不同的 OCI 租户中时，这也是可能的！这意味着黑客可以访问另一个租户中的卷（只要他们知道 OCID），而拥有该卷的人（受害者）将完全不知道其他人对他们的数据具有读/写访问权限。  
## 背景 - OCI 中的卷是什么？  
  
如 OCI文档中所述，卷是为计算实例提供持久存储空间的虚拟磁盘。OCI 中有两种类型的卷：  
- 块卷： 一种可卸载的块存储设备，允许动态扩展实例的存储容量。  
  
- 引导卷： 一种可卸载的引导卷设备，包含用于引导计算实例的映像，通常在创建计算实例时创建。  
  
OCI 支持块卷的多重挂载，这意味着可以使用具有读/写或只读权限的共享功能将单个卷同时挂载到多个实例。  
  
从 CLI 将引导卷或块卷挂载到计算实例非常简单，只需要卷和实例 ID：  
```
oci compute volume-attachment attach --type paravirtualized --instance-id <instance_ocid>  --volume-id <volume_ocid>  

```  
  
根据策略参考， AttachVolume 所需的权限是VOLUME_WRITE、VOLUME_ATTACHMENT_CREATE和INSTANCE_ATTACH_VOLUME。实例和卷不一定需要在同一个隔离空间中。  
  
挂载卷是一种 OCI 资源，它驻留在计算实例的隔离空间中，描述了卷与计算实例的连接。权限应用于隔离空间（及其隔离空间树）。因此，VOLUME_ATTACHMENT_CREATE和INSTANCE_ATTACH_VOLUME必需用于在实例的隔离空间范围（在本例中为黑客的隔离空间），并且VOLUME_WRITE必需用于在卷的隔离空间范围（受害者的隔离空间）。  
  
然而，正如我们所发现的，挂载卷时VOLUME_WRITE权限验证存在漏洞，这使得在未经授权的情况下可能可以挂载任何卷，此外，还可以跨不同的租户进行挂载：我们设法将一个租户的卷挂载到另一个租户的计算实例。  
### 演示  
  
当未经授权的用户尝试对卷执行任何操作时，该服务（正确地）返回一个错误，指示用户缺少所需的权限：  
```
elad_gabay@cloudshell:~ (us-ashburn-1)$ oci bv volume get --volume-id ocid1.bootvolume.oc1.iad.abuwcljrybvvdsn*******************************************
ServiceError:
{
  "client_version": "`Oracle`-PythonSDK/2.69.0, `Oracle`-PythonCLI/3.10.0",
  "code": "NotAuthorizedOrNotFound",
  "logging_tips": "Please run the OCI CLI command using --debug flag to find more debug information.",
  "message": "Authorization failed or requested resource not found.",
  "opc-request-id": "DFB9SCC25*****",
  "operation_name": "get_volume",
  "request_endpoint": "GET https://iaas.us-ashburn-`Oracle`cloud.com/20160918/volumes/ocid1.bootvolume.oc1.iad.abuwcljrybvvdsn*******************************************",
  "status": 404,
  "target_service": "blockstorage",
  "timestamp": "2022-06-07114:12:21.408280",
  "troubleshooting_tips": "See https://docs.`Oracle`.com/iaas/Content/API/References/apierrors.htm#apierrors_404_404_notauthorizedornotfound for more information about resolving this error. If you are unable to resolve this issue, run this CLI command with --debug option and contact `Oracle` support and provide them the full error message."
}

```  
  
但是，在修复#AttachMe 之前，无论用户是否具有足够的权限，尝试将卷挂载到计算实例都会成功：  
```
elad_gabay@cloudshell:~(us-ashburn-1)$ oci compute volume-attachment attach --instance-id ocid1.instance.oc1.iad.anuwcljrixjtluica******************************************* --volume-id ocid1.bootvolume.oc1.iad.abuwcljrybvvdsn3******************************************* --type paravirtualized
{
  "data": {
    "attachment-type": "paravirtualized",
    "availability-domain": "zSfH:US-ASHBURN-AD-1",
    "compartment-id": "ocid1.tenancy.oc1..aaaaaaaaote2dzazv**********************",
    "device": "null",
    "display-name": "volumeattachment20220607141228",
    "id": "ocid1.volumeattachment.oc1.iad.anuwcljrixjtluic***********************",
    "instance-id": "ocid1.instance-oc1.iad.anuwcljrixjtluica*********************",
    "is-multipath": null,
    "is-pv-encryption-in-transit-enabled":false,
    "is-read-only":false,
    "is-shareable": false,
    "iscsi-login-state": null,
    "lifecycle-state": "ATTACHING",
    "time-created": "2022-06-07T14:12:29.027000+00:00",
    "volume-id": "ocid1.bootvolume.oc1.iad.abuwcljrybvvdsn3***********************",
    },
    "etag": "992e06ff86b86a5fe732308092a55***********************************"
}

```  
  
挂载卷后，就可以查看和修改其内容。  
  
利用#AttachMe 的详细要求是：  
- 黑客必须知道目标卷的 OCID， 虽然 OCID 通常是私有的，但它们不被视为秘密，因此很容易实现。  
  
- 黑客的计算实例必须与目标卷位于同一可用域 (AD) 中.由于可用区域的数量相对较少（某些地区最多三个），因此可以轻松满足此条件，因此可以枚举。  
  
- 目标卷必须已卸载或挂载为可共享。已卸载卷相对常见，因为默认情况下不会删除与终止的计算实例关联的引导卷。此外，备份数据卷通常不挂载到正在运行的计算实例。  
  
## 风险分析  
  
当黑客获得对您的卷的读取权限时，主要风险是数据泄露。卷可能包含敏感信息，例如个人身份信息、密钥等。  
  
另一个风险是数据操纵和入侵您的云网络。挂载一个卷提供写访问权限，可用于操作卷上的任何数据，包括操作系统运行文件（例如，通过修改二进制文件），从而在远程计算实例上获得代码执行并在受害者的云环境中立足。  
  
潜在的攻击路径包括：  
- 隔离空间 或 租户 内的权限提升——如果黑客设法获得对受害者 OCI 环境的初始访问权限，则可能会利用#AttachMe进一步提升权限。 黑客本来能够查询隔离区中的所有可用卷以获取它们的 OCID、安装它们并读取存储在它们上的任何敏感信息。  
  
- 跨租户访问——一个更具影响力的场景是，如果黑客设法获得远程租户中的卷的 OCID。#AttachMe可用于通过读取存储在目标卷中的敏感信息和长期密钥来获得对受害者环境的初始访问权限。此外，黑客可能已经操纵了现有的块卷和引导卷，其方式是在卷安装在计算实例上时提供黑客代码执行。  
  
鉴于 OCID 通常不被视为秘密，我们认为这两种潜在的攻击路径都非常可行。可以通过简单的在线搜索找到众多在各种环境（包括大公司的环境）的块卷和引导卷的 OCID。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/QXsgGBUcicbyfUCeObQ4GlUrz3T31zsU37YHPozZIKBeiaAo3oc22HQf8suPZbdjuorqj8SoaMH66nicSw48zGxvg/640?wx_fmt=other "")  
  
还可以找到发布在 GitHub 上的卷的 OCID，表明这些 ID 确实没有被开发人员视为秘密。具有环境读取权限的低权限用户和第三方供应商可以非常轻松地获取 OCID。  
## 发现和披露时间表  
  
在发现#AttachMe后，我们立即向 Oracle 披露了我们的发现，Oracle 在不到 24 小时内调查并解决了这个问题。我们很高兴与这样一个专业的团队合作。  
- 2022 年 6 月 6 日——wiz 发现漏洞  
  
- 2022 年 6 月 9 日——向 Oracle 报告漏洞  
  
- 2022 年 6 月 10 日——甲骨文确认报告  
  
- 2022 年 6 月 10 日——漏洞修复  
  
## 云构建者和云捍卫者的经验教训  
  
用户权限验证不充分是云服务提供商中常见的错误类别。识别此类问题的最佳方法是在开发阶段对每个敏感 API 执行严格的代码审查和全面测试。  
# 请点一下右下角的“在看”，谢谢！！  
# 请帮忙点赞， 谢谢！！  
# 请帮忙转发，谢谢！！  
# 暗号: 657082  
  
  
  
