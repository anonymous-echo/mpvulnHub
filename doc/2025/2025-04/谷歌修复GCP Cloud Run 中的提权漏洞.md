#  谷歌修复GCP Cloud Run 中的提权漏洞   
Kevin Townsend  代码卫士   2025-04-03 18:20  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**网络安全研究员披露了位于谷歌云平台 (GCP) Cloud Run 中一个已修复的提权漏洞。该漏洞本可导致恶意人员访问容器镜像甚至注入恶意代码。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQr0CXoUIvN9qXrGWL7w9E0D7mMPiaPfSg4M7CEPo06ibaSWJJADes3t6vXRr6w2z7MjQEic0ucrZlhg/640?wx_fmt=png&from=appmsg "")  
  
  
Tenable 公司的安全研究员 Liv Matan 在报告中提到，“该漏洞本可导致这类身份滥用其 Google Cloud Run 校订编辑权限，在相同账号中拉取非公开的 Google Artifact Registry 和 Google Container Registry 镜像。”该公司被命名为 “ImageRunner”，谷歌已在2025年1月8日修复。  
  
Google Cloud Run 是一款完全管理服务，用于在可扩展的serverless 环境中执行容器化应用。当该技术用于运行服务时，就会从 Artifact Registry （或Docker Hub）中检索容器镜像，通过指定镜像 URL 实施后续部署。  
  
该问题的本质实际上是某些身份缺乏容器注册表权限，但却在 Google Cloud Run 部署版本上拥有编辑权限。每当 Cloud Run 服务进行部署或更新时，就会创建一个新版本。而每次部署 Cloud Run 部署版本时，就会通过服务代理账号拉取必要的镜像。研究人员解释称，“如果攻击者获得受害者项目中的某些权限，具体说是 run.services.update 和 iam.serviceAccounts.actAs 权限，则可修改 Cloud Run 服务并部署新的版本。这样，他们就能指定同样项目中的任何私有容器镜像，供该服务进行拉取。”  
  
另外，攻击者可访问存储在受害者注册表中的敏感或专有镜像，甚至引入恶意指令。当这些指令被执行时，可被滥用于提取机密、渗透敏感数据、甚至打开受其控制的机器的反向shell。谷歌发布的补丁确保用户或服务账号创建或更新 Cloud Run 资源时，需要获得拥有访问容器镜像的明确权限。谷歌提到，“当使用 Artifact Registry 时，确保委托方在项目上或包含容器镜像进行部署的仓库拥有 Artifact Registry Reader (roles/artifactregistry.reader) IAM 角色。”  
  
Tenable 将 ImageRunner 漏洞列为 “Jenga”，即因为多种云服务的互联本质，它们的安全风险也会传递。谷歌提到，“云提供商在其它已有服务之上构建服务。如果一种服务遭攻击或攻陷，那么其它构建在其基础上的云提供商也会继承风险并易受攻击。这种场景可导致攻击者发现新的提权机会甚至漏洞，并为防御人员引入新的隐藏风险。”  
  
数周前，Praetorian 公司详述了多种可导致低权限主体滥用Azure 虚拟机通过 Azure订阅服务获得控制的情况：  
  
- 登录到与管理员管理身份相关的 Azure 虚拟机。  
  
- 将已有的管理员用户分配的管理身份附加到已有的 Azure 虚拟机并在该虚拟机中执行代码。  
  
- 创建新的 Azure 虚拟机并能附加已有的管理员管理身份，通过数据面板操作，在该虚拟机中执行命令。  
  
  
  
研究人员提到，“获得该订阅的 Owner 角色后，攻击者或能够利用对所有订阅资源的广泛控制，找到到达 Entra ID 租户的提权路径。这一路径基于受害者订阅中的计算资源，拥有 Entra ID 权限的服务主体可能会升级为 Global Administrator。”  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Google Cloud 依赖混淆漏洞影响数百万台服务器](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520848&idx=4&sn=5dd6c8f2b2d48123ef978d8ef1b071ff&scene=21#wechat_redirect)  
  
  
[Google Cloud Build 漏洞可使黑客发动供应链攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517101&idx=1&sn=b0c111a99bc956b2107431d6ebb95ab6&scene=21#wechat_redirect)  
  
  
[研究员发现 Google Cloud 项目中的 SSRF 漏洞，获1万美元奖金](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509349&idx=3&sn=d8378d91c487794e8bfe850aa68365f2&scene=21#wechat_redirect)  
  
  
[从简单的 XSS 到完整的 Google Cloud Shell 实例接管，值5000美元](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247495477&idx=2&sn=66a34141cb091f14aed7ce080d0ed0fc&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2025/04/google-fixed-cloud-run-vuln  
erability.html  
  
  
题图：  
Pexels   
License  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
