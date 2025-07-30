#  Hugging Face 等AI即服务平台易受严重漏洞影响，遭AI供应链攻击   
Deeba Ahmed  代码卫士   2024-04-09 17:48  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**网络安全公司 Wiz.io 发现，AI即服务（即 AI Cloud）平台如 Hugging Face 等易受严重风险，可导致攻击者提升权限、获得跨租户访问权限并可能接管CI/CD管道。**  
  
  
  
**问题简述**  
  
  
AI 模型要求具有强大的GPU，通常会被外包给AI服务提供商，类似于来自 AWS/GCP/Azure的云基础设施。Hugging Face 的服务名称为 “Hugging Face Inference API”。  
  
Wiz Research 可通过上传恶意模型并使用容器逃逸技术攻陷运行自定义模型的服务，从而导致对其他客户存储在 Hugging Face 中的模型拥有跨租户访问权限。该平台支持多种AI模型格式，其中两个是 PyTorch (Pickle) 和 Safetensors。Python 的 Pickle 格式众所周知是不安全的，可导致不可信数据反序列化后的RCE后果，尽管 Hugging Face 评估了上传到平台中的 Pickle 数据且认为它们是危险的。  
  
然而，研究人员克隆了一个合法的基于 Pickle 的模型 (gpt2)，将其修改为上传后运行你想shell，并将该构造的模型以非公开模型格式上传。他们通过使用 Inference API 特性与该模型进行交互，获得反向 shell 并发现构造执行任意代码的 PyTorch 模型很简单，将模型上传至 Hugging Face 可在 Inference API 中执行代码。  
  
  
**潜在风险**  
  
  
潜在风险是灾难性的，因为攻击者可访问数百万个非公开 API 模型和应用。两种关键风险包括共享推断基础设施接管风险，恶意模型运行不可信的引用基础设施，并共享CI/CD接管风险。恶意AI应用可能试图接管该管道并在接管CI/CD集群后执行供应链攻击。  
  
另外，攻击者可通过使用多种方法攻击AI模型、AI/ML应用和推断基础设施。他们可使用引发错误预测的输入、不正确的预测或恶意模型。AI模型通常被视作黑盒且用于应用程序中。然而，验证模型完整性的工具很少，因此开发人员在下载时应该保持谨慎。  
  
Wiz 在报告中解释称，“使用不可信的AI模型可对应用程序引来完整性和安全性风险，并等同于在应用程序中包含不可信代码。”  
  
  
**协作**  
  
  
开源AI中心 Hugging Face 已经和 Wiz.io 协作解决与AI驱动服务相关联的安全风险。这一协作说明了采取主动措施确保负责任和安全开发以及AI技术部署的重要性。  
  
Salt Security 公司产品战略副总裁 Nick Rago 表示，“保护托管AI的关键云基础设施很重要，Wiz 的研究结果很重要。安全团队识别AI所训练和服务的渠道是API这一点也很重要，我们必须在这个层面应用严格的安全性，确保AI供应链的安全。”  
  
  
**令人担忧的场景**  
  
  
这一发现正值基于AI工具下的数据安全问题引发关注之时。AvePoint 公司调查显示，不到一般的组织机构认为它们能够以安全的方式使用AI，71%的受访组织机构担心实现前的数据隐私和安全问题，61%的受访组织机构担心内部数据质量问题。  
  
尽管AI工具如 ChatGPT 和 Google Gemini 得到大规模的应用，但不到半数的工具具有“AI可接受使用策略”。另外，45%的组织机构在AI执行过程中遭遇过数据暴露风险。  
  
多个行业对AI的大规模采用说明了强大安全措施的必要性。这些漏洞可导致攻击者操纵AI模型、窃取敏感数据或中断关键操作。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[开源AI框架 Ray 的0day已用于攻陷服务器和劫持资源](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519162&idx=1&sn=3872fcc82018e2c561d9e4e7574f0c8e&chksm=ea94bad0dde333c6d504e2c7680caabb4badc973dd03223bab93d5b62e5469c4db22d966adf9&scene=21#wechat_redirect)  
  
  
[AWS修复 Airflow 服务中严重的 “FlowFixation” 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519143&idx=2&sn=dc771e1d0ed09825b9fb60e06a9c8291&chksm=ea94bacddde333db8eb4ff27c6f46bccc6a819c55ebd58f8f6b71a42833f11ad76c92012ba76&scene=21#wechat_redirect)  
  
  
[“会话溢出”网络攻击绕过 AI 安全攻击企业高管](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519109&idx=2&sn=238a3481491209e1b525c85f973cf79a&chksm=ea94baefdde333f968d204a3da4718f7c4bab621707765d841725198047d069df315cd196b26&scene=21#wechat_redirect)  
  
  
[研究员开发出AI蠕虫，可在AI系统之间自动传播](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518984&idx=1&sn=84deee6f57e994f428b1dbca62279d53&chksm=ea94ba62dde3337458316504b214849fc60dfd4cc21d2fd7b4dfd2fdd0cc9ff85379a181dcb7&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.hackread.com/hugging-face-vulnerability-ai-supply-chain-attack/  
  
  
题图：  
Pixabay  
 License  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
