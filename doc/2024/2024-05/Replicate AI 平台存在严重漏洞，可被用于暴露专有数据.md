#  Replicate AI 平台存在严重漏洞，可被用于暴露专有数据   
 代码卫士   2024-05-27 17:24  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
作者：  
**Elizabeth Montalbano**  
  
**编译：代码卫士**  
  
**Replicate AI 平台中存在一个严重漏洞，可导致攻击者在平台内执行恶意 AI 模型，实施多租户攻击，从而访问客户的非公开AI模型并可能暴露专有知识或敏感数据。**  
  
Wiz 公司的安全研究员在与AI即服务提供商的合作过程中发现了这个缺陷，并开始调查平台的安全性。该缺陷的发现说明AI即服务解决方案中租户分离的难度，尤其是在运行不可信来源AI模型的环境下更是如此。  
  
研究员 Shir Tamari 和 Sagi Tzadik 在博客文章中提到，“利用该漏洞可导致越权访问 AI 提示和所有 Replicate 平台客户的结果”，还可能修改这些结果。此前，研究人员发现多个漏洞可在 HuggingFace AI 平台中造成类似后果。  
  
Wiz 公司的首席技术官兼联合创始人 Ami Luttwak 表示，“正如我们在与Replicate 一样的顶级AI即服务提供商Hugging Face 的研究结果一样，当在云环境中运行AI模型时，记住AI模型实际上是代码这一点至关重要。和所有代码一样，来源必须得到验证并扫描内容中的恶意 payload。”  
  
确实，该缺陷可对AI即服务提供商带来威胁，可导致客户在存在其他客户数据的共享环境中以AI模型的形式执行不可信代码。该缺陷还可影响AI团队。当AI团队采用不可信来源的AI模型并在工作站或公司服务器上运行时，他们就会受到影响。  
  
研究人员在2023年1月负责任地将该漏洞告知AI模型共享厂商 Replicate；该公司及时缓解该漏洞，避免客户数据遭攻陷。目前客户尚未采取任何其它措施。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQS1J1eFVWgUYuAACRPRwicjL8vmzZTmvpVFictFC1xiayBIRCeo9EibCarFctFR9Tlg57FD39hOUwDDw/640?wx_fmt=gif&from=appmsg "")  
  
**漏洞利用**  
  
  
  
  
  
该漏洞产生的原因在于，攻击者以 Cog 格式创建了一个恶意容器，从而在 Replicate 平台上执行远程代码。Cog 格式是在 Replicate 上容器化模型的一种专有格式。通过 Cog 容器化模型后，用户可将所获得的图像上传到 Replicate 平台上并开始进行交互。  
  
研究人员创建了一个恶意 Cog 容器并将其上传至该平台，之后通过 root 权限在 Replicate 基础设施上执行代码。研究人员提到，“我们认为该代码执行技术是一种模式，企业和组织机构运行不可信来源的AI模型，尽管这些模型可能是恶意代码。”类似技术也被用于利用位于 HuggingFace 平台上的缺陷。  
  
该利用导致研究人员调查环境横向移动并最终移动出所运行的节点之外，而该节点位于托管于谷歌 Cloud 平台上的 Kubernetes 集群内。尽管这一流程挑战重重，但他们最终发起跨租户攻击，查询其它模型甚至修改这些模型的输出。  
  
研究人员写道，“该漏洞的利用本可对Replicate 平台及其用户带来严重风险。攻击者可查询客户的非公开AI模型，从而可能暴露模型训练流程中的专有知识或敏感数据。另外，拦截提示可暴露敏感数据，包括个人可识别信息等。”确实，这种修改AI模型提示和响应的能力可对AI应用的功能造成严重威胁，从而导致攻击者操纵AI行为并攻陷这些模型的决策流程。研究人员提到，“这类操作直接威胁受AI驱动输出的准确性和可靠性，破坏自动化决策的完整性并可能对依赖于受陷模型的用户造成深远后果。”  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQS1J1eFVWgUYuAACRPRwicjL8vmzZTmvpVFictFC1xiayBIRCeo9EibCarFctFR9Tlg57FD39hOUwDDw/640?wx_fmt=gif&from=appmsg "")  
  
**要求新型缓解措施**  
  
  
  
  
  
Luttwak 提到，目前上不存在炎症模型真实性或者扫描威胁的简单方法，因此恶意AI模型为防御人员展示了新的攻击面且需要新的缓解模式。  
  
最佳方式是确保生产工作负载仅使用安全格式下的AI模型如所谓的safetensors。他提到，“我推荐安全团队监控不安全模型的使用并与 AI 团队携手转换到 safetensors 或类似格式。”  
  
他指出，仅使用安全的AI格式，攻击面可“快速”减少，因为“这些格式旨在防御攻击者接管AI模型实例。”此外，在共享环境中运行客户模型的云提供商应当强制实施租户隔离实践，确保设法执行恶意模型的潜在攻击者无法范文其它客户或服务本身的数据。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[AI Python 包中存在缺陷 “Llama Drama” ，威胁软件供应链](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519566&idx=1&sn=991956bfd062dfe52e9fe722b821d358&chksm=ea94bc24dde335320179ca3ef8f51d217570e92946c74792f58bd0cc3104290b3db59cfa67fc&scene=21#wechat_redirect)  
  
  
[英特尔披露 AI 模型压缩软件中的严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519528&idx=1&sn=9ed9dbdab8ecbf2108523342f0297d50&chksm=ea94bc42dde33554871d71670361198896ce01f979786a3843579e0bc30cf8ca128d3449e155&scene=21#wechat_redirect)  
  
  
[RSAC 2024观察：软件供应链安全进入AI+时代](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519497&idx=1&sn=3f531af375c16bd26e01ca94f96d2f6b&chksm=ea94bc63dde33575a6c7f4e47536c932046c465934273303f37535c57d30f3fe32e5335b2de5&scene=21#wechat_redirect)  
  
  
[Hugging Face 等AI即服务平台易受严重漏洞影响，遭AI供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519250&idx=2&sn=9683638aaf21b4d1d794837ff20dd0ab&chksm=ea94bd78dde3346e88bfadb96c14584c0b4fe336e7c708699ee52db68640ead992388acf139e&scene=21#wechat_redirect)  
  
  
[开源AI框架 Ray 的0day已用于攻陷服务器和劫持资源](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519162&idx=1&sn=3872fcc82018e2c561d9e4e7574f0c8e&chksm=ea94bad0dde333c6d504e2c7680caabb4badc973dd03223bab93d5b62e5469c4db22d966adf9&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.darkreading.com/cloud-security/critical-flaw-in-replicate-ai-platform-exposes-customer-models-proprietary-data  
  
  
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
  
