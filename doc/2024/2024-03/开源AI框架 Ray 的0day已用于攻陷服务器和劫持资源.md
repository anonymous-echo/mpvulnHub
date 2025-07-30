#  开源AI框架 Ray 的0day已用于攻陷服务器和劫持资源   
Bill Toulas  代码卫士   2024-03-27 17:14  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**名为 “ShadowRay” 的攻击活动利用热门开源 AI 框架 Ray 中的0day 从数千家公司劫持算力并泄露敏感数据。**  
  
  
  
Oligo 公司发布报告称，攻击至少始于2023年9月5日，针对的是教育、密币、生物制药等行业。Ray 是一款由 Anyscale 开发的开源框架，用于扩展机器集群中的AI和 Python 应用以分发计算工作负载。该框架在 GitHub 上的star 数量超过3.05万颗，用于全球很多组织机构中，包括亚马逊、Spotify、LinkedIn、Instacart、Netflix、Uber 和 OpenAI，以训练ChatGPT。  
  
  
**已遭活跃利用**  
  
  
  
  
  
2023年11月，Anyscale 披露了5个 Ray 漏洞，并修复了其中的4个，包括 CVE-2023-6019、CVE-2023-6020、CVE-2023-6021和CVE-2024-48023。  
  
不过该公司并未修复第5个漏洞即严重的RCE漏洞 (CVE-2023-48022)，原因是缺乏认证是一个长期存在的设计决策。AnyScale 在安全公告中提到，“剩下的CVE漏洞是Ray不具有内置认证的，它是基于 Ray 安全边界如何划定以及Ray部署最佳实践的方式做出的长期设计决策，尽管如此，我们会在未来的版本中提供认证，作为纵深防御战略的一部分。”  
  
具体而言，AnyScale 表示该漏洞仅在违反了该项目文档中提到的仅限在严格受控的网络环境中使用Ray的建议时，才可在部署中遭利用。另外，该公司认为这些缺陷并非漏洞而是bug，因为平台的设计就是作为分布式执行框架来执行代码。不管该缺陷的分类如何，缺少认证已为黑客提供了在不安全环境中利用该漏洞的机会。Oligo 公司在报告中提到，“因为 CVE-2023-48022存在争议，很多部署团队（以及多数静态扫描工具）并未发现应重视该漏洞。其中一些团队或工具可能错过了Ray文档的这部分内容，其他人或工具可能并未发现这一特性。我们已发现该漏洞遭在野利用的迹象，因此这个受争议的CVE成为‘影子漏洞’，即它并不会出现在静态扫描中，但仍然可导致攻陷和重大损失。”  
  
Oligo 公司表示，数百台公开暴露的 Ray 服务器遭该漏洞利用攻陷，可导致攻击者访问敏感信息包括AI模型、环境变量、生产数据库凭据以及云环境访问令牌。在一些案例中，研究人员观察到攻击者利用对机器学习训练中强大显卡的访问权限，从事密币（门罗币）的挖掘。其他人利用反向 shell 获得对受陷环境的持久性，通过Python的伪终端执行任意代码。研究人员还调查了 base64 编码 payload，发现VirusTotal 中的任何AV 引擎均未能发现使用开源脚本在受陷机器提升权限的行为。  
  
  
**对抗 ShadowRay**  
  
  
  
  
  
研究人员提到已经提醒很多受陷企业并提供修复协助。  
  
要保护Ray部署的安全性，通过执行防火墙规则、向 Ray 仪表盘端口增加授权并持续监控异常情况等方式在安全环境中进行操作至关重要。另外应当避免使用默认设置如绑定到0.0.0.0，而使用增强集群安全态势的工具。  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[“会话溢出”网络攻击绕过 AI 安全攻击企业高管](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519109&idx=2&sn=238a3481491209e1b525c85f973cf79a&chksm=ea94baefdde333f968d204a3da4718f7c4bab621707765d841725198047d069df315cd196b26&scene=21#wechat_redirect)  
  
  
[研究员开发出AI蠕虫，可在AI系统之间自动传播](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518984&idx=1&sn=84deee6f57e994f428b1dbca62279d53&chksm=ea94ba62dde3337458316504b214849fc60dfd4cc21d2fd7b4dfd2fdd0cc9ff85379a181dcb7&scene=21#wechat_redirect)  
  
  
[FTC 推出AI声音克隆欺诈检测挑战赛，最高奖励2.5万美元](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518605&idx=1&sn=c8c3d169df7d9f5cd0e5774f7cbc6604&chksm=ea94b8e7dde331f1486b4d70993075d7bb5fbb6179f07728d8b4316acc83c2b07c5ae19d2780&scene=21#wechat_redirect)  
  
  
[OpenAI 推出的 ChatGPT 数据泄露漏洞补丁不完整](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518467&idx=1&sn=e62b48f443aac09cc258fee8e9f2f03f&chksm=ea94b869dde3317f2f82e352111b9ddd5f046149bd1cf6e3f8ba4457dcf2943c2bee4d51943d&scene=21#wechat_redirect)  
  
  
[FTC 推出AI声音克隆欺诈检测挑战赛，最高奖励2.5万美元](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518605&idx=1&sn=c8c3d169df7d9f5cd0e5774f7cbc6604&chksm=ea94b8e7dde331f1486b4d70993075d7bb5fbb6179f07728d8b4316acc83c2b07c5ae19d2780&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/hackers-exploit-ray-framework-flaw-to-breach-servers-hijack-r  
esources/  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
