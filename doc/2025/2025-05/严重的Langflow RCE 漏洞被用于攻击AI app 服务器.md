#  严重的Langflow RCE 漏洞被用于攻击AI app 服务器   
Bill Toulas  代码卫士   2025-05-07 10:07  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTTMhmvKE2iaicmgDxxvQAzfWviaYFhjcoUmlzPlXmh9AF597SPdHuXiaiahicTxWqhjsrjiaIReD9yZfDkQ/640?wx_fmt=png&from=appmsg "")  
  
  
**美国网络安全和基础设施安全局 (CISA) 将Langflow RCE漏洞标记为已遭利用，督促组织机构尽快应用安全更新和缓解措施。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTTMhmvKE2iaicmgDxxvQAzfWR1mT8IVCqiaWHN01PgQc7sy2T0qibr10scw1yMFBgdQPXVYq7C4EQBJw/640?wx_fmt=png&from=appmsg "")  
  
  
该漏洞的编号是CVE-2025-3248，是一个严重的未认证RCE漏洞，可导致互联网上的任何攻击者通过利用一个API端点漏洞的方式，完全控制易受攻击的 Langflow 服务器。  
  
Langflow 是一款开源的可视化编程工具，通过LangChain 组件可构建受LLM驱动的工作流。Langflow 提供一个拖拽界面，无需编写完整的后端代码即可创建、测试和部署AI代理或管道。该工具在 GitHub 上已有近6万颗星和6300个分叉，供AI开发人员、研究人员和创业公司用作原型聊天机器人、数据管道、代理系统和AI 应用。  
  
Langflow暴露了旨在验证由用户提交的代码的端点 (/api/v1/validate/code)。在易受攻击的版本中，该端点并未安全地进行沙箱处理或清理输入，导致攻击者可向该端点发送恶意代码，并在服务器上直接执行。  
  
该漏洞已在2025年4月1日发布的1.3.0版本中修复，因此建议用户升级至该版本或后续版本，缓解相关风险。补丁很小，仅需为易受攻击的端点增加认证即可，并不涉及沙箱或加固。  
  
最新 Langflow 版本1.4.0已发布，并包含一长串修复，因此用户应升级至该版本。Horizon3 公司的研究人员在2025年4月9日发布了该漏洞的深入分析，并提醒称该漏洞遭利用的可能性很高，当时提到至少有500个被暴露在互联网中的实例。  
  
用户如无法立即升级至安全版本，则建议通过防火墙、认证反向代理或VPN等方式限制对Langflow的网络访问权限。另外，不要直接暴露在互联网中。CISA 要求联邦机构在2025年5月6日之前应用安全更新或缓解或停止使用该软件。CISA 并未透露所述利用活动的详情，并表示目前尚不清楚该漏洞是否已遭勒索团伙利用。  
  
Langflow 的用户应注意的是，该工具在权限隔离方面设计不佳，没有沙箱，因其本身和预期功能而“设计”的RCE漏洞由来已久。该漏洞是位于Langflow中的首个真正的未认证RCE漏洞，而鉴于该漏洞已遭利用，因此用户应立即采取行动。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[苹果 “AirBorne” 漏洞可导致零点击 AirPlay RCE 攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522916&idx=2&sn=1292db15893e34108514b0dc4437e9f7&scene=21#wechat_redirect)  
  
  
[Craft CMS RCE利用链用于窃取数据](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522866&idx=1&sn=f8c7ca3a1ba46ce90b3df18909d4b5b4&scene=21#wechat_redirect)  
  
  
[PyTorch 中存在严重的RCE漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522801&idx=2&sn=92cd7620a74a8d5e609a3bd300ef2a66&scene=21#wechat_redirect)  
  
  
[Ingress NGINX 控制器中存在严重漏洞可导致RCE](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522579&idx=2&sn=df3fca1672e67390925fdec6d6a9c0b7&scene=21#wechat_redirect)  
  
  
[速修复！Erlang/OTP SSH 中存在严重的预认证 RCE](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522791&idx=1&sn=b726626262a08aef9a0f09bf3d3332e0&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/critical-langflow-rce-flaw-exploited-to-hack-ai-app-servers/  
  
  
  
题图：  
Pixabay Licen  
se  
  
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
  
