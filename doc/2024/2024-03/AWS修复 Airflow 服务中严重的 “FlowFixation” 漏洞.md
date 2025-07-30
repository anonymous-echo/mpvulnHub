#  AWS修复 Airflow 服务中严重的 “FlowFixation” 漏洞   
THN  代码卫士   2024-03-25 17:29  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**网络安全研究员发布了位于AWS 的Apache Airflow 的工作流管理 (MWAA) 中的一个已修复漏洞详情，它可导致恶意人员劫持受害者会话并在底层实例上实现远程代码执行后果。**  
  
  
该漏洞被 Tenable 公司命名为 “FlowFixation”。该公司的高级安全研究员 Liv Matan 在技术分析文章中提到，“接管受害者账户后，攻击者本可执行多项任务如读取连接字符串、增加配置并触发有向无环图 (DAGS)。在某些条件下，这些操作可导致MWAA的基础、横向移动到其它服务的实例上实现RCE。”  
  
该漏洞的根因在于AWS MWAA的web管理面板上的会话固定和可导致XSS攻击的AWS 域名错误控制问题。会话固定是一种 web 攻击技术，当用户在无需验证任何已有会话标识符的情况下认证到某服务时就会发生。该漏洞可导致攻击者将已知会话标识符强制（即固定）到用户上，一旦用户认证，则攻击者能够访问认证会话。  
  
攻击者可利用该漏洞强迫受害者使用并认证攻击者的已知会话并最终接管受害者的web管理面板。Matan 表示，“FlowFixation 强调了云提供商域架构和管理当前状况中更加广泛的问题，因为它与公共后缀列表 (PSL) 和共享父域有关：同站攻击。”  
  
研究人员还提到，共享架构可成为利用同站攻击、跨域问题、cookie tossing等的攻击者的金矿，从而导致越权访问、数据泄露和代码执行后果。  
  
该漏洞已修复。AWS 和 Azure 将配置不当的域名增加到PSL，从而使web浏览器将所增加域名识别为公开后缀。谷歌 Cloud 认为该问题“不够严重”并未推出修复方案。Matan 解释称，“在同站攻击中，所述域架构的安全影响重大，对于云环境的影响尤甚。其中，cookie-tossing 和同站绕过cookie 防护策略，更为严重，因为它们都能绕过CSRF防御措施。Cookie-tossing攻击也可滥用会话固定问题。”  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Telegram 和 AWS等电商平台用户遭供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517920&idx=2&sn=9b81bba53ca92b9dba48012df9a9d2cb&chksm=ea94b78adde33e9c5b9a7a2184d0c433e97efba3d73c58471d585199cd6d4d88409f7bd57770&scene=21#wechat_redirect)  
  
  
[多租户AWS漏洞暴露账户资源](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514718&idx=1&sn=171e74c0abec3a1060332412667c59e2&chksm=ea948b34dde302221841c5c6fc01ccda3bf10122f733119c7dc0a8393f19753e6b8a66979946&scene=21#wechat_redirect)  
  
  
[适用于Kubernetes 的AWS IAM 验证器中存在漏洞，导致提权等攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512889&idx=4&sn=bd3623a8d3f38a4206124b8681f1c510&chksm=ea948253dde30b457da57e1cfc42ab6fc1b7c06335250b93b2f6b89654f0b83884057e98fbd5&scene=21#wechat_redirect)  
  
  
[PyPI 仓库中的恶意Python包将被盗AWS密钥发送至不安全的站点](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512575&idx=2&sn=5af81a53d9263bf10273d86868a77287&chksm=ea948095dde309830949a85914d18a896ce49535f37a9c0cf802e2d84d4dbf264c0e5795396b&scene=21#wechat_redirect)  
  
  
[热门PyPI 包 “ctx” 和 PHP库 “phpass” 长时间未更新遭劫持，用于窃取AWS密钥](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511966&idx=1&sn=77856cc7ec3f5318efb4f18f2a8ddf66&chksm=ea949ef4dde317e2a06b85bfc4ca7d162951708a197fc45a2b94119ddf30e4457c29386705b2&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://thehackernews.com/2024/03/aws-patches-critical-flowfixation-bug.html  
  
  
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
  
