#  谷歌OAth 漏洞导致弃用账号遭访问   
Bill Toulas  代码卫士   2025-01-17 09:51  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQzBMPIgrH4bQBUsv9hs5UQBvXOmhogEEDkOVof3mWA0OyoqGSzkYbng6gQdKnDicTX8Vl2n8oZtdw/640?wx_fmt=gif&from=appmsg "")  
  
  
**谷歌OAth ”通过谷歌登录”特性中存在一个弱点，可导致注册了已不再正常运行的创业公司域名的攻击者，访问与多个软件即服务 (SaaS) 平台相关的离职员工的敏感数据。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQzBMPIgrH4bQBUsv9hs5UQBvXOmhogEEDkOVof3mWA0OyoqGSzkYbng6gQdKnDicTX8Vl2n8oZtdw/640?wx_fmt=gif&from=appmsg "")  
  
  
该漏洞由 Trufflesecurity 公司的研究员发现并在去年9月30日报送谷歌。谷歌最初表示它只是“欺诈和滥用”问题，而非认证或登录问题。然而，Trufflesecurity公司的首席执行官兼联合创始人 Dylan Ayrey 在去年12月举办的SHmoocon 大会演示该问题后，谷歌向研究人员支付了1337美元的赏金并重开工单。  
  
不过在本文发布之时，该问题仍未修复且可被利用。谷歌的一名发言人建议客户遵循最佳实践并“正确处理域名”。这名发言人表示，“我们感谢Dylan Ayrey协助澄清客户在关闭运营时忘记删除第三方SaaS服务引发的风险。”作为最佳实践，我们建议客户按照所发相关指南正确关闭域名，阻止该问题。另外，我们建议第三方应用遵循最佳实践，使用唯一账户标识符 (sub) 来缓解这一风险。  
  
  
**底层问题**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQzBMPIgrH4bQBUsv9hs5UQNop7quGcicIkwiczgQZ3ReHicGqonYFcKm1xvmjusJPsfSleup7zibW4TA/640?wx_fmt=gif&from=appmsg "")  
  
  
  
Ayrey 在报告中将该问题描述为“谷歌的OAuth 登录并未防御有人购买失败创业公司的域名且借此为离职员工重新创建邮件账户的行为。”  
  
创建克隆邮件并无法使新的邮箱所有人访问通信平台上之前的评论，但账户可用于重新登陆多种服务如 Slack、Notion、Zoom、ChatGPT和多种人力资源平台。  
  
研究人员演示称，通过购买已失效域名和访问SaaS平台，就能够从人力资源系统提取敏感数据（税务文档、保险信息和社保号码）并登录到多种服务（如Slack、ChatGPT、Notion、Zoom）。Ayrey 查看Crunchbase 数据库中的已停用的具有已弃用域名的创业公司后发现，共有116481个可用域名。  
  
在谷歌的Oath 系统中，sub 断言旨在为每次用户登录提供唯一且不可更改的标识符，是在域名或邮件所有权发生变更后识别用户的确定性参照。不过，正如研究员解释的那样，sub 断言中的不一致性大约为0.04%，从而强制下游服务如 Slack和Notion 将其完全舍弃并仅依赖于邮件和托管的域名。  
  
该邮件断言与用户的邮件地址绑定，而托管的域名断言与域名所有权绑定，因此邮件和托管的域名均可由新的所有人继承，之后在 SaaS 平台上模仿离职员工。研究人员提到的一种解决方案是，谷歌引入不可变更的标识符，即与原始组织机构相关联的一个唯一和永久的用户ID以及一个唯一的工作空间ID。  
  
SaaS 提供商也可执行其它措施如交叉引用域注册日期、为账户访问执行管理员级别的许可，或者使用第二因素进行身份验证。然而，这些措施会带来成本、技术复杂度和登录问题。此外，它们将保护此前而非当前的付费客户，因此执行这些措施的动力不足。  
  
  
**不断增长的风险**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQzBMPIgrH4bQBUsv9hs5UQNop7quGcicIkwiczgQZ3ReHicGqonYFcKm1xvmjusJPsfSleup7zibW4TA/640?wx_fmt=gif&from=appmsg "")  
  
  
  
该漏洞影响数百万名人员和数千家企业，而且随着时间的流逝只会越来越严重。  
  
Trufflesecurity 公司在报告中表示，失败的创业公司中可能有数百万个员工账户的域名可供购买。目前，约有600万名美国人在科技创业公司工作，其中90%将在接下来的几年中注定倒闭。大约50%的企业使用适用于邮件的 Google Workspaces，因此他们的员工通过Gmail账号登录到生产力工具。  
  
用户从创业公司离职时，应确保删除账户中的敏感信息并避免使用工作账号注册个人账号，以避免后续信息遭暴露。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Fuzzing 升级：谷歌通过AI找到更多漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521578&idx=1&sn=0f7082c24d8e05dca215004ae796d61e&scene=21#wechat_redirect)  
  
  
[谷歌AI平台存在漏洞，可泄露企业的专有LLMs](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521484&idx=1&sn=19327f5e0d0275273114fd7a7e37da3f&scene=21#wechat_redirect)  
  
  
[谷歌修复已遭利用的两个安卓 0day 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521406&idx=1&sn=af981c3476e81115ffa11866a0bb7b7d&scene=21#wechat_redirect)  
  
  
[谷歌修复由苹果报送的严重 Chrome 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521342&idx=1&sn=355a1e1a938422e3437d8a957f360c7e&scene=21#wechat_redirect)  
  
  
[谷歌：三星0day漏洞已遭活跃利用](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521255&idx=3&sn=a3d253a523be442f0e1f72789ba75fb2&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/google-oauth-flaw-lets-attackers-gain-access-to-abandoned-accounts/  
  
  
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
  
