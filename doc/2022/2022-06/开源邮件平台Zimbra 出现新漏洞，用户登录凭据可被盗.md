#  开源邮件平台Zimbra 出现新漏洞，用户登录凭据可被盗   
Ravie Lakshmanan  代码卫士   2022-06-15 17:58  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMS57QqGb0E8q1dEGds9lic4hcvtU20F2prcT9iaJaXTlyFxhKvtDC1mV4CqDbOQpDo0uVAWexN9tibCg/640?wx_fmt=png "")  
  
研究人员发现 Zimbra 邮件套件中又出现一个高危漏洞 (CVE-2022-27924)，如遭成功利用可导致未认证攻击者窃取用户明文密码且无需任何用户交互。  
  
  
  
研究员在报告中指出，“通过对受害者邮箱后续的访问权限，攻击者可能提升对目标组织机构的访问权限，并获得对多种内部服务的访问权限，窃取高度敏感信息。”  
  
CVE-2022-27924的CVSS评分为7.5，是“未认证请求的缓存投毒”情况，可导致攻击者注入恶意命令并嗅探敏感信息。通过投毒 Memcached 服务器中的 IMAP 路由缓存条目即可实现这一目的。该服务器用于查询 Zimbra 用户并将其HTTP请求推送给合适的后端服务。  
  
鉴于 Memcached 逐行解析进站请求，因此该漏洞可导致攻击者将特殊构造的查询请求发送给包含 CRLF 字符的服务器，导致该服务器执行非计划命令。  
  
该缺陷存在的原因是因为“换行符未在不受信任的用户输入中逃逸。该代码缺陷最终可导致攻击者从目标 Zimbra 实例中窃取用户的明文凭据。”攻击者可利用该漏洞最终损坏缓存，覆写条目，将所有的IMAP 流量转向受攻击者控制的服务器，包括目标用户的明文凭据。  
  
尽管如此，该攻击假定攻击者已经拥有受害者的邮件地址，因此能够投毒缓存条目，并使用IMAP 客户端检索邮件服务器中的邮件信息。研究人员解释称，“一般而言，组织机构使用邮件地址模式如   
{名}.{姓氏}@example.com  
。可从开源情报来源如LinkedIn 等平台获得邮件地址清单。”  
  
然而，威胁行动者可利用“响应走私”技术绕过这些限制条件，该技术需要“走私”滥用该CRLF注入缺陷的越权HTTP响应，将IMAP流量转向恶意服务器，从而在不知道邮件地址的情况下窃取用户凭据。研究人员解释称，“通过持续注入更多的响应，将项目进入Memcached共享响应流中，强制随机 Memached 查询使用被注入的响应而非正确的响应。由于Zimbra 在使用时并未验证 Memcached 响应的密钥，因此它会起作用。”  
  
研究员在2022年3月11日将漏洞报告给Zimbra，后者在2022年5月10日修复该漏洞，发布了新版本8.8.15 P31.1和 9.0.0 P24.1。  
  
Volexity 公司披露了 EmialThief 间谍活动后，研究员公开了这项研究结果。该间谍攻击活动利用Zimbra 平台上的0day 在野攻击欧洲政府和媒体实体机构。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Zimbra 软件曝新漏洞，发送恶意邮件即可劫持Zimbra 服务器](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506589&idx=3&sn=25f25b69bdec8f2533fce73ac56f0a5e&chksm=ea94ebf7dde362e1241e85a223c49542619a6898cbe740db046c3f938b8c59498d85f6f11fbf&scene=21#wechat_redirect)  
  
  
[在线阅读版：《2021中国软件供应链安全分析报告》全文](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247505380&idx=1&sn=01d2f5af200abc6bb20411ee8f17b6b5&chksm=ea94e48edde36d98f20b66aecf9f359e49226b411872bcea527fcca0a5de018f407415313800&scene=21#wechat_redirect)  
  
  
[速更新！流行的开源邮件客户端 Mozilla Thunderbird 91.3修复多个高危缺陷](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509008&idx=1&sn=1d5f73aab5f28eefa310a17cb1b41a8b&chksm=ea94957adde31c6cf9377912bd625f100b628798246e7ee1f89a7560a2570cc3bef703798e3b&scene=21#wechat_redirect)  
  
  
[Mozilla修复开源邮件客户端 Thunderbird 中的严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247486095&idx=4&sn=51dc020924c9c2082c46a12341076d0c&chksm=ea973be5dde0b2f3c89a7868634ff5a387cc49aa3f74303e8c377b6d6ded3e8304e0fe59a28b&scene=21#wechat_redirect)  
  
  
[开源邮件传输代理 Exim 易遭 RCE 和 DoS 攻击 用户应立即修复](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247485423&idx=1&sn=8e7599e60d00a9e49a9c76be679e5120&chksm=ea973685dde0bf939b87d7b19b6be3685eece5133e22018d678ec7176a5026d67715605e8d87&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2022/06/new-zimbra-email-vulnerability-could.html  
  
  
题图：  
Pixab  
ay License  
  
  
  
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
