> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523414&idx=2&sn=35dbec1ac12ce977cb52bd37b9d9860a

#  MongoDB 服务器预认证漏洞可用于触发 DoS 条件  
Kaaviya  代码卫士   2025-07-01 11:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**MongoDB Server 6.0、7.0和8.0发布分支的多个版本受严重的预认证拒绝服务漏洞CVE-2025-6709的影响。**  
  
该漏洞是因为该服务器的 OpenID Connect (OIDC) 认证机制中的输入验证不当造成的，可导致攻击者在无需认证凭据的情况下破坏数据库实例。  
  
该漏洞的CVSS评分为7.5，属于高危级别，对在生产环境中运行易受攻击 MongoDB 部署的组织机构造成重大风险。  
  
  
**MongoDB DoS 漏洞**  
  
  
  
该漏洞归类于 CWE-20（输入验证不当），利用的是 OIDC 认证流程中对 JSON payload 中的特定数据值处理存在的问题。攻击者能够利用 MongoDB (mango) 传输特殊构造的恶意 JSON 数据，触发 invariant 失败条件，最终导致服务器完全崩溃。  
  
该安全机制绕过传统的认证请求，因此尤其危险，因为它可导致未认证远程攻击者破坏数据库操作。该漏洞的技术根因涉及对 OIDC 认证管道中日期格式的输入数据的清理和验证不当。当 MongoDB 服务器处理这些数据值时，解析逻辑遇到异常的违反内部假设的异常数据结构，导致服务器流程异常终止。  
  
该漏洞是一个典型的输入验证漏洞，边界检查和数据类型验证不充分制造了可利用的条件。该漏洞影响严重级别不等的三大 MongoDB Server 发布分支。  
  
MongoDB Server 早于v7.0.17的7.0版本以及早于8.0.5的8.0版本易受预认证利用影响，可导致完全未认证的攻击者远程触发拒绝服务条件。MongoDB 早于6.0.21的6.0版本中也包含该漏洞，不过利用该漏洞要求成功认证，从而降低了威胁面，但仍然遭受认证用户带来的风险。  
  
运行这些易受攻击版本的用户面临潜在的服务中断问题，尤其是在高可用性环境中更是如此，因为在这种环境中，数据库宕机直接影响业务运营。基于网络的攻击向量，加上攻击复杂度低，导致漏洞对于面向互联网的 MongoDB 部署或者通过受陷网络分段访问的部署而言，尤其令人担心。  
  
  
**缓解措施**  
  
  
  
MongoDB 在安全公告中提到，安全团队应当优先立即对最新的稳定版打补丁：MongoDB 6.0.21、7.0.17或8.0.5，具体取决于当前的部署版本。  
  
无法部署补丁的组织机构应当考虑执行网络级别的访问控制，应暂时禁用对于运营并非关键的 OIDC 认证，或者部署能够过滤恶意 JSON payload 的 web 应用防火墙。  
  
该漏洞的预认证性质使其成为威胁人员的香饽饽，因为无需复杂攻击技术就能破坏数据库服务。数据库管理员应当监控异常连接模式，围绕OICD身份验证建立全面的日志记录，并在发现潜在的利用尝试之后建立快速服务恢复的事件响应程序。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[MongoDB库中存在多个漏洞，可用于在Node.js服务器上实现RCE](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522334&idx=2&sn=474bb8a99d7a850a95b1ba847ff41044&scene=21#wechat_redirect)  
  
  
[MongoDB 证实被黑，客户数据被盗](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518402&idx=2&sn=e0b6f6d8b89ce610fc6fce3432021ea2&scene=21#wechat_redirect)  
  
  
[Spring Data MongoDB SpEL表达式注入漏洞安全风险通告第二次更新](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512551&idx=3&sn=1d82552fab1461f66ca02457161cf83b&scene=21#wechat_redirect)  
  
  
[不安全的 MongoDB 数据库爆出大秘密：俄政府拥有访问在俄企业的后门账户](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489157&idx=1&sn=ffae4c8c39b319aa67c2f4bcaacf8228&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://cybersecuritynews.com/mongodb-server-pre-authentication-vulnerability/  
  
  
  
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
  
