> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523425&idx=1&sn=d86d65a64846ff68a79a294116423c60

#  CISA 提醒注意 Microsens 中的多个严重漏洞  
Eduard Kovacs  代码卫士   2025-07-02 10:21  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**德国光纤传输系统和楼宇自动化解决方案制造商 Microsens 制造的产品中受多个严重漏洞影响，可用于远程攻击组织机构。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTCkia0aOjhR9tSX2uZhRYAk5Xarz5mgd5xPD7BSLhoBN1E6Uc0Nkiaib5icChMpHUykGgu6vVkWILh6Q/640?wx_fmt=png&from=appmsg "")  
  
  
Microsens 为工业组织机构和企业提供广泛的连接和自动化解决方案，包括交换机、变频器、楼宇控制器和收发器。该公司 NMP Web+ 产品可使用户通知、监控和配置工业交换机和其它 Microsens 网络设备。  
  
CISA 上周发布安全公告表示，Microsens NMP Web+ 产品受两个严重漏洞和一个高危漏洞的影响。未认证攻击者可利用这些严重漏洞生成伪造的 JSON Web Tokens 并绕过认证 (CVE-2025-49151)，以及覆写文件和执行任意代码 (CVE-2025-49153)。该高危漏洞与 JSON Web Tokens 未过期的事实有关。  
  
Claroty 公司 Team82团队的漏洞研究员 Noam Moshe 发现了这些漏洞，他们表示攻击者可组合利用这些漏洞。第一个漏洞可用于获取向目标系统提供访问权限的合法认证令牌，第二个漏洞可使攻击者覆写服务器上的关键文件，完全控制 OS 级别的系统。  
  
Moshe 解释称，组合利用这两个漏洞可使攻击者完全控制系统，无需拥有任何服务器相关前置知识或凭据。他提到，攻击者需要访问与目标 Microsens NMP Web+ 实例相关联的 web 服务器访问权限来利用这些漏洞，但提醒称多个实例被暴露到互联网并可能易受攻击。  
  
CISA 表示并未发现这些漏洞遭利用的迹象，厂商已发布补丁修复这些漏洞（Windows 和 Linux 为3.3.0版本）。CISA 表示，受影响产品广泛用于全球各行业，其中不乏关键制造业。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[CISA和FBI联合发布关于减少现代软件开发中内存安全漏洞的指南](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523387&idx=2&sn=51d9faa28849e3f10c23498b89c880d0&scene=21#wechat_redirect)  
  
  
[CISA 将TP-Link 路由器高危漏洞纳入KEV](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523309&idx=2&sn=d3e035c89c35c26ad0a1cad90861ac97&scene=21#wechat_redirect)  
  
  
[CISA将Erlang SSH 和 Roundcube 加入KEV清单](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523250&idx=2&sn=245cd6553dde79a725f1afe15893f164&scene=21#wechat_redirect)  
  
  
[CISA提醒注意已遭利用的 Commvault 0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523124&idx=1&sn=1a8e46e871f1fae51bb1c752be774842&scene=21#wechat_redirect)  
  
  
[NIST、CISA联合提出漏洞利用概率度量标准](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523082&idx=2&sn=4d5a25d58482d98bdb3b13320e03bb92&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/critical-microsens-product-flaws-allow-hackers-to-go-from-zero-to-hero/  
  
  
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
  
