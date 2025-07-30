#  VMware 修复 Aria Operations 中的多个高危漏洞   
Ryan Naraine  代码卫士   2024-12-02 10:06  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**上周二，VMware 修复了位于产品 Aria Operations 中的至少5个安全漏洞。**  
  
VMware 在这云IT运维平台上发现了五个漏洞，并提醒用户称恶意黑客可构造 exp，实现提权或发动XSS攻击。  
  
VMware 发布 VMSA-2024-0022 安全公告提到：  
  
- CVE-2024-38830：提权漏洞（CVSS 7.8），具有本地管理员权限的人员可在该设备获得root访问权限。  
  
- CVE-2024-38831：本地提权漏洞（CVSS评分7.8），可将恶意命令插入属性文件，将权限提升至root。  
  
- CVE-2024-38832：存储型XSS漏洞（CVSS评分7.1），对视图具有编辑权限的用户可注入恶意脚本，导致XSS。  
  
- CVE-2024-38833：存储型XSS（CVSS评分6.8），对邮件模板具有编辑权限的恶意人员可注入恶意脚本，导致XSS。  
  
- CVE-2024-38834：存储型XSS（CVSS评分6.5）。对晕提供商具有编辑权限的恶意人员可注入恶意脚本，导致XSS。  
  
  
  
VMware 表示这些漏洞影响 VMware Aria Operations（8.x版本）和VMware Cloud Foundation（使用 Aria Operations 的4.x 和 5.x版本）。  
  
因不存在应变措施，建议企业用户尽快应用补丁。VMware 虚拟化技术产品一直以来是高阶黑客组织的重大目标。CISA 必修清单中纳入多个VMware 缺陷，其中至少一个位于VMware Aria Operations 中。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[补丁不给力，VMware vCenter 严重RCE漏洞遭利用](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521523&idx=1&sn=286f99df03f25ebd1cb1fb497f991b21&scene=21#wechat_redirect)  
  
  
[关于VMware vCenter Server存在堆溢出漏洞的安全公告](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521255&idx=2&sn=96000770c62b8decfa9e07a493e63e88&scene=21#wechat_redirect)  
  
  
[VMware 修复HCX 平台上可导致RCE的高危SQLi 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521136&idx=2&sn=092bf2813ecefa63156a83b9d8eab160&scene=21#wechat_redirect)  
  
  
[博通修复 VMware vCenter Server 中的严重RCE漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520848&idx=2&sn=d95814f9037c7711dfcb09cd0e590f0c&scene=21#wechat_redirect)  
  
  
[VMware 修复Fusion中的高危代码执行漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520668&idx=3&sn=899efb652a40601d77b2cb2fffa9e4a2&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.securityweek.com/vmware-patches-high-severity-vulnerabilities-in-aria-operations/  
  
  
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
  
