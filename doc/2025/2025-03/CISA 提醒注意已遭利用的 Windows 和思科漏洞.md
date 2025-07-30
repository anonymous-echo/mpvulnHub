#  CISA 提醒注意已遭利用的 Windows 和思科漏洞   
Sergiu Gatlan  代码卫士   2025-03-04 17:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**CISA 提醒美国联邦机构保护系统免受利用思科和Windows 系统漏洞的攻击。**  
  
CISA 已将这些漏洞标记为已遭在野利用，不过尚未提供关于该恶意活动及其幕后黑手的具体详情。  
  
第一个漏洞 (CVE-2023-20118) 可导致攻击者在 RV016、RV042、RV042G、RV082、RV320和RV 325 VPN路由器上执行任意命令。虽然实施攻击要求有效的管理员凭据，但可通过组合利用CVE-2023-20025认证绕过漏洞获得root权限。思科在2023年1月份发布安全公告并在一年后更新称，其产品安全事件响应团队 (PSIRT) 注意到CVE-2023-20025公开可用的概念验证利用代码。  
  
第二个漏洞 (CVE-2018-8639) 是 Win32k 提权漏洞。登录到目标系统的本地攻击者能够利用该漏洞在内核模式下运行任意代码。成功利用漏洞可导致以完整的用户权限修改代码或创建恶意账户，接管易受攻击的 Windows 设备。微软在2018年12月发布安全公告提到，该漏洞影响客户端（Windows 7或后续版本）以及服务器（Windows Server 2008及后续版本）平台。  
  
目前，CISA 将这两个漏洞纳入其必修漏洞清单中。CISA提到，“这些漏洞是恶意网络分子常用的攻击向量，为联邦企业带来严重风险。”微软和思科之后并未更新安全公告。2月初，CISA还表示，位于Outlook 中的一个严重RCE漏洞 (CVE-2024-21413) 正遭利用并要求联邦机构在2月27日之前修复系统。  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[CISA：Craft CMS代码注入漏洞已遭利用](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522334&idx=3&sn=f5c15f723d85e58e935d673891c323e3&scene=21#wechat_redirect)  
  
  
[FBI、CISA和NSA公布2023年利用最频繁的15个漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521484&idx=2&sn=719611812a4cbf91cb5c976ad2da4620&scene=21#wechat_redirect)  
  
  
[CISA 提出安全新要求，保护政府和个人数据安全](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521255&idx=1&sn=7f84e630c55856e76ec9a0e7b2ec0166&scene=21#wechat_redirect)  
  
  
[CISA：黑客滥用F5 BIG-IP cookie 映射内部服务器](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521056&idx=1&sn=87bda00602d2d1a2718a0d4d0aef6585&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/cisa-tags-windows-and-cisco-vulnerabilities-as-actively-exploited/  
  
  
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
  
