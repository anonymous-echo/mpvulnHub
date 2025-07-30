#  Windows 内核漏洞已被用于获取系统权限   
Sergiu Gatlan  代码卫士   2024-12-17 10:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**CISA 提醒美国联邦机构保护系统免受一个高危Windows 内核漏洞 (CVE-2024-35250) 的影响。**  
  
  
  
  
该漏洞是因为一个不受信任的指针解引用弱点引发的。该弱点可导致本地攻击者无需用户交互，就能在复杂度低的攻击中获取系统权限。虽然微软并未在6月份发布的一份安全公告中分享更多详情，但发现该漏洞的 DEVCORE 研究团队提到，该易受攻击的系统组件是“微软内核流服务 (Microsoft Kernel Streaming Service (MSKSSRV.SYS)”。  
  
在今年举行的 Pwn2Own 温哥华黑客大赛的第一天，研究人员利用该MSKSSRV 的提权漏洞攻陷了已完全修复的 Windows 11系统。微软在2024年6月补丁星期二中修复了该漏洞，并在四个月后出现了PoC利用。微软在一份尚未更新的未说明该漏洞已遭活跃利用的安全公告中提到，“成功利用该漏洞的攻击者可获得系统权限。”  
  
另外，CISA还将Adobe ColdFusion 中的一个严重漏洞 (CVE-2024-20767) 纳入必修清单。Adobe 在3月份修复了该漏洞，之后已有多份 PoC 利用在网络公开。CVE-2024-20767是因访问控制不当弱点造成的，可导致未认证的远程攻击者读取系统和其它敏感文件。SecureLayer7 公司提到，成功利用管理面板被暴露在网络的 ColdFusion 服务器也可导致攻击者绕过安全措施并执行任意文件系统写。Fofa 搜索引擎跟踪了超过14.5万台暴露在互联网中的 ColdFusion 服务器，不过无法定位到管理面板可遭远程访问的确切的服务器。  
  
CISA将这两个漏洞同时纳入必须清单，将其标记为已遭活跃利用状态。按照BOD22-01的要求，联邦机构必须在三周内即1月6日前保护其网络安全。  
  
CISA提到，“这种类型的漏洞是恶意网络人员的常见攻击向量，对联邦企业造成重大风险。”虽然CISA主要对联邦机构提供漏洞告警，但建议私有组织机构也优先缓解这些漏洞，以拦截正在进行的攻击活动。  
  
微软尚未就CVE-2024-35250遭在野利用的情况置评。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[俄黑客组织 RomCom 被指利用火狐和Windows 0day攻击用户](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521617&idx=1&sn=cc6372f588d0fbc52027797f7d23ae53&scene=21#wechat_redirect)  
  
  
[Copy2Pwn 0day 被用于绕过 Windows 防护措施](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520517&idx=2&sn=3f8deb775a5743e1c32954859fa214e4&scene=21#wechat_redirect)  
  
  
[Telegram 修复Windows 版中的0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519289&idx=2&sn=4c3fb5e7519056c3adfbd18c7a6561d3&scene=21#wechat_redirect)  
  
  
[Lazarus黑客利用Windows内核0day发动攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518970&idx=2&sn=ea8bb2c114507ab3f98fa4427698219b&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/windows-kernel-bug-now-exploited-in-attacks-to-gain-system-privileges/  
  
  
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
  
