#  Jenkins 修复CSRF和开放重定向等多个漏洞   
do son  代码卫士   2025-03-07 18:06  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**热门开源自动化服务器Jenkins 发布安全公告修复多个漏洞，其中包括加密机密泄露和跨站请求伪造 (CSRF) 漏洞。**  
  
该安全公告在2025年3月5日发布，它详述了影响 Jenkins 2.499及之前版本和 LTS 2.492.1及之前版本的三个漏洞。在这三个漏洞中，最严重的是CVE-2025-27622，可导致具有“Agent/Extended 读权限的攻击者查看机密的加密值”。该漏洞是因为在通过 REST API 或 CLI 访问代理配置时未能编辑加密机密时造成的。  
  
第二个漏洞CVE-2025-27623与上述漏洞类似，影响视图配置，可导致“具有查看/读取权限的攻击者查看机密的加密值”。  
  
第三个漏洞是CSRF 漏洞CVE-2025-27642，影响2.500和LTS 2.492.2 版本，可导致攻击者“切换侧边栏工具的 collapsed/expanded 状态”，并可能在受害者的用户资料中存储受攻击者控制的内容。  
  
Jenkins 已在版本2.500和LTS 2.492.2中修复了这些漏洞。强烈建议用户将Jenkins 实例更新至最新版本以缓解这些安全风险。该公告还详述了一个开放重定向漏洞CVE-2025-27625，可导致攻击者执行钓鱼攻击。建议Jenkins 用户和管理员查看完整的安全公告并采取必要措施保护系统安全。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[CISA：严重的 Jenkins 漏洞已被用于勒索攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520541&idx=2&sn=c8001046f4088bb94fd3ffcd7e6926b0&scene=21#wechat_redirect)  
  
  
[Jenkins 出现严重漏洞，可导致代码执行攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515862&idx=2&sn=559cb44fa0529b875f5361b1112c5b60&scene=21#wechat_redirect)  
  
  
[Jenkins 披露插件中未修复的XSS、CSRF等18个0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513380&idx=3&sn=643da5e5ad5ec30250e2a3e9dca17e51&scene=21#wechat_redirect)  
  
  
[Jenkins 披露多个组件中的29个未修复0day](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512696&idx=1&sn=5cc055e6e0d20676ecdd7c4f69dbef58&scene=21#wechat_redirect)  
  
  
[Jenkins 内部服务器遭访问且被部署密币挖机](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247507695&idx=3&sn=3890bec24dc2bb2e4b44e15b7968ed68&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://securityonline.info/csrf-and-open-redirect-jenkins-patches-major-vulnerabilities/  
  
  
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
  
