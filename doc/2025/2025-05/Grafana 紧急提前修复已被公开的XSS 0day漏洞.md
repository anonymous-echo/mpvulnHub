#  Grafana 紧急提前修复已被公开的XSS 0day漏洞   
Ddos  代码卫士   2025-05-23 10:34  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Grafana Labs 披露了计划之外的安全发布，修复了一个高危XSS漏洞CVE-2025-4123（CVSS评分7.6）。**  
  
该XSS漏洞结合了一个客户端路径遍历漏洞和自定义前端插件中的一个开放重定向漏洞。该漏洞可导致攻击者将不知情的用户重定向至执行任意 JavaScript 代码的恶意网站，有可能劫持会话甚至导致账户遭完全接管。  
  
Grafana 发布安全公告指出，“该XSS漏洞可导致用户被重定向至外部网站并在浏览器中执行恶意 JavaScript。”和常见的需要编辑级别权限的XSS漏洞不同，只要启用了匿名访问权限，无需认证，CVE-2025-4123即可遭利用。另外，如果安装了 Grafana Image Renderer 插件，攻击面会扩展到完全的读取服务器端请求伪造 (SSRF) 场景。该安全公告提到，“和许多其它的XSS漏洞不同，该漏洞无需编辑者权限。如启用了匿名访问权限，则会启动XSS。”  
  
该漏洞影响所有受支持的 Grafana 版本，包括：Grafana 11.2至12.0版本，以及追溯至Grafana 8的所有不受支持汉本。值得注意的是，Grafana Cloud 用户不受影响。  
  
Grafana Labs迅速行动缓解该问题。尽管例行的补丁周期按计划在当地时间5月22日发布，但由于该漏洞遭公开披露，因此Grafana 提前一天推出修复方案。该安全公告提醒称，“我们在计划的前一天公开了CVE-2025-4123的安全补丁，因为我们发现该漏洞已遭公开。”  
  
建议用户立即升级 Grafana 版本，或者启用严格的内容安全策略，助力缓解该风险。Grafana Labs已提供官方 CSP 配置指南，以加固部署。管理员应立即采取措施，修复受影响系统并审计访问权限和插件配置。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Grafana 提醒注意严重的认证绕过漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516818&idx=4&sn=9a52564b1d6d8454dd34dce86019d266&scene=21#wechat_redirect)  
  
  
[Grafana 漏洞可导致管理员账户遭接管](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513049&idx=1&sn=31af4654137f918dc610ee51cf05649a&scene=21#wechat_redirect)  
  
  
[Grafana 中存在严重的未授权任意文件读取漏洞，已遭利用](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509616&idx=2&sn=27c5f9e457a2c2aa08753d9d0a67917e&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/critical-flaw-allows-remote-hacking-of-automationdirect-industrial-gateway/  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
