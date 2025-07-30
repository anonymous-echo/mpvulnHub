#  VMware 修复 vRealize 网络分析工具中的严重漏洞   
Sergiu Gatlan  代码卫士   2023-06-08 17:52  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
****  
**VMware 发布了多个补丁，修复了位于 VMware Aria Operations for Networks 中的多个严重和高危漏洞，它们可导致攻击者获得远程执行或访问敏感信息的权限。**  
  
  
  
  
VMware Aria Operations for Networks 此前被称为 vRealize Network Insight (vRNI)，旨在帮助管理员优化网络性能或管理并扩展多种 VMware 和 Kubernetes 部署。  
  
在今天所修复的三个漏洞中，其中最严重的是命令注入漏洞 (CVE-2023-20887)，可被未认证威胁行动者用于无需用户交互的复杂度低的攻击中。VMware 公司指出，“具有对VMware Aria Operations for Networks 网络访问权限的恶意人员或能够执行命令注入攻击，从而导致远程代码执行后果。”  
  
修复的第二个漏洞是CVE-2023-20888，可导致攻击者在未修复的 Aria Operations 设备上执行远程代码，是经验证的反序列化弱点。和CVE-2023-20887一样，该漏洞也要求对易受攻击的设备具有网络访问权限和有效的“成员”角色凭据才能执行导致远程代码执行的反序列化攻击。  
  
VMware 修复的第三个漏洞是信息泄露漏洞CVE-2023-20889，它可使恶意人员执行命令注入攻击，访问敏感信息。  
  
  
**无应变措施**  
  
  
VMware 公司白哦是，不存在可删除该攻击向量的应变措施，因此管理员必须修复所有本地版 VMware Aria Operations Networks 6.x 设备，防御攻击。  
  
用户可通过 VMware 的客户连接网站查看所有易受攻击的 Aria Operations for Networks 的补丁。同时，该公司还共享了关于应用这些补丁的程序详情，要求用户下载更新补丁文件，以 vRNI GUI 已登录管理员用户的身份上传，并从设置＞安装和支持＞查看和更新设置来安装这些补丁。  
  
4月份，VMware 公司还修复了一个严重漏洞，可导致攻击者以 root 身份在 vRealize Log Insight 日志分析工具上运行代码。  
  
几个月前，Horizon3 Attack Team 发布了同样的 VMware 产品中的多个严重漏洞的 PoC 代码，而这些产品在一周前才刚刚修复。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[VMware 修复在 Pwn2Own 大赛上发现的两个严重0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516346&idx=1&sn=260aa87f75279d3101ddc11e8e48ee81&chksm=ea94b1d0dde338c6aa50da46b3651794726cdf0d14752bb2a5af194367089da4bfa90355660d&scene=21#wechat_redirect)  
  
  
[VMware 修复严重的 vRealize 反序列化漏洞，可导致任意代码执行](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516298&idx=2&sn=1625888e8762acc4a48a665717933497&chksm=ea94b1e0dde338f62127926fd478fb71059387a0ae20c0fd3e0d9c2f4c6405f946351edeb454&scene=21#wechat_redirect)  
  
  
[VMware 修复严重的Carbon Black App Control漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515674&idx=1&sn=a2545f99534c8c181bb5022bbc3989e1&chksm=ea948f70dde306661e8a7532ffad9fe411f3cd1cbcb74c5ae58c6e4f394d04247cb807e3ce08&scene=21#wechat_redirect)  
  
  
[VMware Workstation中存在高危的提权漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515478&idx=3&sn=6fb6defbf6e53fa69b775f37bed7bbfd&chksm=ea948c3cdde3052a630422bf457d44f24d36236b6ca666929b3ab6ce6cf3774fc646a1dde7ca&scene=21#wechat_redirect)  
  
  
[VMware 修复严重的ESXi和vRealize 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515027&idx=2&sn=d86995b203eb6824e5179dc7d57b8bce&chksm=ea948af9dde303ef8f28410ce0027472253b95bbd9447f1a2c538a07bda78c61567e5252f1e7&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/vmware-fixes-critical-vulnerabilities-in-vrealize-network-analytics-tool/  
  
  
题图：Pexels License  
  
  
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
  
