#  VMware 修复网络监控产品中的严重漏洞   
Ryan Naraine  代码卫士   2023-08-30 18:23  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
****  
**周二，虚拟化技术巨头 VMware 发布重大安全更新，修复了 Aria Operations for Networks 产品线中的至少两个严重漏洞。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRiaIWMdxhAdqn7oBIjDuMVAfM7Q26YerCAEQEHuCfg9PuQicib6N1jsaA5CSbBLsb3yibtJUYdkVxveQ/640?wx_fmt=png "")  
  
  
VMware 在安全公告中指出，恶意黑客可利用这些漏洞绕过 SSH 认证并获得对 Aria Operations for Networks 命令行界面的访问权限。VMware 为该网络认证绕过问题分配的编号是CVE-2023-34039，CVSS评分为9.8。  
  
该公司提到，“Aria Operations for Networks 中包含一个因缺乏唯一加密密钥生成而造成的认证绕过漏洞。VMware 将该漏洞的严重性评级为‘严重’等级，且CVSSv3 基础评分为9.8。”  
  
VMware Aria Operations for Networks 产品此前名为 vRealize Network Insight，供企业用于监控、发现和分析网络和应用程序，在云间构建安全的网络基础设施。  
  
VMware 指出，Aria Operations for Networks 收集器受该漏洞影响，建议用户升级平台设备进行修复。  
  
VMware 还发布了另外一个漏洞CVE-2023-20890的补丁，该漏洞可导致对VMware Aria Operations for Networks具有管理员访问权限的认证恶意人员将文件写入任意位置中。  
  
VMware 一直在修复 Aria Operations for Networks 产品中的安全漏洞，最近修复了遭远程在野利用的命令注入漏洞。而该产品也出现在美国CISA的必修清单中。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[戴尔 Compellent 硬编码密钥暴露 VMware vCenter 管理员凭据](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517384&idx=1&sn=265b6987345cae72c67305983ab23dd1&chksm=ea94b5a2dde33cb401636bf5a0c1f1029d2a1c8369d20258285b7dfd15d85f6fa83e963936e9&scene=21#wechat_redirect)  
  
  
[VMware 修复 vRealize 网络分析工具中的严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516696&idx=2&sn=f9d50b8697f67622344d6400a4246a35&chksm=ea94b372dde33a64677eb42039df16b745cc37313484a52d2b714d5b8c2fad89b1bc71258855&scene=21#wechat_redirect)  
  
  
[VMware 修复在 Pwn2Own 大赛上发现的两个严重0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516346&idx=1&sn=260aa87f75279d3101ddc11e8e48ee81&chksm=ea94b1d0dde338c6aa50da46b3651794726cdf0d14752bb2a5af194367089da4bfa90355660d&scene=21#wechat_redirect)  
  
  
[VMware 修复严重的 vRealize 反序列化漏洞，可导致任意代码执行](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516298&idx=2&sn=1625888e8762acc4a48a665717933497&chksm=ea94b1e0dde338f62127926fd478fb71059387a0ae20c0fd3e0d9c2f4c6405f946351edeb454&scene=21#wechat_redirect)  
  
  
[VMware 修复严重的Carbon Black App Control漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515674&idx=1&sn=a2545f99534c8c181bb5022bbc3989e1&chksm=ea948f70dde306661e8a7532ffad9fe411f3cd1cbcb74c5ae58c6e4f394d04247cb807e3ce08&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/vmware-patches-major-security-flaws-in-network-monitoring-product/  
  
  
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
  
