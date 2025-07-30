#  VMware 修复严重的 vCenter Server 代码执行漏洞   
Sergiu Gatlan  代码卫士   2023-10-26 11:44  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**今天，VMware 发布安全更新，修复了位于 vCenter Server 中的一个严重漏洞（CVE-2023-34048）。该漏洞可导致攻击者在易受攻击服务器上获得远程代码执行权限。**  
  
  
vCenter Server 是VMware vSphere 套件的中心管理枢纽，帮助管理员管理和监控虚拟化的基础设施。该漏洞由趋势科技ZDI计划的研究员 Grigory Dorodnov 发现并提交，产生原因在于 vCenter 的 DCE/RFC 协议实现中存在一个界外写弱点。  
  
未认证攻击者可在复杂度较低的攻击中远程利用该漏洞且无需任何用户交互。该公司表示，目前尚未由证据表明该漏洞已遭利用。目前补丁通过 vCetner Server 更新机制正常推送。由于该漏洞的评级为严重，因此VMware 还为多个已达生命周期的不在主动支持范围内的产品发布补丁。  
  
VMware 公司提到，“虽然VMware 未在 VMware 安全公告中提到已达生命周期的产品，但鉴于漏洞的严重性以及缺少缓解措施，VMware 也为 vCenter Server 6.7U3、6.5U3和VCF 3.x发布了补丁。同样，VMware 也为 vCenter Server 8.0U1以及同步为VCF 5.x和4.x部署发布了补丁。”  
  
  
无应变措施  
  
  
由于目前不存在应变措施，VMware 督促管理员严格控制对 vSphere 管理组件和接口（包括存储和网络组件）的网络边界访问权限。  
  
与该漏洞相关的潜在攻击利用的具体网络端口是 2012/tcp、2014/tcp和 2020/tcp。  
  
另外，VMware 还修复了一个CVSS评分为4.3的部分信息泄露漏洞CVE-2023-34056。该漏洞可被具有非管理员权限的威胁行动者用于访问 vCenter 服务器，访问敏感数据。  
  
VMware 在一份问答文档中提到，“这是一次紧急变更，组织机构应当迅速行动。不过，所有安全响应都取决于具体情况。请咨询所在组织机构的信息安全员工，做出相应行动。”  
  
6月份，VMware 修复了多个高危的 vCenter Server 漏洞，缓解了代码执行和认证绕过风险。同一周，VMware 还修复了另外一个严重的漏洞。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[VMware 修复网络监控产品中的严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517495&idx=2&sn=f20e793a89665c09e42c6341755a3e88&chksm=ea94b45ddde33d4bec3d0c06c238e806e9061130fc138a24354059fe0f857cafc9054fe04e3c&scene=21#wechat_redirect)  
  
  
[戴尔 Compellent 硬编码密钥暴露 VMware vCenter 管理员凭据](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517384&idx=1&sn=265b6987345cae72c67305983ab23dd1&chksm=ea94b5a2dde33cb401636bf5a0c1f1029d2a1c8369d20258285b7dfd15d85f6fa83e963936e9&scene=21#wechat_redirect)  
  
  
[VMware 修复 vRealize 网络分析工具中的严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516696&idx=2&sn=f9d50b8697f67622344d6400a4246a35&chksm=ea94b372dde33a64677eb42039df16b745cc37313484a52d2b714d5b8c2fad89b1bc71258855&scene=21#wechat_redirect)  
  
  
[VMware 修复在 Pwn2Own 大赛上发现的两个严重0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516346&idx=1&sn=260aa87f75279d3101ddc11e8e48ee81&chksm=ea94b1d0dde338c6aa50da46b3651794726cdf0d14752bb2a5af194367089da4bfa90355660d&scene=21#wechat_redirect)  
  
  
[VMware 修复严重的 vRealize 反序列化漏洞，可导致任意代码执行](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516298&idx=2&sn=1625888e8762acc4a48a665717933497&chksm=ea94b1e0dde338f62127926fd478fb71059387a0ae20c0fd3e0d9c2f4c6405f946351edeb454&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/vmware-fixes-critical-code-execution-flaw-in-vcenter-server/  
  
  
  
  
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
  
