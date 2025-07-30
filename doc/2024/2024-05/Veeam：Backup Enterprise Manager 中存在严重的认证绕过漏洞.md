#  Veeam：Backup Enterprise Manager 中存在严重的认证绕过漏洞   
Sergiu Gatlan  代码卫士   2024-05-22 17:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Veeam 提醒客户称修复一个严重漏洞，它可导致未认证攻击者通过 Veeam Backup Enterprise Manager (VBEM) 登录任何账户。**  
  
VBEM 是一款基于 web 的平台，可使管理员通过单一 web 控制台管理 Veeam Backup & Replication 安装。它有助于在组织机构的备份基础设施和大规模部署中控制备份任务并执行恢复操作。值得注意的话死后，VBEM 并非默认启用，且并非所有环境均易受这些攻击影响。Veeam对CVE-2024-29849给出的评分是9.8。  
  
Veeam 公司解释称，“位于Veeam Backup Enterprise Manager 中的漏洞可导致未认证攻击者以任何用户的身份登录其 web 接口。”无法立即更新至 VBEM 12.1.2.172的管理员可通过停用和禁用 VeeamEnterpriseManagerSvc 和 VeeamRESTSvc (Veeam RESTful API) 服务的方式缓解该漏洞。如不在使用状态，则可通过相关指令卸载 Veeam Backup Enterprise Manager 的方式删除该攻击向量。  
  
Veeam 还修复了其它两个高危漏洞，其中一个可导致攻击者通过 NTLM 中继的方式接管账户 (CVE-2024-29850)，另外一个可导致高权限用户窃取 Veeam Backup Enterprise Manager 服务账户的NTLM 哈希 (CVE-2024-29851)，不过前提是未被配置作为默认的本地系统账户进行运行。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMR02TVB7CHEerCQib30MHJp43gXP3h0fBtkWLvtACvIUKjpccalRYJMZJ1AmZyQPH7jvMymxX7jPxw/640?wx_fmt=gif&from=appmsg "")  
  
**遭勒索攻击**  
  
  
  
  
  
2023年3月，Veeam 修复了位于 Backup & Replication 软件中的一个高危漏洞 (CVE-2023-27532)，它可被用于攻陷备份的基础设施主机。该漏洞之后被用于 FIN7 威胁组织发动的攻击中，该组织与多次勒索活动有关，如 Conti、REvil、Maze、Egregor和BlackBasta。  
  
几个月后，古巴勒索组织利用该漏洞攻击美国的关键基础设施和位于拉丁美洲的拉美IT公司。去年11月，该公司发布热修复方案，解决了位于ONE IT 基础设施监控和分析平台中的其它两个严重漏洞（CVSS评分为9.8和9.9）。Veeam 公司的产品用户超过45万名，遍布全球各地，其中74%的客户在全球排名前2000名。  
  
  
****  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Veeam 修复备份管理平台中的RCE漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519438&idx=1&sn=4e26daf80a580f4ffca69990e4991525&chksm=ea94bda4dde334b29ac40f6c2fcd5382d22e3657a099bbbac0a055d1af89efc833d6a9ee3449&scene=21#wechat_redirect)  
  
  
[Veeam ONE 监控平台存在多个严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518080&idx=3&sn=186f168b319049fd88ec7557cb2458e1&chksm=ea94b6eadde33ffc3b7b219d6a0e6143f28a1c6c166c41882c63ee116d0acffba7acbed4dab3&scene=21#wechat_redirect)  
  
  
[Veeam修复严重漏洞，可攻陷备份基础设施](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515885&idx=3&sn=ffefe13a8f5da2c680df756b9e641cfd&chksm=ea948f87dde30691fda5efbd07f068606a775eb6e6e596b39f44c7f1cd843a4c64a24c1a88a7&scene=21#wechat_redirect)  
  
  
[Veeam 数据备份解决方案修复多个严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510935&idx=2&sn=16d2e8be99d29f0ceb82b7596b370911&chksm=ea949afddde313ebf772d24347c8ee4aa98f2e78b2da9850b34569457f918e386175b6d5b85a&scene=21#wechat_redirect)  
  
  
[瑞士数据管理公司 Veeam 泄露4.45亿条客户记录](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247488036&idx=3&sn=d07a6878bd7689705b7724c3d9fbe1b2&chksm=ea97234edde0aa586c8115f5eda113ca0ea18c04ede5002327dc6390698eec46066457c4971b&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/critical-fluent-bit-flaw-impacts-all-major-cloud-providers/  
  
  
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
  
