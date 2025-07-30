#  VMware 紧急修复多个漏洞   
Ryan Naraine  代码卫士   2025-05-21 10:35  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**本周二，博通紧急修复多个 VMware 漏洞，可导致数据泄露、命令执行和拒绝服务 (DoS) 攻击，目前不存在应变措施。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQ2ZtShadXISAOjbZXiaxficUcOBPJNwwV3AH8LD0fFyx3eX6DtqoR2P0A2Co46SlwL9kphhJ9W2LHg/640?wx_fmt=png&from=appmsg "")  
  
  
博通发布两份公告，至少提到了位于 VMware Cloud Foundation、VMware ESXi、vCenter Server、Workstation 和 Fusion 产品线中的7个漏洞。  
  
VMSA-2025-0009通告的紧急程度更高。该通告致谢北约 (NATO) 网络安全中心报送的三个位于 VMware Cloud Foundation 中的漏洞。其中CVE-2025-41229是目录遍历漏洞，CVSS评分为8.2。该公司提醒称，“对VMware Cloud Foundation 上端口443拥有网络访问权限的恶意人员可利用该漏洞访问某些内部服务。”  
  
VMware 还修复了位于VMware Cloud Foundation（供企业构建和管理私有云）产品中的一个信息泄露漏洞（CVSS 7.5）和一个认证缺失错误 (CVSS 7.3)。  
  
VMware 督促用户立即升级至VMware Cloud Foundation 5.2.21.2版本。  
  
VMware  还推出了第二个安全通告 VMSA-2025-0010，说明了位于 ESXi、vCenter Server、Workstation 和 Fusion 中的四个漏洞。其中最严重的漏洞是位于 vCenter 中的认证命令执行漏洞CVE-2025-41225（CVSS 8.8）。VMware 提醒称，能够创建或修改告警的攻击者能够在管理面板上运行任意命令。其它三个漏洞包括两个拒绝服务条件（CVSS 6.8和5.5）以及同时影响 ESXi 和 vCenter 的一个反射型XSS 漏洞（CVSS 4.3）。和VMware Cloud Foundation 漏洞一样，VMware 除了升级之外并未列出缓解措施，也并未提及这些漏洞遭在野利用的情况。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[供应链攻击：通过Vmware 工具RVTools传播Bumblebee 恶意软件](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523052&idx=2&sn=f996a017b72f7d810caca56e8042083b&scene=21#wechat_redirect)  
  
  
[博通：注意 Vmware Windows Tools 中的认证绕过漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522590&idx=1&sn=ee578730b1733ca26a369770366c3b00&scene=21#wechat_redirect)  
  
  
[博通修复3个已遭利用的 VMware 0day 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522410&idx=1&sn=0f5b704ab0b14c7dd3262ffbc0697b07&scene=21#wechat_redirect)  
  
  
[VMware 修复 Aria Operations 中的多个高危漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521645&idx=2&sn=3a85491541969226b45d2bca18f4373b&scene=21#wechat_redirect)  
  
  
[补丁不给力，VMware vCenter 严重RCE漏洞遭利用](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521523&idx=1&sn=286f99df03f25ebd1cb1fb497f991b21&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/nato-flagged-vulnerability-tops-latest-VMware-security-patch-batch/  
  
  
  
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
  
