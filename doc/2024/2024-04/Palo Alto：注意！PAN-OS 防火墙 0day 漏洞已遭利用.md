#  Palo Alto：注意！PAN-OS 防火墙 0day 漏洞已遭利用   
Bill Toulas  代码卫士   2024-04-15 17:47  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Palo Alto Networks 公司提醒称，PAN-OS 防火墙中存在一个严重的命令注入0day漏洞，且该漏洞已遭在野利用。**  
  
  
  
Palo Alto Networks 公司发布安全公告称，“Palo Alto Networks 注意到数量有限的攻击正在利用该漏洞。”该漏洞由 Volexity 公司发现，编号为CVE-2024-3400，是一个命令注入漏洞，CVSS评分为10，无需特殊权限或用户交互即可遭利用。  
  
Palo Alto Networks 公司澄清表示，如果同时启用了 GlobalProtect 网关和设备要测特性，则PAN-OS 的某些版本受影响。安全公告解释称，“适用于某些特定版本和特殊特性配置的 PAN-OS软件的GlobalProtect 特性中存在命令注入漏洞，可导致未认证攻击者以防火墙上的 root 权限执行任意代码。”  
  
易受攻击影响的版本是PAN-OS 10.2、11.0和11.1，修复方案将在2024年4月14日发布。厂商将发布如下三个版本，在本周日执行热修复方案：  
- PAN-OS 10.2.9-h1  
  
- PAN-OS 11.0.4-h1  
  
- PAN-OS 11.1.2-h3  
  
多款产品如 Cloud NGFW、Panorama 设备以及 Prisma Access 不受影响。相关影响概览如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSejUVxINXkYgrCycAmFWL1NCTAnxZ1yLorHicnibdWzxamuKsMkVZ2m0eNupQFfEKCZ6ic57mfoNmiaA/640?wx_fmt=webp&from=appmsg "")  
  
  
威胁研究员 Yutaka Sejiyama 表示，扫描显示目前被暴露在网络的8.2万台设备可能易受该漏洞影响，其中40%的设备位于美国。  
  
  
**漏洞缓解**  
  
  
由于CVE-2024-3400已遭在野利用，因此受影响用户必须立即应用缓解措施，解决该风险。该安全公告提出执行如下措施：  
  
- 具有“威胁防御”订阅服务的用户可激活系统中的“威胁ID95187”，拦截攻击；  
  
- 确保已在 “GlobalProtect Interfaces” 上配置漏洞防御措施，阻止漏洞遭利用。  
  
- 在应用补丁前禁用设备遥测。  
  
  
  
由于Palo Alto Networks 设备部署在企业网络中，因此已成为复杂威胁行动者的攻击目标。2022年8月，PAN-OS 中的另外一个 0day 被用于执行 TCP DoS 放大攻击。而CVE-2024-3400的严重性更高，如遭利用将产生更严重的影响，因此管理员必须及时采取措施，确保系统安全。  
  
CISA 已将该漏洞列入必修清单，要求联邦机构在2024年4月19日之前必须修复该漏洞。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Palo Alto Networks：PAN-OS DDoS 漏洞已遭在野利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513567&idx=1&sn=181b3bb7e1b34dc9dd67bfde798f4c7d&chksm=ea9484b5dde30da32cd69913ab4a1ad2eb4aa8c77e4dbb69d68262539a9a5940c2b01418807c&scene=21#wechat_redirect)  
  
  
[Palo Alto 再次修复一个严重的 PAN-OS 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247493998&idx=2&sn=bd1a18589634606e0ff70f17de914bfa&chksm=ea94d804dde35112f7323ae883a236262d671771d6b6d019bbec44a870d8e3f2898d89f4f647&scene=21#wechat_redirect)  
  
  
[美网络司令部：马上修复严重的 PAN-OS 漏洞，免遭国家黑客攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247493807&idx=2&sn=39218cc6b67344d48d49fa4dbc62eeca&chksm=ea94d9c5dde350d3119c58d0bee936cd352f2d7fa036451f6038c1938dc88e5ef0ee19604e8f&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/palo-alto-networks-warns-of-pan-os-firewall-zero-day-used-in-attacks/  
  
  
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
  
