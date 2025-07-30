#  CISA：速修复已遭利用的 CentreStack 和 Windows 0day漏洞   
Ionut Arghire  代码卫士   2025-04-10 18:07  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**本周二，CISA督促组织机构紧急修复Gladinet CentreStack 和微软 Windows 中的两个0day 漏洞。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQWzHJYImtDibUtL46yCKT8XF29f2JYDbMfXQIx4iaia6Ez9UaX4IbByHSNPrc9hLcpc9uYRaIPtmW7g/640?wx_fmt=png&from=appmsg "")  
  
  
CVE-2025-30406（CVSS评分9）是 Gladient 公司在4月3日公布的一个 CentreStack 漏洞。该公司提到，漏洞自3月起就遭利用，不过目前似乎并没有相关公开信息。  
  
该漏洞影响CentreStack用于 ViewState 完整性验证的方式，可导致攻击者伪造数据并远程执行任意代码。Gladient 公司在安全公告中提到，“该应用使用 IIS web 配置文件中的一个硬编码或保护不当的、用于保护 ASP.NET ViewState 数据的machineKey。如攻击者获取或预测该 machineKey，则可伪造 ViewState payload，通过完整性检查。”  
  
Gladient 公司解释称，在一些配置中，可发动ViewState 反序列化攻击，可导致在该 web 服务器上远程执行代码。该公司在 CentreStack 16.4.10315.56368版本中修复了该漏洞，督促组织机构立即更新或修改 machineKey 的值作为暂时措施。该公司表示，“最新版本会在安装过程中自动生成新的机器密钥，从而增强系统的安全性。”  
  
Windows 中的漏洞CVE-2025-29824（CVSS评分7.8）是位于该平台 CLFS 驱动中的释放后使用 (UAF) 漏洞，可用于本地提权。微软已在4月补丁星期二中修复了该漏洞，并提醒称已发现位于美国、委内瑞拉、西班牙和沙特阿拉伯的组织机构遭该漏洞利用攻击，而用于勒索攻击中的 PipeMagic 恶意软件被用于部署利用。  
  
本周二，CISA将这两个漏洞添加到了必修清单 (KEV)，督促联邦机构按照BOD22-01规定，在4月29日之前修复和缓解。尽管该指令仅适用于联邦机构，但建议所有组织机构都查看该必修清单，识别环境中的受影响应用和设备，并立即修复。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[EncryptHub 的双重生活：一面网络犯罪分子，一面 Windows 赏金猎人](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522676&idx=1&sn=b2dbfc7fc0240ff2cc12b384750a33f8&scene=21#wechat_redirect)  
  
  
[微软4月补丁星期二值得关注的漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522693&idx=2&sn=e1391919751a9d3acaf0708361a37f65&scene=21#wechat_redirect)  
  
  
[微软利用AI从开源引导加载器中找到20个0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522638&idx=1&sn=15b5a925b5a9f1eecca2dc4a721a63a9&scene=21#wechat_redirect)  
  
  
[微软Dynamics CRM发现“Self-XSS”漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247486043&idx=5&sn=7a3c168e92d5c89f8a28e677a8b57465&scene=21#wechat_redirect)  
  
  
[黑客声称通过受陷 MSP 获得对50家美国企业的访问权限](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513266&idx=1&sn=1e828de8234f1fd800e272f5848205ef&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/cisa-urges-urgent-patching-for-exploited-centrestack-windows-zero-days/  
  
  
  
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
  
