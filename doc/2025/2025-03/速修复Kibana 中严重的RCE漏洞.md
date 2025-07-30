#  速修复Kibana 中严重的RCE漏洞   
Ravie Lakshmanan  代码卫士   2025-03-07 18:06  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Elastic 公司发布安全更新，修复影响用于Elasticsearch 的Kibana 数据可视化仪表盘软件中的一个严重的原型污染漏洞，它可导致任意代码执行后果，编号是CVE-2025-25012，CVSS评分为9.9。**  
  
Elastic 公司在安全公告中提到，“Kibana 中的原型污染漏洞可通过特殊构造的文件上传漏洞和特殊构造的HTTP请求，实现任意代码执行。”原型污染漏洞可使攻击者操纵应用的 JavaScript 对象和属性，可能导致越权数据访问、提权、拒绝服务或远程代码执行后果。  
  
该漏洞影响Kibana 8.15.0和8.17.3之间的所有版本，已在8.17.3版本中修复。从Kibana 8.15.0到8.17.1的版本，仅具有Viewer 角色的用户能够利用该漏洞，而在Kibana 8.17.1和8.17.2版本中，仅具有fleet-all、integrations-all或 actions:execute-advanced-connectors 的用户能够利用该漏洞。  
  
建议用户采取相关措施应用最新修复方案，抵御潜在威胁。如无法立即应用补丁，则建议用户在 Kibana 的配置 (“kibana.yml”) 将 Integration Assistant 特性标记为 false (“xpack.integration_assistant.enabled: false”)。  
  
2024年8月，Elastic 修复了Kibana 中的另外一个严重的原型污染漏洞（CVE-2024-37287，CVSS评分9.9），可导致代码执行后果。一个月后，它修复了两个严重的反序列化漏洞（CVE-2024-37288，CVSS评分9.9和CVE-2024-37285，CVSS评分9.1），它们也可导致任意代码执行后果。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[MITRE Caldera所有版本皆存在满分RCE漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522340&idx=1&sn=857f619293015f92aad6d9622d926c9b&scene=21#wechat_redirect)  
  
  
[MongoDB库中存在多个漏洞，可用于在Node.js服务器上实现RCE](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522334&idx=2&sn=474bb8a99d7a850a95b1ba847ff41044&scene=21#wechat_redirect)  
  
  
[Apache Ignite 严重漏洞可导致RCE](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522291&idx=2&sn=d8279f609eb439d7d723557c865748fe&scene=21#wechat_redirect)  
  
  
[WGS-804HPT 交换机中存在多个严重漏洞，可导致RCE和网络利用](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522124&idx=1&sn=8b928d650502c3cebc7b2ae0e85282a2&scene=21#wechat_redirect)  
  
  
[SimpleHelp 多个严重漏洞可导致文件窃取、提权和RCE攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522089&idx=2&sn=46178e7445995e2b3a605d7fd3c37a93&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2025/03/elastic-releases-urgent-fix-for.html  
  
  
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
  
