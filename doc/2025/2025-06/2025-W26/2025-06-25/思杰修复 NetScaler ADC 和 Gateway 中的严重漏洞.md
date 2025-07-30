> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523373&idx=1&sn=046fdf8814e8311d4a31bd092804a2c2

#  思杰修复 NetScaler ADC 和 Gateway 中的严重漏洞  
Guru Baran  代码卫士   2025-06-25 10:34  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**思杰 (Citrix)修复了NetScaler ADC和NetScaler Gateway 中的一个严重漏洞CVE-2025-5777 (CVSS 评分9.3)，是因输入验证不充分造成的界外读漏洞。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQiaHEEicnHg2bcdILZy8TaZricm13JRT7SibiaWOnusGPFr8Yhj4nbDSbmv1ynV66yFzbvDZxOI7Npncg/640?wx_fmt=png&from=appmsg "")  
  
  
类似于另外一个常被称为“CitrixBleed（思杰出血）”的漏洞CVE-2023-4966，CVE-2025-5777可导致未授权攻击者通过恶意请求从面向互联网的 NetScaler 设备内存中窃取有效的会话令牌。  
  
思杰在关于CVE-2025-5777和CVE-2025-5349（访问控制不当漏洞，CVSS评分8.7）的安全通告中提到，NetScaler ADC 和 NetScaler Gateway 的多个版本受这两个漏洞影响，包括：  
  
- NetScaler ADC 和 NetScaler Gateway早于 14.1-43.56的14.1版本  
  
- NetScaler ADC 和 NetScaler Gateway 早于13.1-58.32的13.1版本  
  
- NetScaler ADC 13.1-FIPS 和 NDcPP 早于13.1-37.235-FIPS 和 NDcPP的版本  
  
- NetScaler ADC 12.1-FIPS 早于 12.1-55.328-FIPS的版本  
  
  
  
安全通告中还提到，12.1和13.0版本已达到生命周期但也受影响，思杰建议客户将设备升级至受支持的最新版本来修复这些漏洞，包括：  
  
- NetScaler ADC 和NetScaler Gateway 14.1-43.56及后续版本  
  
- NetScaler ADC 和NetScaler Gateway   13.1-58.32 及后续版本   
  
- NetScaler ADC 13.1-FIPS 和13.1-NDcPP 13.1-37.234 及后续版本  
  
- NetScaler ADC 12.1-FIPS 和12.1-NDcPP 12.1-55.327及后续版本  
  
  
  
思杰在支持页面中提到，“此外，我们建议运行如下命令，在 HA 对或集群中的 NetScaler 设备升级至已修复版本后，终止所有的活跃 ICA 和 PCoIP 会话。”  

```
kill icaconnection -all
kill pcoipConnection -all
```

  
  
NetScaler ADC 和 NetScaler Gateway 中的漏洞是近年来威胁人员的热门目标。CVE-2023-4966是一个严重的0day漏洞，且触发CISA发布提醒，督促组织机构将系统升级至已修复版本。如遭利用，该漏洞可导致未认证攻击者从受影响的系统内存中获取敏感信息。更早之前，位于该产品中的两个漏洞CVE-2023-6548和CVE-2023-6549影响六个受支持版本且遭在野活跃利用。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Citrix悄悄修复相似度极高但严重性不及CitrixBleed的高危漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519419&idx=1&sn=3bb85759ff76414bd555bb55aa1b3c16&scene=21#wechat_redirect)  
  
  
[思杰ADM高危漏洞可导致管理员密码重置](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512458&idx=3&sn=b55867df7184e1bc35226d1d943cabe3&scene=21#wechat_redirect)  
  
  
[Citrix 分享Netscaler 密码喷射攻击的缓解措施](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521806&idx=1&sn=0678a9877c98e19004381988c56fc6c5&scene=21#wechat_redirect)  
  
  
[Citrix 督促 Mac 用户修复 Workspace App 中的提权漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519614&idx=1&sn=9e0519627dc928e416d3ba3de0a1941c&scene=21#wechat_redirect)  
  
  
[Citrix 提醒管理员手动缓解 PuTTY SSH 客户端漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519453&idx=1&sn=b108366a369534bc2bc55f5a5089d587&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://cybersecuritynews.com/cisco-anyconnect-vpn-server-vulnerability/  
  
  
  
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
  
