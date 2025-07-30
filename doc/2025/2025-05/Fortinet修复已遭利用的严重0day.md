#  Fortinet修复已遭利用的严重0day   
Sergiu Gatlan  代码卫士   2025-05-14 09:36  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Fortinet 公司发布安全更新，修复针对 FortiVoice 企业电话系统的一个严重的RCE漏洞CVE-2025-32756。该漏洞处于0day 状态时即遭利用。该漏洞还影响 FortiMail、FortiNDR、FortiRecorder和FortiCamera。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMS5h0SuuXM8RmRjHiaeibMd6clLBqCEkVcFPuRgGPcvAdaXib24ju6bqDxpq56cJgNA5dicat2KBbfUAQ/640?wx_fmt=png&from=appmsg "")  
  
  
Fortinet 在本周二发布的一份安全公告中提到，成功利用该漏洞可导致远程未认证攻击者通过恶意构造的HTTP请求执行任意代码或命令。该漏洞是由Fortinet 公司的产品安全团队发现的，他们基于攻击者的活动，包括网络扫描、用于掩盖行踪而删除系统崩溃日志以及通过打开“fcgi 调试”记录系统凭据或SSH登录尝试等，发现了该漏洞。  
  
Fortinet 公司在安全公告中提到，攻击者从六个IP地址发起攻击，相关妥协指标包括受陷系统上启用的“fcgi 调试”设置（默认不启用）。要查看系统是否打开了该设置，则应在运行命令 diag debug application fcgi 后查看是否出现“general to-file ENABLED”。  
  
Fortinet 公司在调查过程中还发现威胁人员在被黑设备上部署了恶意软件、添加了 cron 任务收割凭据并释放脚本以扫描受害者的网络。该公司还为无法立即更新的用户分享了缓解措施，用户可禁用易受攻击设备上的HTTP/HTTPS管理员界面。  
  
上个月，Shadowserver Foundation 发现了攻击者利用新的符号链接后门发现了超过1.6万台暴露到互联网中的设备，攻击者对受陷设备上的敏感文件拥有只读权限。4月初，Fortinet 还提醒注意一个严重的可用于远程更改管理员密码的 FortiSwitch 漏洞。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Fortinet：通过符号链接仍可访问已修复的 FortiGate VPN](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522719&idx=2&sn=90b7383d8382773b4919bac86f159006&scene=21#wechat_redirect)  
  
  
[Fortinet：注意这个认证绕过0day漏洞可用于劫持防火墙](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522078&idx=2&sn=a6a418ea6abb9635205b06203e061801&scene=21#wechat_redirect)  
  
  
[Fortinet：注意FortiWLM漏洞，黑客可获得管理员权限](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521859&idx=1&sn=6aade83438190800942638166b046757&scene=21#wechat_redirect)  
  
  
[黑客称窃取 440GB 文件，Fortinet 证实数据遭泄露](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520799&idx=2&sn=d02acbabe690ef64658cea5df0e53131&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/fortinet-fixes-critical-zero-day-exploited-in-fortivoice-attacks/  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
