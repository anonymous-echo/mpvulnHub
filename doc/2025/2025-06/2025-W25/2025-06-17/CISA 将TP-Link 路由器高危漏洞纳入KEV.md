> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523309&idx=2&sn=d3e035c89c35c26ad0a1cad90861ac97

#  CISA 将TP-Link 路由器高危漏洞纳入KEV  
Ravie Lakshmanan  代码卫士   2025-06-17 10:40  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**本周一，美国网络安全和基础设施安全局 (CISA) 将TP-Link 无线路由器中的一个高危漏洞纳入“已知遭利用漏洞 (KEV)”分类表中。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSW47rBFzuOCUm7ezhoRFVzofFc6icb0ozGx0q56Fv57KABKjPOnhTI3RRJbzFRTDO7SClpVZt3UYw/640?wx_fmt=png&from=appmsg "")  
  
  
该漏洞CVE-2023-33538（CVSS评分8.8）是一个命令注入漏洞，可导致在处理特殊构造的HTTP GET请求的 ssid1参数时执行任意系统命令。CISA提到，“TP-Link TL-WR940N V2/V4、TL-WR841N V8/V10和TL-WR740N V1/V2中存在一个可通过component /userRpm/WlanNetworkRpm实现命令注入的漏洞。”  
  
CISA提醒称受影响产品可能已达生命周期以及/或者服务周期，督促用户如无缓解措施则停用这些产品。目前尚无关于该漏洞如何遭在野利用的公开信息。  
  
2024年12月，Palo Alto Networks Unit 42披露称，发现针对运营技术的恶意软件 FrostyGoop 的其它样本，以及与ENCO控制设备对应的其中一个IP地址也充当路由器 web 服务器，它通过 TP-Link WR740N 从web 浏览器访问 ENCO 设备。然而，该公司还提到，“目前尚未有有力证据表明攻击者在2024年7月的 FrostyGoop 攻击中利用CVE-2023-33538。”  
  
TP-Link 公司尚未就此置评。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSW47rBFzuOCUm7ezhoRFVzyK2g9TZUTicd0b7EXvOPE4So4tWSf2WIz7dCD1jtib1PDdHLK1d4CHVg/640?wx_fmt=png&from=appmsg "")  
  
**CVE-2023-28771再遭活跃利用**  
  
  
  
前不久，GreyNoise 公司提醒称 Zyxel 防火墙中的一个严重漏洞（CVE-2023-28771，CVSS 评分9.8）遭利用尝试。  
  
该漏洞也是操作系统命令注入漏洞，可导致未认证攻击者向可疑设备发送构造请求执行命令。Zyxel公司已在2023年4月修复该漏洞。虽然该漏洞在披露后不久就已被用于构建DDoS 僵尸网络如 Mirai，但GreyNoise 公司表示最近针对该漏洞的利用增强。244个唯一IP地址被指在短期实施利用，攻击目标主要位于美国、英国、西班牙、德国和印度。  
  
GreyNoise 公司提到，“历史分析表明在6月16日之前的两周内，这些IP地址并未参与其它任何扫描或利用行为，仅针对CVE-2023-28771”，并表示发现了“与Mirai僵尸网络变体一致的指标”。为缓解该威胁，建议用户将Zyxel设备升级至最新版本，监控异常活动并限制可能的暴露情况。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[CISA将Erlang SSH 和 Roundcube 加入KEV清单](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523250&idx=2&sn=245cd6553dde79a725f1afe15893f164&scene=21#wechat_redirect)  
  
  
[CISA提醒注意已遭利用的 Commvault 0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523124&idx=1&sn=1a8e46e871f1fae51bb1c752be774842&scene=21#wechat_redirect)  
  
  
[NIST、CISA联合提出漏洞利用概率度量标准](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523082&idx=2&sn=4d5a25d58482d98bdb3b13320e03bb92&scene=21#wechat_redirect)  
  
  
[CISA为CVE计划续期11个月，MITRE 成立CVE基金会防范](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522769&idx=2&sn=550a6097b86ddca08a77c2e694b9e854&scene=21#wechat_redirect)  
  
  
[CISA：速修复已遭利用的 CentreStack 和 Windows 0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522701&idx=2&sn=0b8f46ac41b6d62102b7ec1c02b25f60&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2025/06/tp-link-router-flaw-cve-2023-33538.html  
  
  
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
  
