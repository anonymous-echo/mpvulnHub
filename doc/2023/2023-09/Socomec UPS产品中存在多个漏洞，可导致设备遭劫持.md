#  Socomec UPS产品中存在多个漏洞，可导致设备遭劫持   
Eduard Kovacs  代码卫士   2023-09-12 12:33  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**Socomec（溯高美索克曼）的不间断电源 (UPS) 产品中受多个漏洞影响，可用于劫持和破坏设备。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTQjG0tsKz3zHp96paO8kcyoSbmromEoPPZe5Pv5KDdKTDrTPj6qMDKgibluDVKspZ48qrB5hlNMJg/640?wx_fmt=png "")  
  
  
Socomec 是一家总部位于法国的电力设备制造商，专注于低压电能源性能业务。该公司产品包括全球多个行业企业所使用的模块化UPS设备。  
  
西班牙网络安全公司 S21sec 的ICS 安全顾问 Aaron Flecha Menendez 发现，某些 Socomec UPS 设备即 MODULYS GP (MOD3GP-SY-120K) 受七个漏洞影响，包括XSS、明文密码存储、代码注入、会话cookie 窃取、CSRF和敏感信息的不安全存储，其严重程度从中危到严重不等。  
  
美国网络安全机构CISA 上周发布安全公告，将这些漏洞通知给组织机构，指出受影响产品已达生命周期。Socomec 公司建议组织机构停止使用已到期产品，并更新至MODULYS GP2 (M4-S-XXX)，后者应当不受这些漏洞影响。  
  
仍然使用该易受攻击产品的企业可暴露到严重风险中，因为该漏洞可导致了解系统如何运作的攻击者修改其行为并阻止其正常运行。  
  
Flecha menendez 提到，“在可实现的各种场景中，最糟糕的场景无疑是中断UPS 管理并影响其提供备份电源的能力。”好在，似乎并不存在直接暴露到互联网中的UPS 产品。然而，位于目标组织机构网络中的攻击者可组合利用其中一些 MODULYS GP 漏洞造成更严重的影响。  
  
他解释称，“‘不安全的敏感信息存储’漏洞 (CVE-2023-41965) 可导致获取未到期的有效会话cookie (CVE-2023-41084)，继而实现远程代码执行 (CVE-2023-40221)。组合利用这三个漏洞可导致攻击者完全控制管理级设备并影响其正常运转。”  
  
研究员尚未测试更新的产品型号，因此无法证实是否像厂商声称的那样不受影响。值得一提的是，使用该易受攻击产品的组织机构应当采取措施，因为针对UPS 设备的攻击此前已存在。去年，美国政府提醒企业注意这类攻击，并提供了如何缓解的指南。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[施耐德电气 UPS 软件中存在严重的未认证 RCE 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516335&idx=1&sn=d6970653344d43075615c17ff16238fe&chksm=ea94b1c5dde338d3789946c1608390c5efd92097c9603d9825cf6e2a34dfd82935abe1d1fd32&scene=21#wechat_redirect)  
  
  
[CISA提醒：UPS联网设备正遭攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511152&idx=1&sn=039b234b8b1722a93d01b97aa7b797eb&chksm=ea949d1adde3140cdd35a8721bc7a77a03a9093513b9ff8403f63aea52f1c679b63ea2efbd3d&scene=21#wechat_redirect)  
  
  
[TLStorm：APC UPS 存在零点击0day，可远程烧毁设备、切断电源](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510841&idx=4&sn=9090608e9025766a59f873089c8d6683&chksm=ea949a53dde31345cf35905d84dcf611ba5b5deeeadca49c6534882566fa5db8657a3d8b4a69&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/vulnerabilities-allow-hackers-to-hijack-disrupt-socomec-ups-devices/  
  
  
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
  
