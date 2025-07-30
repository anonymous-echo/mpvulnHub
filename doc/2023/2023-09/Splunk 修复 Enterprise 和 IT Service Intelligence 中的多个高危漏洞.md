#  Splunk 修复 Enterprise 和 IT Service Intelligence 中的多个高危漏洞   
Ionut Arghire  代码卫士   2023-09-01 17:50  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
****  
**本周三，Splunk 修复了位于 Splunk Enterprise 和 IT Service Intelligence 中的多个高危漏洞，其中包括位于第三方包中的多个漏洞。**  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTicEwuPwrvibwRcQkPj9dLNZjKnF174bLYvAybSmb1ZKBUxcBh2x9TbqtGDTGxZpTFaul1Tcr0y5iaQ/640?wx_fmt=png "")  
  
  
其中最严重的漏洞是 CVE-2023-40595（CVSS评分8.8），位于 Splunk Enterprise 中，是可通过构造查询利用的远程代码执行漏洞。  
  
Splunk 在安全公告中提到，“利用要求使用在 Splunk Enterprise 中写入文件的 SPL 命令。攻击者可使用该文件提交序列化payload，在该 payload 中执行代码。”  
  
Splunk 还修复了影响一个遗留的内部功能的命令注入漏洞CVE-2023-40598，它可被用于执行任意代码。  
  
Splunk 公司解释称，“该漏洞与当前被废弃的scripted 警报操作所使用的 runshellscript 命有关。该命令和其它外部命令查询可导致攻击者利用该漏洞从 Splunk 平台实例的权限上下文中注入并执行命令。”  
  
最新的 Splunk Enterprise 发布还修复了一个跨站点脚本缺陷 (CVE-2023-40592)、可导致代码执行后果的绝对路径遍历漏洞 (CVE-2023-40597) 和由DLL中不安全路径引用导致的一个提权漏洞 (CVE-2023-40596)。  
  
Splunk Enterprise 版本8.2.12、9.0.6和9.1.1修复了上述漏洞以及另外两个中危的 DoS 漏洞。  
  
周三，Splunk 公司还宣布修复了位于 IT Service Intelligence 中的一个未认证日志注入漏洞（CVE-2023-4571，CVSS评分8.6）。该漏洞可导致攻击者在日志文件中注入ANSI 逃逸代码，从而在易受攻击终端应用中读取日志文件时，执行恶意代码。虽然 IT Service Intelligence 并不受直接影响，但因终端应用所拥有权限以及用户读取恶意日志文件的位置和方式而受到间接影响。  
  
Splunk 公司并未说明这些漏洞是否遭利用，不过在安全公告页面提供了更多信息。Splunk 发布的更新还修复了 Splunk Enterprise、IT Service Intelligence 和 Universal Forwarder中所使用第三方程序包中的多个高危漏洞。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Splunk 企业版修复多个高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516660&idx=3&sn=50c590fbcde8660028cb962e1ee37397&chksm=ea94b09edde33988842895577616f04e287bb0a7c46caf92527cd2429f348583f32f77e7c6c9&scene=21#wechat_redirect)  
  
  
[Splunk Enterprise远程代码执行漏洞(CVE-2022-43571)安全风险通告](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515098&idx=1&sn=7b7050c4fa7d69ee3c61c18f54cbdfeb&chksm=ea948ab0dde303a63d8d84545dc9f8613de167d1120716524c2a2990810c3dc4e62d883ae136&scene=21#wechat_redirect)  
  
  
[千年虫← 2000, 2020→千年虫现身Splunk 平台，立即修复！](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247491676&idx=2&sn=a8b1e588f51a6358298cde5d66b062fc&chksm=ea94d136dde358203977f1fbb7a4d8cb81e5223e487c15160e6b6f1911e500bf0aaee906971a&scene=21#wechat_redirect)  
  
  
[Splunk以1.9亿美元收购安全创业公司Caspida](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247485927&idx=6&sn=d7271606cbb72b8156979be7e0b3a7a5&chksm=ea97388ddde0b19b07445ce51dfe239812937fc94595f82a909584dc8ec0906acd4d6f76e1da&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/splunk-patches-high-severity-flaws-in-enterprise-it-service-intelligence/  
  
  
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
  
