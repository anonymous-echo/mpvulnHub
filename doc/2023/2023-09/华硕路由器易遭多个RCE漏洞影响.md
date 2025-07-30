#  华硕路由器易遭多个RCE漏洞影响   
Bill Toulas  代码卫士   2023-09-06 20:05  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
****  
**华硕 RT-AX55、RT-AX56U_V2 和 RT-AC86U 路由器受三个严重远程代码执行 (RCE) 漏洞影响，如安全更新未安装则可导致设备遭劫持。**  
  
  
  
这三款无线路由器是消费者网络市场上的热门高端路由器，备受游戏玩家和高性能需求用户的青睐。这三个漏洞的CVSS v3.1 评分均为9.8，是格式化字符串漏洞，可遭远程利用且无需任何认证，可导致远程代码执行、服务终端和在设备上实施任意操作等后果。  
  
格式化字符串漏洞源自某些函数中格式化字符串参数中的未验证和/或未清洁用户输入，可导致多种问题如信息泄露和代码执行等。攻击者可通过发送给易受攻击设备的特殊构造的输入利用这些漏洞。攻击者可攻击华硕设备上的某些管理员 API 函数。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSS3HRdicXibDnfEXjP3fLlMRycicvicD3qjAztoFtUuWY0jq71kggt3Xxjwjgvd17wt3ZXnViaXlXGmLg/640?wx_fmt=png "")  
  
**漏洞简述**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSS3HRdicXibDnfEXjP3fLlMRyrMfZ0uHibaicyq2LBMn5hHKB0XuDuCbbqxa0TjB1nmiaAh1qEWDXzDag/640?wx_fmt=png "")  
  
  
  
这三个漏洞如下：  
  
-  CVE-2023-39238：缺乏对 iperf 相关的API 模块 “ser_iperf3_svr.cgi” 上的输入格式化字符串的正确验证。  
  
- CVE-2023-39239：缺乏对通用设置功能的API 中输入格式化字符串的正确验证。  
  
- CVE-2023-39240：缺乏对iperf 相关API 模块 “set_ipertf3_cli.cgi” 上输入格式化字符串的正确验证。  
  
  
  
上述漏洞分别影响在固件版本 3.0.0.4.386_50460、3.0.0.4.386_50460和3.0.0.4.386_51529 中的 ASUS RT-AX55、RT-AX56U_V2和RT-AC86U。推荐的解决方案是应用如下固件更新：  
  
- RT-AX55: 3.0.0.4.386_51948或后续版本  
  
- RT-AX56U_V2: 3.0.0.4.386_51948或后续版本  
  
- RT-AC86U: 3.0.0.4.386_51915或后续版本  
  
  
  
华硕在今年8月早些时候为 RT-AX55发布补丁，在5月份为AX56U_V2 发布补丁并在7月尾RT-AC86U 发布补丁。尚未应用安全更新的用户应尽快行动。另外，由于很多消费者路由器缺陷都与 web 管理控制台有关，强烈建议关闭远程管理 (WAN Web Access) 特性，阻止从互联网访问。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[华硕紧急修复多个严重的路由器漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516769&idx=1&sn=e00e30e1c0b1187da247a4f936d2761e&chksm=ea94b30bdde33a1d1e665e5aff83de4c7dc1f514f22b2f801b2394245122fa4c1d765b8d7585&scene=21#wechat_redirect)  
  
  
[华硕修复可禁用安全启动程序的UEFI漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514814&idx=2&sn=d77760825e29cde63586a63c502a43c9&chksm=ea948bd4dde302c23aaeb3cca7bc0319a84411de5600ffbdd5a3f0b8d9241858e091fa9b19f8&scene=21#wechat_redirect)  
  
  
[华硕：警惕 Cyclops Blink 恶意软件正在攻击路由器](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511001&idx=1&sn=0238153b461824d38ec21531bdbb393d&chksm=ea949ab3dde313a5170ec185487dde03b9bbc977c5c0e051d87e36c4caae41139956f79c0d0f&scene=21#wechat_redirect)  
  
  
[华硕承认 Live Update Utility 已遭 APT 组织利用，发布补丁](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489553&idx=5&sn=395bbe261cc2a7a8f7ef01301e4baa6d&chksm=ea97297bdde0a06d49391ef32da9f97b978b807598bcecdd92ef4e9f748f18c07b802bd5e589&scene=21#wechat_redirect)  
  
  
[知情不报|华硕 Live Update 被曝后门，超百万用户遭供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489542&idx=2&sn=0887d3f3ac123fc74b3b6bb9182a6267&chksm=ea97296cdde0a07af9b99a8da2ac4077ee063257118268d775e9f0c23be131e95530334eb212&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/asus-routers-vulnerable-to-critical-remote-code-execution-flaws/  
  
  
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
  
