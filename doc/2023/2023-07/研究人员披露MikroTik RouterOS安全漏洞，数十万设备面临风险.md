#  研究人员披露MikroTik RouterOS安全漏洞，数十万设备面临风险   
看雪学苑  看雪学苑   2023-07-27 18:04  
  
近日，VulnCheck在一篇报告中披露，MikroTik RouterOS系统存在一个严重权限提升漏洞（CVE-2023-30799，CVSS分数9.1），攻击者能够利用该漏洞执行任意代码并完全控制受影响的设备，初步估算有数十万设备受到影响。  
  
  
据了解，这个漏洞本质是从管理员到超级管理员的权限提升。尽管对该漏洞的利用需要经过身份验证，但获取RouterOS系统的凭据比预期要容易。这是因为MikroTik RouterOS操作系统并未提供任何防止密码暴力破解的保护措施，并且在2021年10月之前，它还附带有一个众所周知的默认“admin”用户，其密码为空字符串。直到RouterOS 6.49版本发布，管理员才被提示更新空密码。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8FJ7e6pMbIR6iczXww1qIGmGRibaicTWoypacbEyWkO2BJFSUmJTnyqRWCSRlZs0FvibibVib2XIb8autqQ/640?wx_fmt=jpeg "")  
  
  
研究人员使用了Shodan来估测漏洞的影响，发现有474000台设备因暴露了基于Web的管理页面而容易受到攻击。但由于该漏洞也可通过Mikrotek管理客户端Winbox进行利用，共有926000台设备暴露了该管理端口，因此实际影响要大得多。  
  
  
研究人员还指出，此类攻击一旦得逞很难被发现。RouterOS的Web和Winbox界面实现了Snort或Suricata都无法解密及检查的自定义加密方案。一旦攻击者对设备建立了连接，他们能够很容易地在RouterOS用户界面中隐藏自身。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8FJ7e6pMbIR6iczXww1qIGmGDAibwEBWT3R9QGbflnlI1cWW30ibA0aybDv0oXdhsRiaCThK5ibSY8bfCA/640?wx_fmt=webp "")  
  
  
这类漏洞通常会被不法分子利用来建立分布式拒绝服务（DDoS）僵尸网络，例如Mēris。为减轻遭受攻击的风险，建议用户尽快更新到最新版本（6.49.8或7.x）以修补此漏洞。另外还可采取以下缓解措施：删除MikroTik管理接口，限制允许管理员登录的IP地址，禁用Winbox和Web界面并使用SSH，将SSH配置为使用公钥/私钥而非密码。  
  
  
  
编辑：左右里  
  
资讯来源：Vulncheck  
  
转载请注明出处和本文链接  
  
  
**每日涨知识**  
  
 僵尸网络（Botnet）  
  
僵尸网络是由大量遥距控制的僵尸电脑所组成的网络，被利用作发出垃圾邮件或病毒，  
以发动分布式拒绝服务攻击。  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=other "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球在看**  
  
****  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1UG7KPNHN8FxuBNT7e2ZEfQZgBuH2GkFjvK4tzErD5Q56kwaEL0N099icLfx1ZvVvqzcRG3oMtIXqUz5T9HYKicA/640?wx_fmt=gif "")  
  
戳  
“阅读原文  
”  
一起来充电吧！  
  
