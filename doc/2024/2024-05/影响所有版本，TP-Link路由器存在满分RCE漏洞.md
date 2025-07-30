#  影响所有版本，TP-Link路由器存在满分RCE漏洞   
看雪学苑  看雪学苑   2024-05-30 18:03  
  
德国网络安全公司ONEKEY在一份报告中披露，TP-Link Archer C5400X游戏路由器中存在满分安全漏洞，允许远程黑客完全控制该设备。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HUXdkEzTrGCeibatXldicdwJ8DKmDGoHxT8yvdfeykXEjVAyAe1nGodTibKR3xvoiaCrkpcm2XlGMvxA/640?wx_fmt=png&from=appmsg "")  
  
  
据了解，TP-Link Archer C5400X是一款专为在线游戏和流媒体等高要求应用设计的高性能游戏路由器。该漏洞（CVE-2024-5035，CVSS评分为10.0）影响路由器固件的所有版本，若成功利用此漏洞，远程未经身份验证的攻击者可以在设备上获得具有提升权限的任意命令执行。  
  
  
漏洞位于一个与无线电频率测试相关的“rftest”二进制文件中。研究人员发现该二进制文件在TCP端口8888、8889和8890上暴露了一个网络服务，虽然该网络服务设计为仅接受以“wl”或“nvram get”开头的命令，但ONEKEY研究人员发现，可以通过在shell元字符（例如; & |）之后注入命令来轻松绕过限制（例如“wl;id;”），从而在易受攻击的路由器上获取完全的远程代码执行权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HUXdkEzTrGCeibatXldicdwJCmo8NUQiatwpr893bGMIjlNtXuwkfVfp6a6rvQt6ORMAjZjbwuJrXhQ/640?wx_fmt=png&from=appmsg "")  
  
ONEKEY推测TP-Link可能是匆忙开放了这个API而缺乏妥善保护，以致留下了一个远程代码执行漏洞：“似乎TP-Link需要快速或廉价地回应无线设备配置API的需求，结果导致他们在网络上暴露了一个被认为是有限的shell，路由器内的客户端可以将其用作配置无线设备的一种方式。由于不安全的编码实践，这个‘API’实际上远程暴露了一个shell，这一事实在审查过程中被忽略了。”  
  
  
该问题影响1.1.1.6及更早版本，目前TP-Link已在最新的Archer C5400X（EU）_V1_1.1.7 Build 20240510中解决了这一问题（https://www.tp-link.com/en/support/download/archer-c5400x/#Firmware）。  
  
  
  
编辑：左右里  
  
资讯来源：onekey、tp-link  
  
转载请注明出处和本文链接  
  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
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
  
