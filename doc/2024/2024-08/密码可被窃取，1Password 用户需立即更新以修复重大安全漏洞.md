#  密码可被窃取，1Password 用户需立即更新以修复重大安全漏洞   
看雪学苑  看雪学苑   2024-08-13 18:03  
  
根据知名密码管理器 1Password 官方数据，全球已有超过 1000 万用户使用 该软件管理密码。  
而在近期举行的DEF CON 2024大会上， Robinhood安全团队计划披露其在1Password Mac版中发现的多个漏洞，攻击者可以利用这些漏洞窃取存储在软件保险库中的密码。  
  
  
其中，CVE-2024-42219漏洞允许本地运行的恶意进程绕过进程间通信保护机制，从而窃取保险库中的密码。CVE-2024-42218漏洞则允许攻击者利用1Password Mac版旧版本的漏洞，绕过macOS特有的安全机制，同样可以窃取密码。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HXbURdTdBDW34TsIEGmsPZIzpia90bIgkQeXGer593QWaUichEsmeY08Qx6YvEhL8dRBNyWkMEZNvg/640?wx_fmt=png&from=appmsg "")  
  
  
CVE-2024-42219：   
  
该漏洞利用了macOS特有的进程间通信机制XPC的漏洞。1Password使用了XPC的“强化运行时”保护机制，但攻击者找到了绕过该保护机制的方法。攻击者可以伪装成受信任的1Password集成组件，例如浏览器扩展或命令行工具，从而窃取保险库中的密码和账户解锁密钥。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HXbURdTdBDW34TsIEGmsPZvLxmZia0A9ebTSb1pXR7icGIs3RpSRNSttiacoZhPwohzKfNfXcyqqYwQ/640?wx_fmt=png&from=appmsg "")  
  
  
CVE-2024-42218：   
  
该漏洞利用了1Password Mac版旧版本中存在的第三方依赖项漏洞和安全加固措施缺失。攻击者可以利用这些漏洞，在用户的电脑上加载旧版本的1Password，从而访问存储在macOS Keychain中的1Password相关密码。  
  
  
1Password官方在一篇博客中感谢Robinhood安全团队的漏洞报告及积极合作，他们目前已确认这些漏洞的存在，并表示已分别在v8.10.36和v8.10.38版本中修复。1Password首席技术官Pedro Canahuati强调，Robinhood安全团队发现的所有漏洞都是本地漏洞，需要攻击者控制受害者的设备才能利用。他们将继续尽一切努力保护用户，并在DEF CON 2024大会结束后公布更多漏洞细节。  
  
  
目前尚无证据表明这些漏洞已被利用，但仍然建议用户采取一些保护措施，例如：  
  
① 立即更新1Password Mac版到最新版本（8.10.38或更高版本）。  
  
② 开启“自动安装更新”选项，确保及时获取安全更新。  
  
③ 加强安全意识，不要轻易打开来历不明的邮件附件或点击可疑链接。  
  
④ 定期更改主密码，并使用强密码。  
  
⑤ 谨慎使用自动填充功能，特别是在不信任的网站或应用程序中。  
  
  
  
编辑：左右里  
  
资讯来源：1password  
  
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
  
